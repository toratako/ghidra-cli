use super::{start_daemon, TEST_PROGRAM};
use crate::common::{ensure_test_project, test_project};
use serial_test::serial;

// Exercise the production dispatcher against a separate, real Ghidra database.
// Java interface proxies inject failures only after real edits, without adding
// test switches to the bridge or nesting under the enclosing script's request.
const TRANSACTION_PROBE: &str = r#"
import com.google.gson.JsonObject;
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.concurrent.Callable;

public class RequestTransactionProbe extends GhidraScript {
    private Program real;
    private Program selected;
    private Object session;
    private Object dispatcher;
    private Method execute;
    private final TaskMonitorAdapter requestMonitor = new TaskMonitorAdapter(true);
    private String fault;
    private boolean failNextTransaction;
    private Integer leakedTransaction;
    private int savesToFail;
    private int saveCalls;
    private int commentWrites;
    private Address address;
    private String prior;

    private static Object invoke(Method method, Object target, Object... args) throws Throwable {
        try { return method.invoke(target, args); }
        catch (InvocationTargetException failure) { throw failure.getCause(); }
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new IllegalStateException(message);
    }

    private JsonObject command(String command, JsonObject args) throws Exception {
        return (JsonObject) execute.invoke(dispatcher, command, args);
    }

    private JsonObject comment(String text, String type) {
        JsonObject args = new JsonObject();
        args.addProperty("address", "0x" + address.toString());
        args.addProperty("text", text);
        args.addProperty("comment_type", type);
        return args;
    }

    private static void success(JsonObject response) {
        check("success".equals(response.get("status").getAsString()), response.toString());
    }

    private static JsonObject failed(JsonObject response) {
        check("error".equals(response.get("status").getAsString()), response.toString());
        return response.getAsJsonObject("detail");
    }

    private static void rolledBack(JsonObject response) {
        JsonObject detail = failed(response);
        check(detail != null && detail.has("rolled_back")
            && detail.get("rolled_back").getAsBoolean(), response.toString());
        check(!detail.has("partial_changes_saved") && !detail.has("save_failed"), response.toString());
    }

    private static void saveFailed(JsonObject response, String originalStatus) {
        JsonObject detail = failed(response);
        check(detail != null && detail.has("save_failed")
            && detail.get("save_failed").getAsBoolean(), response.toString());
        check(!detail.get("saved").getAsBoolean(), response.toString());
        check(!detail.has("rolled_back") && !detail.has("partial_changes_saved"), response.toString());
        check(originalStatus.equals(detail.getAsJsonObject("command_response")
            .get("status").getAsString()), response.toString());
    }

    private static void rollbackPending(JsonObject detail) {
        check(detail != null && detail.has("transaction_failed")
            && detail.get("transaction_failed").getAsBoolean(), String.valueOf(detail));
        check(!detail.has("rolled_back") && !detail.has("save_failed")
            && !detail.has("partial_changes_saved"), detail.toString());
    }

    private void rollbackPending(Throwable failure) throws Exception {
        Class<?> protocol = session.getClass().getClassLoader()
            .loadClass(session.getClass().getPackageName() + ".JsonProtocol");
        Method detail = protocol.getDeclaredMethod("errorDetail", Throwable.class);
        detail.setAccessible(true);
        rollbackPending((JsonObject) detail.invoke(null, failure));
    }

    private String liveComment(int type) {
        return real.getListing().getComment(type, address);
    }

    private void savedComment(int type, String expected) throws Exception {
        Object reader = new Object();
        Program saved = (Program) real.getDomainFile()
            .getReadOnlyDomainObject(reader, DomainFile.DEFAULT_VERSION, TaskMonitor.DUMMY);
        try {
            String actual = saved.getListing().getComment(type, address);
            check(java.util.Objects.equals(expected, actual), "Saved comment: " + actual);
        } finally { saved.release(reader); }
    }

    private void configureDispatcher() throws Exception {
        Class<?> bridgeCaller = StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
            .walk(frames -> frames.map(StackWalker.StackFrame::getDeclaringClass)
                .filter(type -> type.getSimpleName().equals("ScriptCommands")
                    && type.getPackageName().equals("ghidracli"))
                .findFirst().orElseThrow());
        ClassLoader bridgeLoader = bridgeCaller.getClassLoader();
        // Build class names at runtime so bnd does not infer a hard OSGi import
        // of the bridge's private source bundle from a qualified name literal.
        String bridgePackage = bridgeCaller.getPackageName() + ".";
        Listing listing = (Listing) Proxy.newProxyInstance(Listing.class.getClassLoader(),
            new Class<?>[] { Listing.class }, (proxy, method, args) -> {
                Object result = invoke(method, real.getListing(), args);
                if (method.getName().equals("setComment")) {
                    commentWrites++;
                    if ("late-error".equals(fault)) {
                        fault = null;
                        throw new IllegalStateException("injected failure after comment edit");
                    }
                    if ("cancel".equals(fault)) {
                        fault = null;
                        requestMonitor.cancel();
                    }
                    if ("leak-child".equals(fault)) {
                        fault = null;
                        leakedTransaction = real.startTransaction("test-owned native mutation child");
                    }
                }
                return result;
            });
        FunctionManager functions = (FunctionManager) Proxy.newProxyInstance(
            FunctionManager.class.getClassLoader(), new Class<?>[] { FunctionManager.class },
            (proxy, method, args) -> {
                Object result = invoke(method, real.getFunctionManager(), args);
                if (method.getName().equals("removeFunction") && "native-false".equals(fault)) {
                    check(Boolean.TRUE.equals(result), "Fixture function was not removed");
                    fault = null;
                    return false;
                }
                return result;
            });
        selected = (Program) Proxy.newProxyInstance(Program.class.getClassLoader(),
            new Class<?>[] { Program.class }, (proxy, method, args) -> {
                if (method.getName().equals("getListing")) return listing;
                if (method.getName().equals("getFunctionManager")) return functions;
                if (method.getName().equals("startTransaction") && failNextTransaction) {
                    failNextTransaction = false;
                    throw new IllegalStateException("injected transaction start failure");
                }
                if (method.getName().equals("save")) {
                    saveCalls++;
                    if (savesToFail > 0) {
                        savesToFail--;
                        throw new IOException("injected one-shot save failure");
                    }
                }
                return invoke(method, real, args);
            });
        Class<?> accessClass = bridgeLoader.loadClass(bridgePackage + "ScriptAccess");
        Object access = Proxy.newProxyInstance(bridgeLoader, new Class<?>[] { accessClass },
            (proxy, method, args) -> {
                switch (method.getName()) {
                    case "program": return selected;
                    case "setProgram": selected = (Program) args[0]; return null;
                    case "state": return state;
                    case "monitor": return requestMonitor;
                    case "logError": printerr((String) args[0]); return null;
                    default: throw new UnsupportedOperationException(method.getName());
                }
            });
        Class<?> sessionClass = bridgeLoader.loadClass(bridgePackage + "ProgramSession");
        Constructor<?> sessionConstructor = sessionClass.getDeclaredConstructor(accessClass);
        sessionConstructor.setAccessible(true);
        session = sessionConstructor.newInstance(access);
        Class<?> dispatcherClass = bridgeLoader.loadClass(bridgePackage + "CommandDispatcher");
        Constructor<?> dispatcherConstructor = dispatcherClass.getDeclaredConstructor(sessionClass);
        dispatcherConstructor.setAccessible(true);
        dispatcher = dispatcherConstructor.newInstance(session);
        execute = dispatcherClass.getDeclaredMethod("execute", String.class, JsonObject.class);
        execute.setAccessible(true);
    }

    private void testLateFailure(String mode) throws Exception {
        fault = mode;
        JsonObject response;
        if (mode.equals("native-false")) {
            JsonObject args = new JsonObject();
            args.addProperty("address", "0x" + address.toString());
            response = command("delete_function", args);
            check(real.getFunctionManager().getFunctionAt(address) != null,
                "Failed native delete removed the function");
        } else {
            response = command("comment_set", comment("must-roll-back", "EOL"));
            check(commentWrites == 2, "Fault did not follow a real mutation");
        }
        rolledBack(response);
        requestMonitor.clearCancelled();
        check(prior.equals(liveComment(CodeUnit.EOL_COMMENT)), "Prior edit was lost");
        savedComment(CodeUnit.EOL_COMMENT, prior);
        // A fresh successful request still commits after cancellation/failure.
        success(command("comment_set", comment("next-request", "PRE")));
        savedComment(CodeUnit.PRE_COMMENT, "next-request");
    }

    private void testSaveRecovery() throws Exception {
        String previouslySaved = liveComment(CodeUnit.PRE_COMMENT);
        savesToFail = 1;
        int before = saveCalls;
        saveFailed(command("comment_set", comment("pending-save", "PRE")), "success");
        check(saveCalls == before + 1, "Auto-save was retried within one request");
        check(real.isChanged(), "Failed save did not retain the edit");
        check("pending-save".equals(liveComment(CodeUnit.PRE_COMMENT)), "Pending edit was lost");
        savedComment(CodeUnit.EOL_COMMENT, prior);
        savedComment(CodeUnit.PRE_COMMENT, previouslySaved);

        // A later rollback must preserve an earlier request's still-unsaved edit.
        before = saveCalls;
        fault = "late-error";
        rolledBack(command("comment_set", comment("must-roll-back", "EOL")));
        check(saveCalls == before, "Rollback saved an earlier pending edit");
        check(prior.equals(liveComment(CodeUnit.EOL_COMMENT)), "Failed edit survived rollback");
        check("pending-save".equals(liveComment(CodeUnit.PRE_COMMENT)), "Rollback lost pending edit");
        savedComment(CodeUnit.PRE_COMMENT, previouslySaved);

        int transaction = real.startTransaction("committed edit pending a lifecycle save");
        try { real.getListing().setComment(address, CodeUnit.POST_COMMENT, "pending-close-save"); }
        finally { real.endTransaction(transaction, true); }
        savesToFail = 1;
        before = saveCalls;
        saveFailed(command("program_close", new JsonObject()), "error");
        check(saveCalls == before + 1, "Lifecycle save was retried within one request");
        check(selected != null && real.isChanged(), "Save failure released the selected program");
        int writesBeforeSave = commentWrites;
        success(command("program_save", new JsonObject()));
        check(commentWrites == writesBeforeSave, "Saving replayed the editing command");
        savedComment(CodeUnit.EOL_COMMENT, prior);
        savedComment(CodeUnit.PRE_COMMENT, "pending-save");
        savedComment(CodeUnit.POST_COMMENT, "pending-close-save");
    }

    private void testForeignTransaction() throws Exception {
        int transaction = real.startTransaction("owned by another script");
        try {
            real.getListing().setComment(address, CodeUnit.PRE_COMMENT, "foreign-edit");
            JsonObject response = command("comment_set", comment("must-not-run", "EOL"));
            JsonObject detail = failed(response);
            check(detail != null && detail.has("transaction_failed")
                && detail.get("transaction_failed").getAsBoolean(), response.toString());
            check(!detail.has("rolled_back") && !detail.has("save_failed"), response.toString());
            check(commentWrites == 1, "Request ran inside a foreign transaction");
            check(real.getCurrentTransactionInfo() != null, "Foreign transaction was ended");
            check("foreign-edit".equals(liveComment(CodeUnit.PRE_COMMENT)), "Foreign edit was lost");
        } finally { real.endTransaction(transaction, true); }
        success(command("program_save", new JsonObject()));
        savedComment(CodeUnit.EOL_COMMENT, prior);
        savedComment(CodeUnit.PRE_COMMENT, "foreign-edit");
    }

    private void testTransactionStartFailure() throws Exception {
        failNextTransaction = true;
        JsonObject response = command("comment_set", comment("must-not-run", "EOL"));
        JsonObject detail = failed(response);
        check(response.get("message").getAsString().contains("injected transaction start failure"),
            response.toString());
        rollbackPending(detail);
        check(commentWrites == 1, "Editing command ran without its transaction");
        check(real.getCurrentTransactionInfo() == null, "Failed start left a transaction");
        success(command("comment_set", comment("after-start-failure", "PRE")));
        savedComment(CodeUnit.EOL_COMMENT, prior);
        savedComment(CodeUnit.PRE_COMMENT, "after-start-failure");
    }

    private void closeLeakedChild() {
        int transaction = leakedTransaction;
        leakedTransaction = null;
        check(!real.endTransaction(transaction, true), "Pending rollback unexpectedly committed");
        check(real.getCurrentTransactionInfo() == null, "Bridge left its own transaction open");
    }

    private void assertChildRemainsOwned(int previousSaveCalls) throws Exception {
        check(leakedTransaction != null, "Native child was not opened");
        var info = real.getCurrentTransactionInfo();
        check(info != null && info.getOpenSubTransactions().size() == 1,
            "Bridge closed the test-owned child or opened another transaction");
        check(saveCalls == previousSaveCalls, "Bridge saved an incomplete rollback");
        savedComment(CodeUnit.EOL_COMMENT, prior);
    }

    private void assertChildRollbackRecovery() throws Exception {
        check(prior.equals(liveComment(CodeUnit.EOL_COMMENT)), "Native child committed failed edits");
        success(command("comment_set", comment("after-child-rollback", "PRE")));
        savedComment(CodeUnit.EOL_COMMENT, prior);
        savedComment(CodeUnit.PRE_COMMENT, "after-child-rollback");
    }

    private void testMutationLeakedChild() throws Exception {
        int previousSaveCalls = saveCalls;
        fault = "leak-child";
        try {
            JsonObject response = command("comment_set", comment("must-roll-back", "EOL"));
            JsonObject detail = failed(response);
            rollbackPending(detail);
            check("success".equals(detail.getAsJsonObject("command_response")
                .get("status").getAsString()), response.toString());
            check(commentWrites == 2, "Fault did not follow an actual edit");
            assertChildRemainsOwned(previousSaveCalls);
        } finally {
            if (leakedTransaction != null) closeLeakedChild();
        }
        assertChildRollbackRecovery();
    }

    private void testPreviewLeakedChild() throws Exception {
        Class<?> type = session.getClass();
        Method begin = type.getDeclaredMethod("beginRequest", String.class);
        Method preview = type.getDeclaredMethod("preview", String.class, Callable.class);
        Method finish = type.getDeclaredMethod("finishRequest", boolean.class);
        begin.setAccessible(true);
        preview.setAccessible(true);
        finish.setAccessible(true);
        int previousSaveCalls = saveCalls;
        begin.invoke(session, "define_code");
        try {
            Throwable previewFailure = null;
            try {
                preview.invoke(session, "test preview with native child", (Callable<Void>) () -> {
                    real.getListing().setComment(address, CodeUnit.EOL_COMMENT, "preview-only");
                    leakedTransaction = real.startTransaction("test-owned native preview child");
                    return null;
                });
            } catch (InvocationTargetException failure) { previewFailure = failure.getCause(); }
            check(previewFailure != null, "Preview reported a completed rollback with a child open");
            rollbackPending(previewFailure);

            Throwable finishFailure = null;
            try { finish.invoke(session, false); }
            catch (InvocationTargetException failure) { finishFailure = failure.getCause(); }
            check(finishFailure != null, "Request completion ignored the pending preview rollback");
            rollbackPending(finishFailure);
            assertChildRemainsOwned(previousSaveCalls);
        } finally {
            if (leakedTransaction != null) closeLeakedChild();
        }
        assertChildRollbackRecovery();
    }

    private void testPreviewAfterEdit() throws Exception {
        Class<?> type = session.getClass();
        Method begin = type.getDeclaredMethod("beginRequest", String.class);
        Method preview = type.getDeclaredMethod("preview", String.class, Callable.class);
        Method finish = type.getDeclaredMethod("finishRequest", boolean.class);
        begin.setAccessible(true);
        preview.setAccessible(true);
        finish.setAccessible(true);
        boolean[] callbackRan = { false };
        boolean rejected = false;
        begin.invoke(session, "comment_set");
        try {
            real.getListing().setComment(address, CodeUnit.EOL_COMMENT, "before-preview");
            try {
                preview.invoke(session, "test preview", (Callable<Void>) () -> {
                    callbackRan[0] = true;
                    real.getListing().setComment(address, CodeUnit.PRE_COMMENT, "preview-only");
                    return null;
                });
            } catch (InvocationTargetException failure) {
                rejected = true;
                check(failure.getCause() instanceof IllegalStateException,
                    "Unexpected preview failure: " + failure.getCause());
            }
        } finally { finish.invoke(session, false); }
        check(rejected, "Preview was not rejected after an earlier request edit");
        check(!callbackRan[0], "Rejected preview executed its callback");
        check(prior.equals(liveComment(CodeUnit.EOL_COMMENT)), "Preview committed earlier request edit");
        check(!"preview-only".equals(liveComment(CodeUnit.PRE_COMMENT)), "Preview edit escaped rollback");
        savedComment(CodeUnit.EOL_COMMENT, prior);
    }

    public void run() throws Exception {
        String folderName = getScriptArgs()[0];
        String mode = getScriptArgs()[2];
        var folder = state.getProject().getProjectData().getRootFolder().createFolder(folderName);
        DomainFile file = currentProgram.getDomainFile().copyTo(folder, monitor);
        Object owner = new Object();
        real = (Program) file.getDomainObject(owner, true, false, monitor);
        try {
            address = real.getAddressFactory().getAddress(getScriptArgs()[1]);
            prior = "prior:" + folderName;
            configureDispatcher();
            success(command("comment_set", comment(prior, "EOL")));
            savedComment(CodeUnit.EOL_COMMENT, prior);
            switch (mode) {
                case "late-error": case "cancel": case "native-false": testLateFailure(mode); break;
                case "save-recovery": testSaveRecovery(); break;
                case "foreign-transaction": testForeignTransaction(); break;
                case "start-failure": testTransactionStartFailure(); break;
                case "mutation-leaked-child": testMutationLeakedChild(); break;
                case "preview-leaked-child": testPreviewLeakedChild(); break;
                case "preview": testPreviewAfterEdit(); break;
                default: throw new IllegalArgumentException(mode);
            }
            println("contract-ok:" + mode);
        } finally {
            fault = null;
            savesToFail = 0;
            requestMonitor.clearCancelled();
            try {
                if (session != null) {
                    Method close = session.getClass().getDeclaredMethod("closeProgram");
                    close.setAccessible(true);
                    close.invoke(session);
                }
            } finally { real.release(owner); }
        }
    }
}
"#;

fn run_transaction_probe(mode: &str) {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    let client = harness.client().unwrap();
    let function = client
        .send_command(
            "get_function",
            Some(serde_json::json!({"address": "add_numbers"})),
        )
        .unwrap();
    let address = function["address"].as_str().unwrap().to_owned();
    let folder = format!("transaction-{}", uuid::Uuid::new_v4());
    let result = client
        .script_run_source(
            TRANSACTION_PROBE,
            &[folder.clone(), address.clone(), mode.to_owned()],
            &[],
            false,
        )
        .unwrap();
    assert!(
        result["stdout"]
            .as_str()
            .unwrap()
            .contains(&format!("contract-ok:{mode}")),
        "{result}"
    );
    drop(harness);

    // A new bridge and normal public requests independently verify durability.
    let restarted = start_daemon();
    let client = restarted.client().unwrap();
    let program = format!("/{folder}/{TEST_PROGRAM}");
    client.open_program(&program).unwrap();
    let comments = client.comment_get(&address).unwrap();
    assert!(
        comments["comments"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["type"] == "EOL" && row["text"] == format!("prior:{folder}")),
        "Prior successful edit was lost: {comments}"
    );
    let function = client
        .send_command(
            "get_function",
            Some(serde_json::json!({"address": address})),
        )
        .unwrap();
    assert_eq!(function["name"], "add_numbers");
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&program).unwrap();
}

#[test]
#[serial]
fn test_late_error_rolls_back_only_the_failed_request() {
    run_transaction_probe("late-error");
}

#[test]
#[serial]
fn test_cancellation_after_edit_rolls_back_only_the_cancelled_request() {
    run_transaction_probe("cancel");
}

#[test]
#[serial]
fn test_native_false_rolls_back_changes_before_the_failure() {
    run_transaction_probe("native-false");
}

#[test]
#[serial]
fn test_transient_save_failure_is_not_retried_and_pending_edits_survive_rollback() {
    run_transaction_probe("save-recovery");
}

#[test]
#[serial]
fn test_foreign_transaction_rejection_preserves_its_edits_and_owner() {
    run_transaction_probe("foreign-transaction");
}

#[test]
#[serial]
fn test_transaction_start_failure_does_not_poison_later_requests() {
    run_transaction_probe("start-failure");
}

#[test]
#[serial]
fn test_mutation_leaked_child_defers_rollback_to_its_owner_without_saving() {
    run_transaction_probe("mutation-leaked-child");
}

#[test]
#[serial]
fn test_preview_leaked_child_defers_rollback_to_its_owner_without_saving() {
    run_transaction_probe("preview-leaked-child");
}

#[test]
#[serial]
fn test_preview_cannot_commit_prior_edits_in_the_same_request() {
    run_transaction_probe("preview");
}
