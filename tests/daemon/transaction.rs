use super::{start_daemon, TEST_PROGRAM};
use crate::common::{ensure_test_project, test_project};
use serial_test::serial;

// Exercise the production dispatcher against a separate, real Ghidra database.
// Java interface proxies inject failures after real edits or iterator reads,
// without bridge test switches or nesting under the enclosing script's request.
const TRANSACTION_PROBE: &str = r#"
import com.google.gson.JsonObject;
import ghidra.app.script.GhidraScript;
import ghidra.framework.data.DomainObjectAdapterDB;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.TransactionInfo;
import ghidra.framework.model.TransactionListener;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.exception.CancelledException;
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
    private final TaskMonitorAdapter requestMonitor = new TaskMonitorAdapter(true) {
        @Override public void checkCancelled() throws CancelledException {
            Throwable failure = openMonitorFailure;
            openMonitorFailure = null;
            if (failure instanceof Error error) throw error;
            if (failure instanceof RuntimeException exception) throw exception;
            super.checkCancelled();
        }
    };
    private Throwable openMonitorFailure;
    private String fault;
    private boolean failNextTransaction;
    private Integer leakedTransaction;
    private int savesToFail;
    private boolean failSaveWithAssertion;
    private boolean cancelAfterSave;
    private Throwable selectionFailureAfterSave;
    private int saveCalls;
    private int commentWrites;
    private int memoryWrites;
    private int statsEntriesRead;
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
        String sessionPackage = session.getClass().getPackageName();
        Class<?> protocol = session.getClass().getClassLoader()
            .loadClass(sessionPackage.substring(0, sessionPackage.lastIndexOf('.') + 1)
                + "protocol.JsonProtocol");
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
                    && type.getPackageName().equals("ghidracli.script"))
                .findFirst().orElseThrow());
        ClassLoader bridgeLoader = bridgeCaller.getClassLoader();
        // Build class names at runtime so bnd does not infer a hard OSGi import
        // of the bridge's private source bundle from a qualified name literal.
        String bridgePackage = bridgeCaller.getPackageName()
            .substring(0, bridgeCaller.getPackageName().lastIndexOf('.') + 1);

        Listing listing = (Listing) Proxy.newProxyInstance(Listing.class.getClassLoader(),
            new Class<?>[] { Listing.class }, (proxy, method, args) -> {
                Object result = invoke(method, real.getListing(), args);
                if (method.getName().equals("getDefinedData") && "stats-cancel".equals(fault)) {
                    fault = null;
                    return Proxy.newProxyInstance(method.getReturnType().getClassLoader(),
                        new Class<?>[] { method.getReturnType() }, (iterator, operation, inputs) -> {
                            Object entry = invoke(operation, result, inputs);
                            if (operation.getName().equals("next") && ++statsEntriesRead == 1) {
                                check(((java.util.Iterator<?>) result).hasNext(),
                                    "Stats cancellation fixture needs remaining entries");
                                requestMonitor.cancel();
                            }
                            return entry;
                        });
                }
                if (method.getName().equals("setComment")) {
                    commentWrites++;
                    if ("late-error".equals(fault)) {
                        fault = null;
                        throw new IllegalStateException("injected failure after comment edit");
                    }
                    if ("late-assertion".equals(fault)) {
                        fault = null;
                        throw new AssertionError("injected assertion after comment edit");
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
                if (result instanceof Function function && fault != null && fault.startsWith("storage-")) {
                    return Proxy.newProxyInstance(Function.class.getClassLoader(), new Class<?>[] { Function.class },
                        (wrapper, operation, inputs) -> {
                            Object value = invoke(operation, function, inputs);
                            if (operation.getName().equals("updateFunction")) {
                                String mode = fault;
                                fault = null;
                                if ("storage-cancel".equals(mode)) requestMonitor.cancel();
                                else throw new IllegalStateException("injected failure after ABI update");
                            }
                            return value;
                        });
                }
                if (method.getName().equals("removeFunction") && "native-false".equals(fault)) {
                    check(Boolean.TRUE.equals(result), "Fixture function was not removed");
                    fault = null;
                    return false;
                }
                return result;
            });
        Memory memory = (Memory) Proxy.newProxyInstance(Memory.class.getClassLoader(),
            new Class<?>[] { Memory.class }, (proxy, method, args) -> {
                Object result = invoke(method, real.getMemory(), args);
                if (method.getName().equals("setBytes") && fault != null && fault.startsWith("memory-")) {
                    if (++memoryWrites == 2) {
                        String mode = fault;
                        fault = null;
                        if (mode.equals("memory-cancel")) requestMonitor.cancel();
                        else throw new IllegalStateException("injected failure after second byte range");
                    }
                }
                return result;
            });
        ReferenceManager references = (ReferenceManager) Proxy.newProxyInstance(ReferenceManager.class.getClassLoader(),
            new Class<?>[] { ReferenceManager.class }, (proxy, method, args) -> {
                Object result = invoke(method, real.getReferenceManager(), args);
                if (method.getName().equals("addMemoryReference") && "pointer-error".equals(fault)) {
                    fault = null;
                    throw new IllegalStateException("injected failure after pointer reference update");
                }
                return result;
            });
        selected = (Program) Proxy.newProxyInstance(Program.class.getClassLoader(),
            new Class<?>[] { Program.class }, (proxy, method, args) -> {
                if (method.getName().equals("getListing")) return listing;
                if (method.getName().equals("getFunctionManager")) return functions;
                if (method.getName().equals("getMemory")) return memory;
                if (method.getName().equals("getReferenceManager")) return references;
                if (method.getName().equals("startTransaction") && failNextTransaction) {
                    failNextTransaction = false;
                    throw new IllegalStateException("injected transaction start failure");
                }
                if (method.getName().equals("save")) {
                    saveCalls++;
                    if (savesToFail > 0) {
                        savesToFail--;
                        if (failSaveWithAssertion) throw new AssertionError("injected one-shot save failure");
                        throw new IOException("injected one-shot save failure");
                    }
                }
                Object result = invoke(method, real, args);
                if (method.getName().equals("save") && cancelAfterSave) {
                    cancelAfterSave = false;
                    requestMonitor.cancel();
                }
                if (method.getName().equals("save") && selectionFailureAfterSave != null) {
                    openMonitorFailure = selectionFailureAfterSave;
                    selectionFailureAfterSave = null;
                }
                return result;
            });
        Class<?> accessClass = bridgeLoader.loadClass(bridgePackage + "session.ScriptAccess");
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
        Class<?> sessionClass = bridgeLoader.loadClass(bridgePackage + "session.ProgramSession");
        Constructor<?> sessionConstructor = sessionClass.getDeclaredConstructor(accessClass);
        sessionConstructor.setAccessible(true);
        session = sessionConstructor.newInstance(access);
        Class<?> dispatcherClass = bridgeLoader.loadClass(bridgePackage + "runtime.CommandDispatcher");
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

    private void testStatsCancellation() throws Exception {
        fault = "stats-cancel";
        JsonObject response = command("stats", new JsonObject());
        rolledBack(response);
        check(response.getAsJsonObject("detail").get("cancelled").getAsBoolean(),
            "Missing stats cancellation detail: " + response);
        check(statsEntriesRead == 1, "Cancelled stats read " + statsEntriesRead + " entries");
        check(real.getCurrentTransactionInfo() == null, "Cancelled stats left a transaction open");
        requestMonitor.clearCancelled();
        success(command("stats", new JsonObject()));
        success(command("comment_set", comment("after-stats-cancellation", "PRE")));
        savedComment(CodeUnit.EOL_COMMENT, prior);
        savedComment(CodeUnit.PRE_COMMENT, "after-stats-cancellation");
    }

    private void testNonAtomicCancellationDiagnostics(boolean failSave) throws Exception {
        String previouslySaved = liveComment(CodeUnit.PRE_COMMENT);
        JsonObject args = new JsonObject();
        args.addProperty("source", """
            import ghidra.app.script.GhidraScript;
            public class SessionCancelledRequest extends GhidraScript {
                public void run() throws Exception {
                    setPreComment(toAddr(getScriptArgs()[0]), "cancelled-script-edit");
                    monitor.cancel();
                    monitor.checkCancelled();
                }
            }
            """);
        com.google.gson.JsonArray scriptArgs = new com.google.gson.JsonArray();
        scriptArgs.add("0x" + address.toString());
        args.add("args", scriptArgs);
        int previousSaveCalls = saveCalls;
        savesToFail = failSave ? 1 : 0;
        JsonObject response = command("script_run", args);
        JsonObject detail = failed(response);
        if (failSave) {
            saveFailed(response, "error");
            check(saveCalls == previousSaveCalls + 1 && real.isChanged(),
                "Cancelled script retried save or lost pending edits");
            savedComment(CodeUnit.PRE_COMMENT, previouslySaved);
        }
        check(detail != null && detail.has("cancelled") && detail.get("cancelled").getAsBoolean(),
            "Non-atomic failure lost cancellation diagnostics: " + response);
        requestMonitor.clearCancelled();
        if (failSave) success(command("program_save", new JsonObject()));
        else check(detail.get("partial_changes_saved").getAsBoolean() && !detail.has("rolled_back"),
            "Cancelled script did not retain its explicit non-atomic save semantics: " + response);
        savedComment(CodeUnit.EOL_COMMENT, prior);
        savedComment(CodeUnit.PRE_COMMENT, "cancelled-script-edit");
        // A completed non-atomic save still succeeds if cancellation arrives
        // during its uninterruptible durable write.
        int transaction = real.startTransaction("late save cancellation");
        try { real.getListing().setComment(address, CodeUnit.PRE_COMMENT, "saved-before-late-cancel"); }
        finally { real.endTransaction(transaction, true); }
        cancelAfterSave = true;
        success(command("program_save", new JsonObject()));
        check(!cancelAfterSave && requestMonitor.isCancelled(), "Save did not receive late cancellation");
        requestMonitor.clearCancelled();
        savedComment(CodeUnit.PRE_COMMENT, "saved-before-late-cancel");
        success(command("comment_set", comment("after-cancelled-script", "PRE")));
        savedComment(CodeUnit.PRE_COMMENT, "after-cancelled-script");
    }

    private void testMemoryFailure(String mode) throws Exception {
        var base = real.getAddressFactory().getDefaultAddressSpace().getAddress(0x50000000);
        int tx = real.startTransaction("memory rollback fixture");
        try {
            real.getMemory().createInitializedBlock("memory_rollback", base, 32, (byte)0, requestMonitor, false);
            real.getMemory().setBytes(base, new byte[]{0x66,(byte)0x90});
            check(new ghidra.app.cmd.disassemble.DisassembleCommand(base,
                new ghidra.program.model.address.AddressSet(base, base.add(1)), false)
                .applyTo(real, requestMonitor), "Fixture instruction");
            var scalar = real.getListing().createData(base.add(4), ghidra.program.model.data.DWordDataType.dataType);
            ghidra.docking.settings.FormatSettingsDefinition.DEF.setChoice(scalar,
                ghidra.docking.settings.FormatSettingsDefinition.BINARY);
            real.getMemory().setLong(base.add(8), base.add(24).getOffset());
            real.getListing().createData(base.add(8),
                new ghidra.program.model.data.PointerDataType(null, 8, real.getDataTypeManager()));
        } finally { real.endTransaction(tx, true); }
        real.save("memory rollback fixture", requestMonitor);
        byte[] before = new byte[16];
        real.getMemory().getBytes(base, before);
        byte[] patch = before.clone();
        patch[0] = (byte)0x90;
        patch[4] = 42;
        patch[8] = 28;
        JsonObject args = new JsonObject();
        args.addProperty("address", "0x50000000");
        args.addProperty("hex", java.util.HexFormat.of().formatHex(patch));
        fault = mode;
        JsonObject response = command("memory_write", args);
        rolledBack(response);
        check(fault == null, "Failure was not injected after the edits");
        if (mode.equals("memory-cancel")) check(response.getAsJsonObject("detail").get("cancelled").getAsBoolean(), "Missing cancellation detail");
        requestMonitor.clearCancelled();
        Object reader = new Object();
        Program saved = (Program)real.getDomainFile().getReadOnlyDomainObject(reader, DomainFile.DEFAULT_VERSION, requestMonitor);
        try {
            for (Program program : new Program[]{real, saved}) {
                byte[] actual = new byte[16];
                program.getMemory().getBytes(base, actual);
                check(java.util.Arrays.equals(before, actual), "Failed memory write changed bytes");
                check(program.getListing().getInstructionAt(base) != null, "Instruction clear escaped rollback");
                var scalar = program.getListing().getDefinedDataAt(base.add(4));
                check(scalar != null && ghidra.docking.settings.FormatSettingsDefinition.DEF.getChoice(scalar)
                    == ghidra.docking.settings.FormatSettingsDefinition.BINARY, "Data settings lost");
                var refs = program.getReferenceManager();
                check(refs.getReference(base.add(8), base.add(24), 0) != null
                    && refs.getReference(base.add(8), base.add(28), 0) == null, "Pointer reference update escaped rollback");
            }
        } finally { saved.release(reader); }
    }

    private void testSaveRecovery(String mode) throws Exception {
        failSaveWithAssertion = mode.equals("save-assertion");
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

    private void savedDescription(String expected) throws Exception {
        Object reader = new Object();
        Program saved = (Program) real.getDomainFile()
            .getReadOnlyDomainObject(reader, DomainFile.DEFAULT_VERSION, TaskMonitor.DUMMY);
        try {
            String actual = saved.getDataTypeManager().getDataType("/DescriptionSaveProbe").getDescription();
            check(java.util.Objects.equals(expected, actual), "Saved description: " + actual);
        } finally { saved.release(reader); }
    }

    private void testDescriptionSaveRecovery() throws Exception {
        JsonObject create = new JsonObject();
        create.addProperty("definition", "DescriptionSaveProbe");
        success(command("type_create", create));
        String original = real.getDataTypeManager().getDataType("/DescriptionSaveProbe").getDescription();
        JsonObject edit = new JsonObject();
        edit.addProperty("type_name", "/DescriptionSaveProbe");
        edit.addProperty("text", "pending description");
        savesToFail = 1;
        int before = saveCalls;
        JsonObject response = command("type_set_description", edit);
        saveFailed(response, "success");
        check(saveCalls == before + 1, "Description save was retried");
        JsonObject receipt = failed(response).getAsJsonObject("command_response").getAsJsonObject("data");
        check(receipt.get("changed").getAsBoolean()
            && "pending description".equals(receipt.get("after").getAsString()), response.toString());
        check(real.isChanged(), "Failed save lost the description edit");
        savedDescription(original);
        // A rejected edit must neither erase nor save the earlier pending edit.
        edit.remove("text");
        rolledBack(command("type_set_description", edit));
        check(saveCalls == before + 1, "Rejected description edit saved pending changes");
        check("pending description".equals(real.getDataTypeManager()
            .getDataType("/DescriptionSaveProbe").getDescription()), "Rollback lost pending description");
        savedDescription(original);
        success(command("program_save", new JsonObject()));
        savedDescription("pending description");
    }

    private void savedStorage(boolean custom) throws Exception {
        Object reader = new Object();
        Program saved = (Program) real.getDomainFile()
            .getReadOnlyDomainObject(reader, DomainFile.DEFAULT_VERSION, TaskMonitor.DUMMY);
        try {
            check(saved.getFunctionManager().getFunctionAt(address).hasCustomVariableStorage() == custom,
                "Saved storage mode differs from expected state");
        } finally { saved.release(reader); }
    }

    private void testStorageTransaction(String mode) throws Exception {
        JsonObject baseline = new JsonObject();
        baseline.addProperty("target", "0x" + address.toString());
        baseline.addProperty("signature", "int " + real.getFunctionManager().getFunctionAt(address).getName() + "(void)");
        success(command("function_set_signature", baseline));
        var original = real.getFunctionManager().getFunctionAt(address).getReturn().getVariableStorage();
        JsonObject piece = new JsonObject();
        piece.addProperty("kind", "register");
        piece.addProperty("register", original.getRegisters().get(0).getName());
        var pieces = new com.google.gson.JsonArray();
        pieces.add(piece);
        JsonObject storage = new JsonObject();
        storage.add("return", pieces);
        JsonObject edit = new JsonObject();
        edit.addProperty("target", "0x" + address.toString());
        edit.add("storage", storage);
        int before = saveCalls;
        if (mode.equals("storage-save")) savesToFail = 1;
        else fault = mode;
        JsonObject response = command("function_set_storage", edit);
        if (mode.equals("storage-save")) {
            saveFailed(response, "success");
            check(saveCalls == before + 1, "ABI save was retried");
            JsonObject receipt = failed(response).getAsJsonObject("command_response").getAsJsonObject("data");
            check(receipt.get("changed").getAsBoolean()
                && receipt.getAsJsonObject("after").get("storage_mode").getAsString().equals("custom"), response.toString());
            check(real.getFunctionManager().getFunctionAt(address).hasCustomVariableStorage(), "Lost pending ABI edit");
            savedStorage(false);
            piece.addProperty("register", "NONEXISTENT");
            rolledBack(command("function_set_storage", edit));
            check(real.getFunctionManager().getFunctionAt(address).hasCustomVariableStorage(), "Rejected edit erased pending ABI");
            check(saveCalls == before + 1, "Rejected edit saved pending ABI");
            success(command("program_save", new JsonObject()));
            savedStorage(true);
        } else {
            rolledBack(response);
            requestMonitor.clearCancelled();
            var function = real.getFunctionManager().getFunctionAt(address);
            check(!function.hasCustomVariableStorage() && function.getReturn().getVariableStorage().equals(original),
                "Failed ABI edit escaped rollback");
            check(saveCalls == before, "Failed ABI edit was saved");
            savedStorage(false);
            success(command("function_set_storage", edit));
            savedStorage(true);
        }
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

    private void testPreviewTransactionStartFailure() throws Exception {
        Class<?> type = session.getClass();
        Method begin = type.getDeclaredMethod("beginRequest", String.class);
        Method preview = type.getDeclaredMethod("preview", String.class, Callable.class);
        Method finish = type.getDeclaredMethod("finishRequest", boolean.class);
        begin.setAccessible(true);
        preview.setAccessible(true);
        finish.setAccessible(true);
        for (boolean failRestore : new boolean[] { false, true }) {
            String previouslySaved = liveComment(CodeUnit.PRE_COMMENT);
            String pending = "pending-before-preview-" + failRestore;
            savesToFail = 1;
            saveFailed(command("comment_set", comment(pending, "PRE")), "success");
            int previousSaveCalls = saveCalls;
            boolean[] callbackRan = { false };
            begin.invoke(session, "define_code");
            failNextTransaction = !failRestore;
            try {
                Throwable previewFailure = null;
                try {
                    preview.invoke(session, "test preview transaction failure", (Callable<Void>) () -> {
                        callbackRan[0] = true;
                        real.getListing().setComment(address, CodeUnit.EOL_COMMENT, "preview-only");
                        failNextTransaction = true;
                        return null;
                    });
                } catch (InvocationTargetException failure) { previewFailure = failure.getCause(); }
                check(previewFailure != null, "Preview ignored transaction start failure");
                rollbackPending(previewFailure);
            } finally {
                Throwable finishFailure = null;
                try { finish.invoke(session, false); }
                catch (InvocationTargetException failure) { finishFailure = failure.getCause(); }
                check(finishFailure != null, "Request completion ignored preview transaction failure");
                rollbackPending(finishFailure);
            }
            check(callbackRan[0] == failRestore, "Preview callback ran in the wrong phase");
            check(saveCalls == previousSaveCalls, "Failed preview saved an earlier pending edit");
            check(real.getCurrentTransactionInfo() == null, "Failed preview left a transaction open");
            check(prior.equals(liveComment(CodeUnit.EOL_COMMENT)), "Preview edit escaped rollback");
            check(pending.equals(liveComment(CodeUnit.PRE_COMMENT)), "Failed preview lost pending edit");
            savedComment(CodeUnit.EOL_COMMENT, prior);
            savedComment(CodeUnit.PRE_COMMENT, previouslySaved);
            success(command("program_save", new JsonObject()));
            savedComment(CodeUnit.PRE_COMMENT, pending);
        }
    }

    private void testCancelledDeletionRefusal() throws Exception {
        Class<?> type = session.getClass();
        Method begin = type.getDeclaredMethod("beginRequest", String.class);
        Method delete = type.getDeclaredMethod("delete", DomainFile.class);
        Method finish = type.getDeclaredMethod("finishRequest", boolean.class);
        begin.setAccessible(true);
        delete.setAccessible(true);
        finish.setAccessible(true);
        DomainFile file = real.getDomainFile();
        var consumers = real.getConsumerList();
        boolean[] deletionAttempted = { false };
        DomainFile target = (DomainFile) Proxy.newProxyInstance(DomainFile.class.getClassLoader(),
            new Class<?>[] { DomainFile.class }, (proxy, method, args) -> {
                if (method.getName().equals("delete")) {
                    deletionAttempted[0] = true;
                    requestMonitor.cancel();
                }
                return invoke(method, file, args);
            });
        begin.invoke(session, "program_delete");
        Throwable deletionFailure = null;
        try { delete.invoke(session, target); }
        catch (InvocationTargetException failure) { deletionFailure = failure.getCause(); }
        finally {
            finish.invoke(session, false);
            requestMonitor.clearCancelled();
        }
        check(deletionAttempted[0] && deletionFailure instanceof IOException,
            "Native deletion refusal was not exercised: " + deletionFailure);
        check(selected == real, "Cancelled deletion refusal did not restore the selected Program");
        check(real.getConsumerList().size() == consumers.size()
            && real.getConsumerList().containsAll(consumers), "Deletion changed consumer ownership");
        check(file.exists(), "Refused deletion removed the Program file");
        check(real.getCurrentTransactionInfo() == null, "Deletion recovery left a transaction open");
        savedComment(CodeUnit.EOL_COMMENT, prior);
        success(command("comment_set", comment("after-deletion-refusal", "PRE")));
        savedComment(CodeUnit.PRE_COMMENT, "after-deletion-refusal");
    }

    private void testCancelledDeletionAfterSave() throws Exception {
        Class<?> type = session.getClass();
        Method begin = type.getDeclaredMethod("beginRequest", String.class);
        Method delete = type.getDeclaredMethod("delete", DomainFile.class);
        Method finish = type.getDeclaredMethod("finishRequest", boolean.class);
        begin.setAccessible(true);
        delete.setAccessible(true);
        finish.setAccessible(true);
        DomainFile file = real.getDomainFile();
        var consumers = real.getConsumerList();
        boolean[] deletionAttempted = { false };
        DomainFile target = (DomainFile) Proxy.newProxyInstance(DomainFile.class.getClassLoader(),
            new Class<?>[] { DomainFile.class }, (proxy, method, args) -> {
                if (method.getName().equals("delete")) deletionAttempted[0] = true;
                return invoke(method, file, args);
            });
        begin.invoke(session, "program_delete");
        real.getListing().setComment(address, CodeUnit.PRE_COMMENT, "saved-before-cancelled-delete");
        int previousSaveCalls = saveCalls;
        cancelAfterSave = true;
        boolean cancellationDelivered = false;
        Throwable deletionFailure = null;
        try { delete.invoke(session, target); }
        catch (InvocationTargetException failure) { deletionFailure = failure.getCause(); }
        finally {
            finish.invoke(session, false);
            cancellationDelivered = requestMonitor.isCancelled();
            cancelAfterSave = false;
            requestMonitor.clearCancelled();
        }
        check(cancellationDelivered && saveCalls == previousSaveCalls + 1,
            "Deletion fixture did not cancel after its durable save");
        check(!deletionAttempted[0],
            "Cancellation during the durable save still attempted deletion");
        check(deletionFailure instanceof CancelledException,
            "Deletion lost the cancellation failure: " + deletionFailure);
        check(selected == real && selected.getDomainFile().equals(file),
            "Cancelled deletion did not restore the original selection");
        check(real.getConsumerList().size() == consumers.size()
            && real.getConsumerList().containsAll(consumers), "Cancelled deletion changed consumer ownership");
        check(file.exists() && real.getCurrentTransactionInfo() == null,
            "Cancelled deletion removed the file or left a transaction open");
        savedComment(CodeUnit.EOL_COMMENT, prior);
        savedComment(CodeUnit.PRE_COMMENT, "saved-before-cancelled-delete");

        // A save completed before deletion failed, so the wire receipt must
        // retain it even though request completion sees a clean Program.
        // Reinstall fault injection after deletion recovery reopened the real Program.
        Method close = type.getDeclaredMethod("closeProgram");
        close.setAccessible(true);
        close.invoke(session);
        configureDispatcher();
        savesToFail = 1;
        saveFailed(command("comment_set", comment("pending-before-cancelled-delete", "PRE")), "success");
        previousSaveCalls = saveCalls;
        cancelAfterSave = true;
        JsonObject args = new JsonObject();
        args.addProperty("program", file.getPathname());
        JsonObject response;
        try { response = command("program_delete", args); }
        finally {
            cancelAfterSave = false;
            requestMonitor.clearCancelled();
        }
        JsonObject detail = failed(response);
        check(detail.has("partial_changes_saved") && detail.get("partial_changes_saved").getAsBoolean()
            && detail.get("cancelled").getAsBoolean(), response.toString());
        check(saveCalls == previousSaveCalls + 1, "Deletion completion retried its successful save");
        check(selected == real && file.exists() && real.getCurrentTransactionInfo() == null,
            "Cancelled deletion did not retain its selected Program");
        savedComment(CodeUnit.PRE_COMMENT, "pending-before-cancelled-delete");
        args.addProperty("program", file.getPathname() + "/absent");
        JsonObject unchangedFailure = command("program_delete", args);
        JsonObject unchangedDetail = failed(unchangedFailure);
        check(unchangedDetail == null || !unchangedDetail.has("partial_changes_saved"),
            "A later request inherited the prior save receipt: " + unchangedFailure);
        success(command("comment_set", comment("after-cancelled-delete", "PRE")));
        savedComment(CodeUnit.PRE_COMMENT, "after-cancelled-delete");
    }

    private void testFailedOpenReleasesConsumer() throws Exception {
        Class<?> type = session.getClass();
        Method begin = type.getDeclaredMethod("beginRequest", String.class);
        Method open = type.getDeclaredMethod("open", DomainFile.class);
        Method finish = type.getDeclaredMethod("finishRequest", boolean.class);
        begin.setAccessible(true);
        open.setAccessible(true);
        finish.setAccessible(true);
        var folder = real.getDomainFile().getParent().createFolder("failed-open");
        for (boolean assertion : new boolean[] { false, true }) {
            DomainFile file = real.getDomainFile().copyTo(folder.createFolder("target-" + assertion), monitor);
            Program previous = selected;
            var previousConsumers = real.getConsumerList();
            Program[] acquired = { null };
            Object[] acquiredConsumer = { null };
            Throwable injected = assertion ? new AssertionError("injected post-open assertion")
                : new IllegalStateException("injected post-open exception");
            DomainFile target = (DomainFile) Proxy.newProxyInstance(DomainFile.class.getClassLoader(),
                new Class<?>[] { DomainFile.class }, (proxy, method, args) -> {
                    Object result = invoke(method, file, args);
                    if (method.getName().equals("getDomainObject")) {
                        acquired[0] = (Program) result;
                        acquiredConsumer[0] = args[0];
                        // Fail at ProgramSession's first cancellation check after
                        // the native open has acquired the session consumer.
                        openMonitorFailure = injected;
                    }
                    return result;
                });
            try {
                begin.invoke(session, "open_program");
                Throwable failure = null;
                try { open.invoke(session, target); }
                catch (InvocationTargetException caught) { failure = caught.getCause(); }
                finally { finish.invoke(session, false); }
                check(failure == injected, "Open lost its original failure: " + failure);
                check(selected == previous, "Failed open changed the selected Program");
                check(real.getConsumerList().equals(previousConsumers), "Failed open released the previous consumer");
                check(acquired[0] != null && acquired[0].isClosed()
                    && acquired[0].getConsumerList().isEmpty(), "Failed open leaked its target consumer");
                savedComment(CodeUnit.EOL_COMMENT, prior);
                open.invoke(session, file);
                check(selected.getDomainFile().getPathname().equals(file.getPathname()),
                    "Open could not recover after failure");
                Program retried = selected;
                open.invoke(session, real.getDomainFile());
                check(retried.isClosed(), "Switch retained the retried target Program");
                file.delete();
            } finally {
                openMonitorFailure = null;
                if (acquired[0] != null && acquired[0].isUsedBy(acquiredConsumer[0])) {
                    acquired[0].release(acquiredConsumer[0]);
                }
            }
        }
    }

    private void testSelectorSaveReceipt(String mode) throws Exception {
        boolean finishAssertion = mode.equals("selector-finish-assertion") || mode.equals("selector-commit-assertion");
        boolean commitBeforeAssertion = mode.equals("selector-commit-assertion");
        DomainFile previousFile = real.getDomainFile();
        DomainFile target = previousFile.copyTo(previousFile.getParent().createFolder("selector-target"), monitor);
        var previousConsumers = real.getConsumerList();
        Method targetedExecute = dispatcher.getClass().getDeclaredMethod("execute", String.class,
            JsonObject.class, String.class);
        targetedExecute.setAccessible(true);
        String previouslySaved = liveComment(CodeUnit.PRE_COMMENT);
        savesToFail = 1;
        saveFailed(command("comment_set", comment("pending-before-selector", "PRE")), "success");
        savedComment(CodeUnit.PRE_COMMENT, previouslySaved);
        int previousSaveCalls = saveCalls;
        Object targetOwner = new Object();
        Program heldTarget = null;
        Integer foreignTransaction = null;
        TransactionListener transactionListener = null;
        boolean[] finishAssertionDelivered = { false };
        if (mode.equals("selector-save-failure") || finishAssertion) {
            heldTarget = (Program) target.getDomainObject(targetOwner, true, false, monitor);
            if (mode.equals("selector-save-failure")) {
                foreignTransaction = heldTarget.startTransaction("test-owned selector target transaction");
            } else {
                transactionListener = new TransactionListener() {
                    private boolean armed;
                    private TransactionInfo owned;
                    public void transactionStarted(DomainObjectAdapterDB program, TransactionInfo info) {
                        armed = "ghidra-cli: comment_set".equals(info.getDescription());
                        if (armed) owned = info;
                    }
                    public void transactionEnded(DomainObjectAdapterDB program) {
                        if (!armed) return;
                        armed = false;
                        var current = program.getCurrentTransactionInfo();
                        check(commitBeforeAssertion
                            ? current != null && current.getID() == owned.getID()
                                && current.getOpenSubTransactions().isEmpty()
                            : current == null,
                            "Native finish assertion preceded the expected root state");
                        check(owned.getStatus() == (commitBeforeAssertion
                            ? TransactionInfo.Status.COMMITTED : TransactionInfo.Status.ABORTED),
                            "Native finish assertion followed unexpected transaction status");
                        finishAssertionDelivered[0] = true;
                        throw new AssertionError("injected native transaction-ended assertion");
                    }
                    public void undoStackChanged(DomainObjectAdapterDB program) {}
                    public void undoRedoOccurred(DomainObjectAdapterDB program) {}
                };
                heldTarget.addTransactionListener(transactionListener);
            }
        }
        cancelAfterSave = mode.equals("selector-save-receipt");
        if (mode.equals("selector-assertion")) {
            selectionFailureAfterSave = new AssertionError("injected post-save selector assertion");
        }
        JsonObject response = null;
        Throwable selectorFailure = null;
        try {
            response = (JsonObject) targetedExecute.invoke(dispatcher,
                mode.equals("selector-save-failure") ? "program_save" : "comment_set",
                comment(commitBeforeAssertion ? "committed-before-finish-assertion" : "must-not-change-target",
                    commitBeforeAssertion ? "PRE" : "invalid"), target.getPathname());
        } catch (InvocationTargetException failure) {
            selectorFailure = failure.getCause();
        } finally {
            cancelAfterSave = false;
            selectionFailureAfterSave = null;
            openMonitorFailure = null;
            requestMonitor.clearCancelled();
            if (transactionListener != null) heldTarget.removeTransactionListener(transactionListener);
            if (foreignTransaction != null) heldTarget.endTransaction(foreignTransaction, true);
            if (heldTarget != null) heldTarget.release(targetOwner);
        }
        check(saveCalls == previousSaveCalls + 1 && !real.isChanged(),
            "Selector fixture did not complete its durable save");
        savedComment(CodeUnit.PRE_COMMENT, "pending-before-selector");
        if (finishAssertion) {
            var current = selected.getCurrentTransactionInfo();
            check(finishAssertionDelivered[0] && (commitBeforeAssertion
                ? current != null && current.getStatus() == TransactionInfo.Status.COMMITTED
                    && current.getOpenSubTransactions().isEmpty()
                : current == null), "Native transaction-ended assertion did not retain expected root state");
            if (commitBeforeAssertion) {
                check(selected.isChanged() && "committed-before-finish-assertion".equals(
                    selected.getListing().getComment(CodeUnit.PRE_COMMENT, address)),
                    "Failed completion lost committed pending edits");
                Object reader = new Object();
                Program saved = (Program) target.getReadOnlyDomainObject(reader, DomainFile.DEFAULT_VERSION, TaskMonitor.DUMMY);
                try {
                    check(java.util.Objects.equals(previouslySaved, saved.getListing().getComment(CodeUnit.PRE_COMMENT, address)),
                        "Failed completion implicitly saved target edits");
                } finally { saved.release(reader); }
            }
        }
        check(selectorFailure == null, "Selector escaped its response boundary after saving: " + selectorFailure);
        JsonObject detail = failed(response);
        check(detail.has("partial_changes_saved") && detail.get("partial_changes_saved").getAsBoolean(),
            "Selector lost completed save receipt: " + response);
        check(detail.getAsJsonArray("saved_programs").size() == 1
            && detail.getAsJsonArray("saved_programs").get(0).getAsString().equals(previousFile.getPathname()),
            "Selector lost saved Program identity: " + response);
        if (mode.equals("selector-save-receipt") || mode.equals("selector-assertion")) {
            check(selected != null && selected.getDomainFile().equals(previousFile)
                && real.getConsumerList().equals(previousConsumers), "Cancelled selector changed selection or consumers");
            if (mode.equals("selector-save-receipt")) {
                check(detail.get("cancelled").getAsBoolean(), "Selector lost cancellation: " + response);
            } else {
                check(response.get("message").getAsString().contains("injected post-save selector assertion")
                    && !detail.has("cancelled"), "Selector lost native assertion: " + response);
            }
            check(!detail.has("rolled_back") && !detail.has("save_failed"), response.toString());
        } else {
            check(selected.getDomainFile().equals(target) && real.getConsumerList().size() == previousConsumers.size() - 1,
                "Successful selection did not transfer only its own consumer");
            check(detail.get("program").getAsString().equals(target.getPathname()),
                "Failure lost selected target identity: " + response);
            if (mode.equals("selector-save-failure")) {
                check(detail.get("save_failed").getAsBoolean() && !detail.get("saved").getAsBoolean()
                    && !detail.has("rolled_back") && detail.has("command_response"), response.toString());
                success(command("program_save", new JsonObject()));
            } else if (finishAssertion) {
                check(detail.get("transaction_failed").getAsBoolean() && !detail.has("rolled_back")
                    && !detail.has("save_failed") && detail.has("command_response"), response.toString());
                check(response.get("message").getAsString().contains("injected native transaction-ended assertion"),
                    "Transaction cleanup lost its native error: " + response);
                check(detail.getAsJsonObject("command_response").get("status").getAsString()
                    .equals(commitBeforeAssertion ? "success" : "error"),
                    "Transaction cleanup lost original command outcome: " + response);
                if (commitBeforeAssertion) {
                    // Ghidra clears a committed native root after invoking its
                    // listeners. Do not invent successful cleanup when that
                    // callback interrupted it; keep target and pending edits.
                    JsonObject blocked = (JsonObject) targetedExecute.invoke(dispatcher, "program_info", new JsonObject(),
                        previousFile.getPathname());
                    JsonObject blockedDetail = failed(blocked);
                    check(blockedDetail.get("save_failed").getAsBoolean()
                        && !blockedDetail.get("saved").getAsBoolean() && !blockedDetail.has("command_response")
                        && !blockedDetail.has("partial_changes_saved"), blocked.toString());
                    check(selected.getDomainFile().equals(target) && selected.isChanged()
                        && "committed-before-finish-assertion".equals(selected.getListing().getComment(CodeUnit.PRE_COMMENT, address)),
                        "Native incomplete commit lost the selected recovery Program");
                    return;
                }
                // Selection saves before its command transaction starts. A stale
                // wrapper for the already-ended native root must not block it.
                success((JsonObject) targetedExecute.invoke(dispatcher, "program_info", new JsonObject(),
                    previousFile.getPathname()));
                success((JsonObject) targetedExecute.invoke(dispatcher, "program_info", new JsonObject(),
                    target.getPathname()));
            } else {
                check(detail.get("rolled_back").getAsBoolean() && !detail.has("save_failed"), response.toString());
            }
            String expected = commitBeforeAssertion ? "committed-before-finish-assertion" : previouslySaved;
            check(java.util.Objects.equals(expected, selected.getListing().getComment(CodeUnit.PRE_COMMENT, address)),
                "Rejected target edit changed copied Program");
            Object reader = new Object();
            Program saved = (Program) target.getReadOnlyDomainObject(reader, DomainFile.DEFAULT_VERSION, TaskMonitor.DUMMY);
            try {
                check(prior.equals(saved.getListing().getComment(CodeUnit.EOL_COMMENT, address))
                    && java.util.Objects.equals(expected, saved.getListing().getComment(CodeUnit.PRE_COMMENT, address)),
                    "Rejected target edit changed persisted Program");
            } finally { saved.release(reader); }
        }

        JsonObject rejected = (JsonObject) targetedExecute.invoke(dispatcher, "program_info", new JsonObject(),
            target.getPathname() + "/absent");
        JsonObject rejectedDetail = failed(rejected);
        check(rejectedDetail == null || !rejectedDetail.has("partial_changes_saved"),
            "Selector inherited prior request save receipt: " + rejected);
        JsonObject selectedResponse = (JsonObject) targetedExecute.invoke(dispatcher, "program_info", new JsonObject(),
            target.getPathname());
        success(selectedResponse);
        check(selected.getDomainFile().equals(target), "Successful selector did not open target");
        session.getClass().getMethod("open", DomainFile.class).invoke(session, previousFile);
        savedComment(CodeUnit.EOL_COMMENT, prior);
        savedComment(CodeUnit.PRE_COMMENT, "pending-before-selector");
        success(command("comment_set", comment("after-selector-cancellation", "POST")));
        savedComment(CodeUnit.POST_COMMENT, "after-selector-cancellation");
        target.delete();
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
                case "late-error": case "late-assertion": case "cancel": case "native-false": testLateFailure(mode); break;
                case "stats-cancel": testStatsCancellation(); break;
                case "non-atomic-cancel": case "non-atomic-cancel-save":
                    testNonAtomicCancellationDiagnostics(mode.equals("non-atomic-cancel-save")); break;
                case "memory-error": case "memory-cancel": case "pointer-error": testMemoryFailure(mode); break;
                case "save-recovery": case "save-assertion": testSaveRecovery(mode); break;
                case "description-save": testDescriptionSaveRecovery(); break;
                case "storage-error": case "storage-cancel": case "storage-save": testStorageTransaction(mode); break;
                case "foreign-transaction": testForeignTransaction(); break;
                case "start-failure": testTransactionStartFailure(); break;
                case "mutation-leaked-child": testMutationLeakedChild(); break;
                case "preview-leaked-child": testPreviewLeakedChild(); break;
                case "preview-start-failure": testPreviewTransactionStartFailure(); break;
                case "cancelled-delete-refusal": testCancelledDeletionRefusal(); break;
                case "cancelled-delete-save": testCancelledDeletionAfterSave(); break;
                case "failed-open": testFailedOpenReleasesConsumer(); break;
                case "selector-save-receipt": case "selector-assertion": case "selector-rollback":
                case "selector-save-failure": case "selector-finish-assertion": case "selector-commit-assertion":
                    testSelectorSaveReceipt(mode); break;
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
                    // Cleanup follows the assertions. A failed probe must not
                    // hide its original error behind a stale native wrapper.
                    if (mode.equals("selector-finish-assertion") || mode.equals("selector-commit-assertion")) {
                        command("program_save", new JsonObject());
                    }
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
    let function = crate::common::helpers::get_fixture_function(&client, "add_numbers");
    let address = function.address;
    let original_name = function.name;
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
    assert_eq!(function["name"], original_name);
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
fn test_late_assertion_rolls_back_only_the_failed_request() {
    run_transaction_probe("late-assertion");
}

#[test]
#[serial]
fn test_memory_write_late_failure_restores_bytes_definitions_and_references() {
    run_transaction_probe("memory-error");
}

#[test]
#[serial]
fn test_memory_write_cancellation_restores_bytes_definitions_and_references() {
    run_transaction_probe("memory-cancel");
}

#[test]
#[serial]
fn test_memory_write_reference_failure_restores_bytes_definitions_and_references() {
    run_transaction_probe("pointer-error");
}

#[test]
#[serial]
fn test_cancellation_after_edit_rolls_back_only_the_cancelled_request() {
    run_transaction_probe("cancel");
}

#[test]
#[serial]
fn test_program_stats_cancellation_stops_scanning_and_preserves_later_requests() {
    run_transaction_probe("stats-cancel");
}

#[test]
#[serial]
fn test_non_atomic_cancelled_script_retains_cancellation_and_saved_changes_diagnostics() {
    run_transaction_probe("non-atomic-cancel");
}

#[test]
#[serial]
fn test_non_atomic_cancelled_script_save_failure_keeps_cancellation_and_pending_edits() {
    run_transaction_probe("non-atomic-cancel-save");
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
fn test_native_save_assertion_is_not_retried_and_pending_edits_survive_rollback() {
    run_transaction_probe("save-assertion");
}

#[test]
#[serial]
fn test_description_save_failure_retains_receipt_and_recovers_without_replay() {
    run_transaction_probe("description-save");
}

#[test]
#[serial]
fn test_storage_late_error_rolls_back_native_abi_update() {
    run_transaction_probe("storage-error");
}

#[test]
#[serial]
fn test_storage_cancellation_rolls_back_native_abi_update() {
    run_transaction_probe("storage-cancel");
}

#[test]
#[serial]
fn test_storage_save_failure_retains_receipt_and_pending_abi() {
    run_transaction_probe("storage-save");
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

#[test]
#[serial]
fn test_preview_transaction_start_failures_do_not_save_earlier_pending_edits() {
    run_transaction_probe("preview-start-failure");
}

#[test]
#[serial]
fn test_cancelled_deletion_refusal_restores_selection_and_preserves_consumers() {
    run_transaction_probe("cancelled-delete-refusal");
}

#[test]
#[serial]
fn test_cancellation_during_save_prevents_deletion_and_restores_selection() {
    run_transaction_probe("cancelled-delete-save");
}

#[test]
#[serial]
fn test_failed_program_open_releases_its_consumer_and_preserves_selection() {
    run_transaction_probe("failed-open");
}

#[test]
#[serial]
fn test_cancelled_selector_reports_saved_pending_edits_and_preserves_selection() {
    run_transaction_probe("selector-save-receipt");
}

#[test]
#[serial]
fn test_selector_assertion_reports_saved_pending_edits_and_preserves_selection() {
    run_transaction_probe("selector-assertion");
}

#[test]
#[serial]
fn test_native_finish_assertion_preserves_prior_saved_receipt_and_command_response() {
    run_transaction_probe("selector-finish-assertion");
}

#[test]
#[serial]
fn test_native_commit_assertion_retains_pending_edits_and_reports_blocked_selection() {
    run_transaction_probe("selector-commit-assertion");
}

#[test]
#[serial]
fn test_rejected_target_edit_reports_previous_program_saved_by_selector() {
    run_transaction_probe("selector-rollback");
}

#[test]
#[serial]
fn test_selector_save_receipt_survives_later_target_save_failure() {
    run_transaction_probe("selector-save-failure");
}
