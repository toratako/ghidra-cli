use super::{start_daemon, TEST_PROGRAM};
use crate::common::{ensure_test_project, test_project};
use serial_test::serial;

// Use a separate saved Program and the real dispatcher, as in transaction.rs.
// Native callbacks inject cancellation/timeout without timing a large function.
const DECOMPILER_PROBE: &str = r#"
import com.google.gson.JsonObject;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileProcess;
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitorAdapter;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.concurrent.TimeUnit;

public class DecompilerSessionProbe extends GhidraScript {
    private Program real;
    private Program selected;
    private Object session;
    private Object dispatcher;
    private Method execute;
    private TaskMonitorAdapter requestMonitor = new TaskMonitorAdapter(true);
    private String fault;
    private boolean failSave;
    private String address;
    private String otherAddress;
    private String originalName;

    private static void check(boolean condition, String message) {
        if (!condition) throw new IllegalStateException(message);
    }

    private static Object field(Object object, String name) throws Exception {
        Field field = object.getClass().getDeclaredField(name);
        field.setAccessible(true);
        return field.get(object);
    }

    private DecompInterface engine() throws Exception {
        return (DecompInterface) field(field(session, "decompiler"), "decompiler");
    }

    private static DecompileProcess process(DecompInterface engine) throws Exception {
        return (DecompileProcess) field(engine, "decompProcess");
    }

    private static Object invoke(Method method, Object target, Object... args) throws Throwable {
        try { return method.invoke(target, args); }
        catch (InvocationTargetException failure) { throw failure.getCause(); }
    }

    private Object sessionCall(String name, Class<?>[] types, Object... args) throws Exception {
        Method method = session.getClass().getDeclaredMethod(name, types);
        method.setAccessible(true);
        return method.invoke(session, args);
    }

    private JsonObject command(String name, JsonObject args) throws Exception {
        // Match the scheduler's fresh monitor for every request.
        requestMonitor = new TaskMonitorAdapter(true);
        return (JsonObject) execute.invoke(dispatcher, name, args);
    }

    private static JsonObject args(String... pairs) {
        JsonObject args = new JsonObject();
        for (int i = 0; i < pairs.length; i += 2) args.addProperty(pairs[i], pairs[i + 1]);
        return args;
    }

    private static JsonObject success(JsonObject response) {
        check("success".equals(response.get("status").getAsString()), response.toString());
        return response.getAsJsonObject("data");
    }

    private JsonObject decompile() throws Exception {
        JsonObject args = args("address", address);
        args.addProperty("with_params", true);
        return success(command("decompile", args));
    }

    private void configure() throws Exception {
        Class<?> caller = StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
            .walk(frames -> frames.map(StackWalker.StackFrame::getDeclaringClass)
                .filter(type -> type.getSimpleName().equals("ScriptCommands")
                    && type.getPackageName().equals("ghidracli"))
                .findFirst().orElseThrow());
        ClassLoader loader = caller.getClassLoader();
        String pkg = caller.getPackageName() + ".";
        Listing listing = (Listing) Proxy.newProxyInstance(Listing.class.getClassLoader(),
            new Class<?>[] { Listing.class }, (proxy, method, args) -> {
                if (method.getName().equals("getInstructionAt") && fault != null) {
                    String mode = fault;
                    fault = null;
                    if (mode.equals("cancel")) requestMonitor.cancel();
                    else {
                        DecompileProcess nativeProcess = process(engine());
                        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
                        while (nativeProcess.getDisposeState()
                                == DecompileProcess.DisposeState.NOT_DISPOSED
                                && System.nanoTime() < deadline) Thread.sleep(10);
                        check(nativeProcess.getDisposeState()
                            == DecompileProcess.DisposeState.DISPOSED_ON_TIMEOUT,
                            "Native timeout did not fire during the blocked callback");
                    }
                }
                return invoke(method, real.getListing(), args);
            });
        selected = (Program) Proxy.newProxyInstance(Program.class.getClassLoader(),
            new Class<?>[] { Program.class }, (proxy, method, args) -> {
                if (method.getName().equals("getListing")) return listing;
                if (method.getName().equals("save") && failSave) {
                    failSave = false;
                    throw new IOException("injected save failure");
                }
                return invoke(method, real, args);
            });
        Class<?> accessClass = loader.loadClass(pkg + "ScriptAccess");
        Object access = Proxy.newProxyInstance(loader, new Class<?>[] { accessClass },
            (proxy, method, args) -> {
                switch (method.getName()) {
                    case "program": return selected;
                    case "setProgram": selected = (Program) args[0]; return null;
                    case "state": return state;
                    case "monitor": return requestMonitor;
                    default: throw new UnsupportedOperationException(method.getName());
                }
            });
        Class<?> sessionClass = loader.loadClass(pkg + "ProgramSession");
        var constructor = sessionClass.getDeclaredConstructor(accessClass);
        constructor.setAccessible(true);
        session = constructor.newInstance(access);
        Class<?> dispatcherClass = loader.loadClass(pkg + "CommandDispatcher");
        var dispatcherConstructor = dispatcherClass.getDeclaredConstructor(sessionClass);
        dispatcherConstructor.setAccessible(true);
        dispatcher = dispatcherConstructor.newInstance(session);
        execute = dispatcherClass.getDeclaredMethod("execute", String.class, JsonObject.class);
        execute.setAccessible(true);
    }

    private void reuseAndChanges() throws Exception {
        check(engine() == null, "Decompiler started before first use");
        JsonObject initial = decompile();
        DecompInterface shared = engine();
        DecompileProcess nativeProcess = process(shared);
        check(initial.equals(decompile()), "Repeated decompile changed output");
        success(command("decompile", args("address", otherAddress)));
        JsonObject high = args("function", address);
        high.addProperty("high", true);
        check(success(command("pcode_function", high)).get("count").getAsInt() > 0,
            "High P-code is empty");
        check(shared == engine() && nativeProcess == process(engine()),
            "Read-only requests restarted the decompiler");

        String parameter = initial.getAsJsonArray("params").get(0).getAsJsonObject()
            .get("name").getAsString();
        success(command("function_edit_var", args("target", address, "var_name", parameter,
            "new_name", "session_input")));
        check(shared == engine(), "Variable edit did not share the decompiler");
        check(decompile().getAsJsonArray("params").get(0).getAsJsonObject()
            .get("name").getAsString().equals("session_input"), "Stale parameter after saved edit");
        check(shared != engine() && shared.getProgram() == null,
            "Saved edit did not invalidate the old decompiler");

        // Decompile a transient edit inside a request, then roll it back. The
        // following request must not reuse either its state or Function objects.
        sessionCall("beginRequest", new Class<?>[] { String.class }, "test-decompiler-rollback");
        DecompInterface transientEngine;
        try {
            var function = real.getFunctionManager().getFunctionAt(real.getAddressFactory().getAddress(address));
            function.setName("transient_name", SourceType.USER_DEFINED);
            sessionCall("decompile", new Class<?>[] { ghidra.program.model.listing.Function.class, int.class },
                function, 0);
            transientEngine = engine();
        } finally { sessionCall("finishRequest", new Class<?>[] { boolean.class }, false); }
        check(decompile().get("name").getAsString().equals(originalName), "Rolled-back name leaked");
        check(engine() != transientEngine && transientEngine.getProgram() == null,
            "Rollback retained the transient decompiler");
    }

    private void failures() throws Exception {
        for (String mode : new String[] { "cancel", "timeout" }) {
            DecompInterface previous = engine();
            fault = mode;
            JsonObject args = args("address", address);
            args.addProperty("timeout_secs", 1);
            JsonObject response = command("decompile", args);
            check(fault == null, "Fault did not reach the native callback");
            check("error".equals(response.get("status").getAsString()), response.toString());
            if (mode.equals("cancel")) {
                check(response.getAsJsonObject("detail").get("cancelled").getAsBoolean(), response.toString());
            } else {
                check(response.get("message").getAsString().contains("timed out"), response.toString());
            }
            check(engine() == null && previous.getProgram() == null, "Failed decompiler was retained");
            TaskMonitorAdapter oldMonitor = requestMonitor;
            decompile();
            DecompInterface recovered = engine();
            oldMonitor.cancel();
            decompile();
            check(recovered == engine(), "Old monitor cancelled a later request");
        }

        // A failed durable save must keep the selected Program and its live
        // decompiler available. Only a successful close may release them.
        success(command("rename_function", args("old_name", originalName, "new_name", "saved_name")));
        int transaction = real.startTransaction("pending edit");
        try {
            real.getFunctionManager().getFunctionAt(real.getAddressFactory().getAddress(address))
                .setName("pending_name", SourceType.USER_DEFINED);
        } finally { real.endTransaction(transaction, true); }
        DecompInterface previous = engine();
        failSave = true;
        JsonObject response = command("program_close", new JsonObject());
        check(response.getAsJsonObject("detail").get("save_failed").getAsBoolean(), response.toString());
        check(selected != null && engine() == previous && previous.getProgram() != null,
            "Failed close released the Program/decompiler");
        check(decompile().get("name").getAsString().equals("pending_name"), "Pending edit was lost");
    }

    public void run() throws Exception {
        var folder = state.getProject().getProjectData().getRootFolder().createFolder(getScriptArgs()[0]);
        DomainFile first = currentProgram.getDomainFile().copyTo(folder, monitor);
        DomainFile second = currentProgram.getDomainFile().copyTo(folder.createFolder("second"), monitor);
        Object owner = new Object();
        real = (Program) first.getDomainObject(owner, true, false, monitor);
        try {
            address = getScriptArgs()[1];
            otherAddress = getScriptArgs()[2];
            originalName = real.getFunctionManager()
                .getFunctionAt(real.getAddressFactory().getAddress(address)).getName();
            configure();
            reuseAndChanges();
            failures();
            DecompInterface previous = engine();
            DecompileProcess nativeProcess = process(previous);
            success(command("open_program", args("program", second.getPathname())));
            check(engine() == null && previous.getProgram() == null,
                "Switch retained the previous Program in the decompiler");
            check(nativeProcess.getDisposeState() != DecompileProcess.DisposeState.NOT_DISPOSED,
                "Switch left the native process running");
            check(decompile().get("name").getAsString().equals(originalName),
                "Same-named Program switch returned the first Program's result");
            previous = engine();
            success(command("program_close", new JsonObject()));
            check(engine() == null && previous.getProgram() == null, "Close retained the decompiler");
            success(command("open_program", args("program", first.getPathname())));
            check(decompile().get("name").getAsString().equals("pending_name"), "Reopen lost saved edits");
            println("decompiler-session-ok");
        } finally {
            fault = null;
            failSave = false;
            requestMonitor.clearCancelled();
            try {
                if (session != null) sessionCall("closeProgram", new Class<?>[0]);
            } finally { real.release(owner); }
        }
    }
}
"#;

#[test]
#[serial]
fn test_decompiler_reuse_invalidation_and_recovery() {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    let client = harness.client().unwrap();
    let function = crate::common::helpers::get_fixture_function(&client, "add_numbers");
    let other = crate::common::helpers::get_fixture_function(&client, "multiply");
    let result = client
        .script_run_source(
            DECOMPILER_PROBE,
            &[
                format!("decompiler-{}", uuid::Uuid::new_v4()),
                function.address,
                other.address,
            ],
            &[],
            false,
        )
        .unwrap();
    assert!(
        result["stdout"]
            .as_str()
            .unwrap()
            .contains("decompiler-session-ok"),
        "{result}"
    );
}
