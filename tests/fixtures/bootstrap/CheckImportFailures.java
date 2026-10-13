import com.google.gson.JsonObject;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;

/** Verify detached import failure diagnostics and program ownership. */
public class CheckImportFailures extends GhidraScript {
    public void run() throws Exception {
        Class<?> caller = StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
            .walk(frames -> frames.map(StackWalker.StackFrame::getDeclaringClass)
                .filter(type -> type.getSimpleName().equals("ScriptCommands")
                    && type.getPackageName().equals("ghidracli.script"))
                .findFirst().orElseThrow());
        String bridgePackage = caller.getPackageName()
            .substring(0, caller.getPackageName().lastIndexOf('.') + 1);
        ClassLoader loader = caller.getClassLoader();
        Class<?> support = loader.loadClass(bridgePackage + "project.ImportSupport");
        Class<?> analysis = loader.loadClass(bridgePackage + "project.ImportSupport$Analysis");
        var run = support.getMethod("run", ghidra.framework.model.Project.class,
            JsonObject.class, Object.class, TaskMonitor.class, analysis);
        var failure = support.getMethod("failure", Exception.class);
        Object consumer = new Object();
        for (String mode : new String[] {"cancelled", "failed", "aborted"}) {
            boolean cancel = mode.equals("cancelled");
            String name = mode + "-import";
            JsonObject request = request(name);
            TaskMonitorAdapter task = new TaskMonitorAdapter(true);
            Program[] detached = {null};
            Object callback = Proxy.newProxyInstance(loader, new Class<?>[] {analysis},
                (proxy, method, arguments) -> {
                    detached[0] = (Program) arguments[0];
                    detached[0].getOptions(Program.PROGRAM_INFO).setString("Import Failure Probe", name);
                    if (cancel) {
                        task.cancel();
                        return null;
                    }
                    if (mode.equals("aborted")) {
                        int child = detached[0].startTransaction("Abort import analysis probe");
                        detached[0].endTransaction(child, false);
                        return null;
                    }
                    throw new IOException("analysis failure probe");
                });
            try {
                run.invoke(null, state.getProject(), request, consumer, task, callback);
                throw new AssertionError("Faulted import succeeded: " + name);
            } catch (InvocationTargetException error) {
                Exception cause = (Exception) error.getCause();
                JsonObject response = (JsonObject) failure.invoke(null, cause);
                JsonObject detail = response.getAsJsonObject("detail");
                if (!detail.get("stage").getAsString().equals("import.analysis")
                        || !detail.get("import_status").getAsString().equals("unknown")
                        || !detail.get("analysis_status").getAsString().equals("unknown")
                        || !detail.has("loader_diagnostics")
                        || (cancel && (!detail.has("cancelled") || !detail.get("cancelled").getAsBoolean()))
                        || (!cancel && detail.has("cancelled"))) {
                    throw new AssertionError(response.toString());
                }
                Throwable original = cause.getCause() == null ? null : cause.getCause().getCause();
                Class<?> expected = cancel ? CancelledException.class
                    : mode.equals("aborted") ? IllegalStateException.class : IOException.class;
                if (!expected.isInstance(original)) {
                    throw new AssertionError("Import failure lost its cause: " + cause);
                }
            }
            if (detached[0] == null || !detached[0].isClosed()) {
                throw new AssertionError("Failed import retained its detached program: " + name);
            }
            if (state.getProject().getProjectData().getRootFolder().getFile(name) != null) {
                throw new AssertionError("Failed analysis saved a project file: " + name);
            }
        }
        JsonObject result = (JsonObject) run.invoke(null, state.getProject(),
            request("recovered-import"), consumer, new TaskMonitorAdapter(true), null);
        if (!result.get("import_status").getAsString().equals("saved")
                || !result.get("analysis_status").getAsString().equals("skipped")) {
            throw new AssertionError(result.toString());
        }
    }

    private JsonObject request(String name) {
        JsonObject request = new JsonObject();
        request.addProperty("binary_path", getScriptArgs()[0]);
        request.addProperty("program", name);
        request.addProperty("loader", "BinaryLoader");
        request.addProperty("language", "x86:LE:32:default");
        return request;
    }
}
