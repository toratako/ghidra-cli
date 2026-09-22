import com.google.gson.JsonObject;
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;

/** Cancel both source enumeration and result serialization without returning partial success. */
public class CheckFileMappingCancellation extends GhidraScript {
    public void run() throws Exception {
        Class<?> caller = StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
            .walk(frames -> frames.map(StackWalker.StackFrame::getDeclaringClass)
                .filter(type -> type.getSimpleName().equals("ScriptCommands")
                    && type.getPackageName().equals("ghidracli"))
                .findFirst().orElseThrow());
        ClassLoader loader = caller.getClassLoader();
        String prefix = caller.getPackageName() + ".";
        Object reader = new Object();
        Program program = (Program) currentProgram.getDomainFile()
            .getReadOnlyDomainObject(reader, DomainFile.DEFAULT_VERSION, TaskMonitor.DUMMY);
        Program[] selected = {program};
        TaskMonitor[] requestMonitor = {new TaskMonitorAdapter(true)};
        Class<?> sessionClass = loader.loadClass(prefix + "ProgramSession");
        Object session = null;
        try {
            Class<?> accessClass = loader.loadClass(prefix + "ScriptAccess");
            Object access = Proxy.newProxyInstance(loader, new Class<?>[] {accessClass},
                (proxy, method, args) -> {
                    switch (method.getName()) {
                        case "program": return selected[0];
                        case "setProgram": selected[0] = (Program) args[0]; return null;
                        case "monitor": return requestMonitor[0];
                        default: throw new UnsupportedOperationException(method.getName());
                    }
                });
            var constructor = sessionClass.getDeclaredConstructor(accessClass);
            constructor.setAccessible(true);
            session = constructor.newInstance(access);
            Class<?> commandsClass = loader.loadClass(prefix + "FileMappingCommands");
            var commandsConstructor = commandsClass.getDeclaredConstructor(sessionClass);
            commandsConstructor.setAccessible(true);
            Object commands = commandsConstructor.newInstance(session);
            var find = commandsClass.getDeclaredMethod("handleFileMappings", JsonObject.class);
            find.setAccessible(true);
            for (int stop : new int[] {1, 12, 30}) {
                requestMonitor[0] = new TaskMonitorAdapter(true) {
                    private int checks;
                    @Override
                    public void checkCancelled() throws CancelledException {
                        if (++checks == stop) cancel();
                        super.checkCancelled();
                    }
                };
                try {
                    find.invoke(commands, new JsonObject());
                    throw new IllegalStateException("Cancelled scan returned a successful partial result at " + stop);
                } catch (InvocationTargetException failure) {
                    if (!(failure.getCause() instanceof CancelledException)) throw failure;
                }
                requestMonitor[0] = new TaskMonitorAdapter(true);
                JsonObject result = (JsonObject) find.invoke(commands, new JsonObject());
                if (result.get("count").getAsInt() != 8) {
                    throw new IllegalStateException("Fresh monitor did not recover the full query: " + result);
                }
            }
        } finally {
            try {
                if (session != null) {
                    var close = sessionClass.getDeclaredMethod("closeProgram");
                    close.setAccessible(true);
                    close.invoke(session);
                }
            } finally {
                program.release(reader);
            }
        }
    }
}
