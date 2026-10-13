import com.google.gson.JsonObject;
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;

public class CheckRelocationCancellation extends GhidraScript {
    public void run() throws Exception {
        Class<?> caller = StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
            .walk(frames -> frames.map(StackWalker.StackFrame::getDeclaringClass)
                .filter(type -> type.getSimpleName().equals("ScriptCommands")
                    && type.getPackageName().equals("ghidracli.script"))
                .findFirst().orElseThrow());
        ClassLoader loader = caller.getClassLoader();
        String prefix = caller.getPackageName()
            .substring(0, caller.getPackageName().lastIndexOf('.') + 1);

        Object reader = new Object();
        Program program = (Program) currentProgram.getDomainFile()
            .getReadOnlyDomainObject(reader, DomainFile.DEFAULT_VERSION, TaskMonitor.DUMMY);
        Program[] selected = {program};
        TaskMonitor[] requestMonitor = {new TaskMonitorAdapter(true) {
            private int checks;
            @Override
            public void checkCancelled() throws CancelledException {
                if (++checks == 2) cancel();
                super.checkCancelled();
            }
        }};
        Class<?> sessionClass = loader.loadClass(prefix + "session.ProgramSession");
        Object session = null;
        try {
            Class<?> accessClass = loader.loadClass(prefix + "session.ScriptAccess");
            Object access = Proxy.newProxyInstance(loader, new Class<?>[] {accessClass},
                (proxy, method, args) -> {
                    switch (method.getName()) {
                        case "program": return selected[0];
                        case "setProgram": selected[0] = (Program) args[0]; return null;
                        case "monitor": return requestMonitor[0];
                        default: throw new UnsupportedOperationException(method.getName());
                    }
                });
            var sessionConstructor = sessionClass.getDeclaredConstructor(accessClass);
            sessionConstructor.setAccessible(true);
            session = sessionConstructor.newInstance(access);
            Class<?> commandsClass = loader.loadClass(prefix + "program.ProgramCommands");
            var commandsConstructor = commandsClass.getDeclaredConstructor(sessionClass);
            commandsConstructor.setAccessible(true);
            Object commands = commandsConstructor.newInstance(session);
            var list = commandsClass.getDeclaredMethod("handleListRelocations");
            list.setAccessible(true);
            try {
                list.invoke(commands);
                throw new IllegalStateException("Cancelled relocation scan returned partial success");
            } catch (InvocationTargetException failure) {
                if (!(failure.getCause() instanceof CancelledException)) throw failure;
            }
            requestMonitor[0] = new TaskMonitorAdapter(true);
            JsonObject result = (JsonObject) list.invoke(commands);
            if (result.get("count").getAsInt() != 4) {
                throw new IllegalStateException("Fresh monitor did not recover all relocations: " + result);
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
