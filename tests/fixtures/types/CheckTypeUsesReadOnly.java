import com.google.gson.JsonObject;
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;

/** Query a separate read-only database and cancel in the middle of a wrapper traversal. */
public class CheckTypeUsesReadOnly extends GhidraScript {
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
        TaskMonitor[] requestMonitor = {new TaskMonitorAdapter(true)};
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
            var constructor = sessionClass.getDeclaredConstructor(accessClass);
            constructor.setAccessible(true);
            session = constructor.newInstance(access);
            Class<?> resolverClass = loader.loadClass(prefix + "types.TypeResolver");
            Object resolver = resolverClass.getConstructor(sessionClass).newInstance(session);
            Class<?> commandsClass = loader.loadClass(prefix + "types.TypeUsesCommands");
            Object commands = commandsClass.getConstructor(sessionClass, resolverClass)
                .newInstance(session, resolver);
            var find = commandsClass.getMethod("handleUses", JsonObject.class);
            JsonObject args = new JsonObject();
            args.addProperty("type_name", "/Recovered/Widget");
            long before = program.getModificationNumber();
            JsonObject complete = (JsonObject) find.invoke(commands, args);
            if (complete.getAsJsonArray("uses").size() != 18
                    || !complete.getAsJsonObject("scan").get("complete").getAsBoolean()) {
                throw new IllegalStateException("Read-only query lost declarations: " + complete);
            }
            requestMonitor[0] = new TaskMonitorAdapter(true) {
                private int checks;
                @Override
                public void checkCancelled() throws CancelledException {
                    if (++checks == 12) cancel();
                    super.checkCancelled();
                }
            };
            try {
                find.invoke(commands, args);
                throw new IllegalStateException("Cancelled query returned a successful partial result");
            } catch (InvocationTargetException failure) {
                if (!(failure.getCause() instanceof CancelledException)) throw failure;
            }
            requestMonitor[0] = new TaskMonitorAdapter(true);
            if (!complete.equals(find.invoke(commands, args))) {
                throw new IllegalStateException("Fresh query did not recover all declarations");
            }
            if (program.getModificationNumber() != before) {
                throw new IllegalStateException("Type-use queries changed the Program");
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
