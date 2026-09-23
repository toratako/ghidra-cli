import com.google.gson.JsonObject;
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;

/** Read-only DB ownership proves successful, partial, invalid and cancelled reads never edit. */
public class CheckVtableReadOnly extends GhidraScript {
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
            Class<?> resolverClass = loader.loadClass(prefix + "query.AddressResolver");
            Object resolver = resolverClass.getConstructor(sessionClass).newInstance(session);
            Class<?> commandsClass = loader.loadClass(prefix + "analysis.VtableCommands");
            Object commands = commandsClass.getConstructor(sessionClass, resolverClass)
                .newInstance(session, resolver);
            var read = commandsClass.getMethod("handleRead", JsonObject.class);
            JsonObject args = new JsonObject();
            args.addProperty("target", "0x1020");
            args.addProperty("entries", 5);
            args.addProperty("abi", "itanium");
            long before = program.getModificationNumber();
            JsonObject complete = (JsonObject) read.invoke(commands, args);
            if (!complete.get("complete").getAsBoolean()) {
                throw new IllegalStateException("Fixture read incomplete: " + complete);
            }
            args.addProperty("target", "0x12f0");
            JsonObject partial = (JsonObject) read.invoke(commands, args);
            if (partial.get("complete").getAsBoolean()) {
                throw new IllegalStateException("Unmapped slots reported complete: " + partial);
            }
            args.addProperty("entries", 0);
            try {
                read.invoke(commands, args);
                throw new IllegalStateException("Zero entry count accepted");
            } catch (InvocationTargetException failure) {
                if (!(failure.getCause() instanceof IllegalArgumentException)) throw failure;
            }
            args.addProperty("target", "0x1020");
            args.addProperty("entries", 5);
            requestMonitor[0] = new TaskMonitorAdapter(true) {
                private int checks;
                @Override
                public void checkCancelled() throws CancelledException {
                    if (++checks == 12) cancel();
                    super.checkCancelled();
                }
            };
            try {
                read.invoke(commands, args);
                throw new IllegalStateException("Cancelled read returned success");
            } catch (InvocationTargetException failure) {
                if (!(failure.getCause() instanceof CancelledException)) throw failure;
            }
            requestMonitor[0] = new TaskMonitorAdapter(true);
            if (!complete.equals(read.invoke(commands, args))) {
                throw new IllegalStateException("Fresh read changed after cancellation");
            }
            if (program.getModificationNumber() != before) {
                throw new IllegalStateException("VTable reads changed the Program");
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
