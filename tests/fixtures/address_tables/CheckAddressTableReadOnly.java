import com.google.gson.JsonObject;
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;

/** Exercise cancellation inside getEntry and prove the detector never edits a Program. */
public class CheckAddressTableReadOnly extends GhidraScript {
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
            session = sessionClass.getConstructor(accessClass).newInstance(access);
            Class<?> resolverClass = loader.loadClass(prefix + "query.AddressResolver");
            Object resolver = resolverClass.getConstructor(sessionClass).newInstance(session);
            Class<?> commandsClass = loader.loadClass(prefix + "listing.AddressTableSearch");
            Object commands = commandsClass.getConstructor(sessionClass, resolverClass)
                .newInstance(session, resolver);
            var find = commandsClass.getMethod("handleFindAddressTables", JsonObject.class);
            JsonObject args = new JsonObject();
            args.addProperty("start", "0x1000");
            args.addProperty("end", "0x10ff");
            args.addProperty("alignment", 1);
            long modification = program.getModificationNumber();
            JsonObject baseline = (JsonObject) find.invoke(commands, args);
            if (baseline.get("count").getAsInt() != 2) {
                throw new IllegalStateException("Unexpected baseline: " + baseline);
            }
            for (int stop : new int[] {2, 5, 12}) {
                requestMonitor[0] = new TaskMonitorAdapter(true) {
                    private int checks;
                    @Override
                    public boolean isCancelled() {
                        if (++checks == stop) cancel();
                        return super.isCancelled();
                    }
                };
                try {
                    find.invoke(commands, args);
                    throw new IllegalStateException("Cancelled native scan returned partial success at " + stop);
                } catch (InvocationTargetException failure) {
                    if (!(failure.getCause() instanceof CancelledException)) throw failure;
                }
                requestMonitor[0] = new TaskMonitorAdapter(true);
                JsonObject recovered = (JsonObject) find.invoke(commands, args);
                if (!baseline.equals(recovered)) {
                    throw new IllegalStateException("Fresh request did not recover: " + recovered);
                }
            }
            if (program.getModificationNumber() != modification) {
                throw new IllegalStateException("Address-table queries modified the database");
            }
        } finally {
            try {
                if (session != null) sessionClass.getMethod("closeProgram").invoke(session);
            } finally {
                program.release(reader);
            }
        }
    }
}
