import com.google.gson.JsonObject;
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;

/** Search an independently opened saved database without a transaction or writable Program. */
public class CheckFunctionCandidatesReadOnly extends GhidraScript {
    private static void check(boolean condition, String message) {
        if (!condition) throw new IllegalStateException(message);
    }

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
            Class<?> commandsClass = loader.loadClass(prefix + "function.FunctionCandidateSearch");
            Object commands = commandsClass.getConstructor(sessionClass, resolverClass)
                .newInstance(session, resolver);
            var find = commandsClass.getMethod("handleFindFunctionCandidates", JsonObject.class);
            JsonObject args = new JsonObject();
            args.addProperty("limit", 0);
            long modification = program.getModificationNumber();
            JsonObject baseline = (JsonObject) find.invoke(commands, args);
            check(baseline.get("count").getAsInt() == 13, "Unexpected baseline: " + baseline);
            check(!program.isChanged(), "Baseline query changed the saved database");
            // Deterministic monitor checks exercise cancellation at different scan depths.
            for (int stop : new int[] {1, 3, 12, 30}) {
                TaskMonitorAdapter cancelled = new TaskMonitorAdapter(true) {
                    private int checks;
                    @Override
                    public void checkCancelled() throws CancelledException {
                        if (++checks == stop) cancel();
                        super.checkCancelled();
                    }
                };
                requestMonitor[0] = cancelled;
                try {
                    find.invoke(commands, args);
                    throw new IllegalStateException("Cancellation returned partial success at " + stop);
                } catch (InvocationTargetException failure) {
                    if (!(failure.getCause() instanceof CancelledException)) throw failure;
                }
                requestMonitor[0] = new TaskMonitorAdapter(true);
                check(baseline.equals(find.invoke(commands, args)), "Fresh request did not recover at " + stop);
                cancelled.clearCancelled();
                cancelled.cancel();
                check(baseline.equals(find.invoke(commands, args)), "Old monitor cancelled a fresh request");
            }
            args.addProperty("limit", 1);
            JsonObject limited = (JsonObject) find.invoke(commands, args);
            check(limited.get("count").getAsInt() == 1, "Native result budget: " + limited);
            check(!limited.getAsJsonObject("scan").get("complete").getAsBoolean(),
                "Budget-limited scan claimed completeness");
            check(program.getModificationNumber() == modification && !program.isChanged(),
                "Queries or cancellation edited the saved database");
        } catch (InvocationTargetException failure) {
            throw new IllegalStateException("Candidate read-only probe: " + failure.getCause(), failure.getCause());
        } finally {
            try {
                if (session != null) sessionClass.getMethod("closeProgram").invoke(session);
            } finally {
                program.release(reader);
            }
        }
    }
}
