import com.google.gson.JsonObject;
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

/** Graph and CFG reads on an independently opened saved, read-only Program. */
public class CheckCallQueriesReadOnly extends GhidraScript {
    private static void check(boolean condition, String message) {
        if (!condition) throw new IllegalStateException(message);
    }

    private static JsonObject query(Method method, Object owner, JsonObject args) throws Exception {
        JsonObject result = (JsonObject) method.invoke(owner, args);
        // CFG identities belong to one result; compare its semantic content.
        result.remove("result_id");
        return result;
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
                        case "state": return state;
                        case "setProgram": selected[0] = (Program) args[0]; return null;
                        case "monitor": return requestMonitor[0];
                        default: throw new UnsupportedOperationException(method.getName());
                    }
                });
            session = sessionClass.getConstructor(accessClass).newInstance(access);
            Class<?> resolverClass = loader.loadClass(prefix + "query.AddressResolver");
            Object resolver = resolverClass.getConstructor(sessionClass).newInstance(session);
            Class<?> queriesClass = loader.loadClass(prefix + "function.FunctionQueries");
            Object queries = queriesClass.getConstructor(sessionClass, resolverClass)
                .newInstance(session, resolver);
            Class<?> graphClass = loader.loadClass(prefix + "analysis.GraphCommands");
            Object graph = graphClass.getConstructor(sessionClass, queriesClass)
                .newInstance(session, queries);
            Class<?> cfgClass = loader.loadClass(prefix + "analysis.InstructionCfg");
            Object cfg = cfgClass.getConstructor(sessionClass, queriesClass)
                .newInstance(session, queries);
            Method[] methods = {
                graphClass.getMethod("handleGraphCallees", JsonObject.class),
                graphClass.getMethod("handleGraphCallers", JsonObject.class),
                graphClass.getMethod("handleGraphCalls", JsonObject.class),
                cfgClass.getMethod("handle", JsonObject.class)
            };
            Object[] owners = {graph, graph, graph, cfg};
            String[] targets = {"pointer_caller", "target", null, "diamond"};
            long modification = program.getModificationNumber();
            for (int i = 0; i < methods.length; i++) {
                JsonObject args = new JsonObject();
                if (targets[i] != null) args.addProperty("function", targets[i]);
                JsonObject baseline = query(methods[i], owners[i], args);
                check(!baseline.has("error"), "Read-only query failed: " + baseline);
                check(!program.isChanged(), "Baseline query changed the saved database");
                for (int stop : new int[] {1, 3}) {
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
                        methods[i].invoke(owners[i], args);
                        throw new IllegalStateException("Cancelled " + methods[i].getName()
                            + " returned success at " + stop);
                    } catch (InvocationTargetException failure) {
                        if (!(failure.getCause() instanceof CancelledException)) throw failure;
                    }
                    requestMonitor[0] = new TaskMonitorAdapter(true);
                    check(baseline.equals(query(methods[i], owners[i], args)),
                        "Fresh query did not recover after cancellation");
                    cancelled.clearCancelled();
                    cancelled.cancel();
                    check(baseline.equals(query(methods[i], owners[i], args)),
                        "Old query monitor cancelled a fresh request");
                }
            }
            check(program.getModificationNumber() == modification && !program.isChanged(),
                "Graph, CFG or cancelled query edited the saved database");
        } catch (InvocationTargetException failure) {
            throw new IllegalStateException("Read-only graph probe: " + failure.getCause(), failure.getCause());
        } finally {
            try {
                if (session != null) sessionClass.getMethod("closeProgram").invoke(session);
            } finally {
                program.release(reader);
            }
        }
    }
}
