import com.google.gson.JsonObject;
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;

/** Cancel selection and result serialization without timing-dependent job races. */
public class CheckStructureInferenceCancellation extends GhidraScript {
    public void run() throws Exception {
        Class<?> caller = StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
            .walk(frames -> frames.map(StackWalker.StackFrame::getDeclaringClass)
                .filter(type -> type.getSimpleName().equals("ScriptCommands")
                    && type.getPackageName().equals("ghidracli.script"))
                .findFirst().orElseThrow());
        ClassLoader loader = caller.getClassLoader();
        String prefix = caller.getPackageName().substring(0, caller.getPackageName().lastIndexOf('.') + 1);
        Class<?> sessionClass = loader.loadClass(prefix + "session.ProgramSession");
        Class<?> commandsClass = loader.loadClass(prefix + "analysis.StructureInferenceCommands");
        Object reader = new Object();
        Program program = (Program) currentProgram.getDomainFile()
            .getReadOnlyDomainObject(reader, DomainFile.DEFAULT_VERSION, TaskMonitor.DUMMY);
        Program[] selected = {program};
        TaskMonitor[] requestMonitor = {new TaskMonitorAdapter(true)};
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
            Class<?> queriesClass = loader.loadClass(prefix + "function.FunctionQueries");
            Object queries = queriesClass.getConstructor(sessionClass, resolverClass).newInstance(session, resolver);
            Object commands = commandsClass.getConstructor(sessionClass, queriesClass).newInstance(session, queries);
            var infer = commandsClass.getMethod("handleInfer", JsonObject.class);
            JsonObject args = new JsonObject();
            args.addProperty("target", "recover");
            args.addProperty("var_name", "ctx");
            args.addProperty("with_accesses", true);
            long modification = program.getModificationNumber();
            for (String phase : new String[] {"wholeVariable", "describe", "addAccesses"}) {
                requestMonitor[0] = new TaskMonitorAdapter(true) {
                    @Override
                    public void checkCancelled() throws CancelledException {
                        boolean reached = StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
                            .walk(frames -> frames.anyMatch(frame -> frame.getDeclaringClass() == commandsClass
                                && frame.getMethodName().equals(phase)));
                        if (reached) cancel();
                        super.checkCancelled();
                    }
                };
                try {
                    Object result = infer.invoke(commands, args);
                    throw new IllegalStateException("Cancelled " + phase + " returned a result: " + result);
                } catch (InvocationTargetException failure) {
                    if (!(failure.getCause() instanceof CancelledException)) throw failure;
                }
                if (program.getModificationNumber() != modification) {
                    throw new IllegalStateException("Cancelled inference changed the program");
                }
                requestMonitor[0] = new TaskMonitorAdapter(true);
                JsonObject result = (JsonObject) infer.invoke(commands, args);
                if (!result.has("structure") || result.get("structure").isJsonNull()
                        || result.getAsJsonArray("accesses").size() != 2) {
                    throw new IllegalStateException("Fresh request did not recover: " + result);
                }
            }
            if (program.getModificationNumber() != modification) {
                throw new IllegalStateException("Inference changed the program");
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
