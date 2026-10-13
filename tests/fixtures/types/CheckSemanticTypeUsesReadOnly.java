import com.google.gson.JsonObject;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileProcess;
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.concurrent.TimeUnit;

/** Real native faults on a read-only saved database, without races or production hooks. */
public class CheckSemanticTypeUsesReadOnly extends GhidraScript {
    private Object session;
    private TaskMonitorAdapter requestMonitor = new TaskMonitorAdapter(true);
    private String fault;

    private static void check(boolean condition, String message) {
        if (!condition) throw new IllegalStateException(message);
    }

    private static Object field(Object object, String name) throws Exception {
        var field = object.getClass().getDeclaredField(name);
        field.setAccessible(true);
        return field.get(object);
    }

    private DecompInterface engine() throws Exception {
        return (DecompInterface) field(field(session, "decompiler"), "decompiler");
    }

    private static Object invoke(Method method, Object target, Object... arguments) throws Throwable {
        try { return method.invoke(target, arguments); }
        catch (InvocationTargetException failure) { throw failure.getCause(); }
    }

    public void run() throws Exception {
        Class<?> caller = StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
            .walk(frames -> frames.map(StackWalker.StackFrame::getDeclaringClass)
                .filter(type -> type.getSimpleName().equals("ScriptCommands")
                    && type.getPackageName().equals("ghidracli.script"))
                .findFirst().orElseThrow());
        ClassLoader loader = caller.getClassLoader();
        String prefix = caller.getPackageName().substring(0, caller.getPackageName().lastIndexOf('.') + 1);
        Class<?> sessionClass = loader.loadClass(prefix + "session.ProgramSession");
        Class<?> commandsClass = loader.loadClass(prefix + "analysis.SemanticTypeUsesCommands");
        Object reader = new Object();
        Program real = (Program) currentProgram.getDomainFile()
            .getReadOnlyDomainObject(reader, DomainFile.DEFAULT_VERSION, TaskMonitor.DUMMY);
        try {
            Listing listing = (Listing) Proxy.newProxyInstance(Listing.class.getClassLoader(),
                new Class<?>[] {Listing.class}, (proxy, method, args) -> {
                    if (method.getName().equals("getInstructionAt") && fault != null
                            && StackWalker.getInstance().walk(frames -> frames.anyMatch(frame ->
                                frame.getClassName().equals("ghidra.app.decompiler.DecompileCallback")))) {
                        String mode = fault;
                        fault = null;
                        if (mode.equals("cancel")) requestMonitor.cancel();
                        else {
                            DecompileProcess process = (DecompileProcess) field(engine(), "decompProcess");
                            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
                            while (process.getDisposeState() == DecompileProcess.DisposeState.NOT_DISPOSED
                                    && System.nanoTime() < deadline) Thread.sleep(10);
                            check(process.getDisposeState() == DecompileProcess.DisposeState.DISPOSED_ON_TIMEOUT,
                                "Native semantic search timeout did not fire");
                        }
                    }
                    return invoke(method, real.getListing(), args);
                });
            Program[] selected = {(Program) Proxy.newProxyInstance(Program.class.getClassLoader(),
                new Class<?>[] {Program.class}, (proxy, method, args) -> {
                    if (method.getName().equals("getListing")) return listing;
                    return invoke(method, real, args);
                })};
            Class<?> accessClass = loader.loadClass(prefix + "session.ScriptAccess");
            Object access = Proxy.newProxyInstance(loader, new Class<?>[] {accessClass},
                (proxy, method, args) -> {
                    switch (method.getName()) {
                        case "program": return selected[0];
                        case "setProgram": selected[0] = (Program) args[0]; return null;
                        case "monitor": return requestMonitor;
                        default: throw new UnsupportedOperationException(method.getName());
                    }
                });
            session = sessionClass.getConstructor(accessClass).newInstance(access);
            Class<?> typeResolverClass = loader.loadClass(prefix + "types.TypeResolver");
            Object typeResolver = typeResolverClass.getConstructor(sessionClass).newInstance(session);
            Class<?> addressResolverClass = loader.loadClass(prefix + "query.AddressResolver");
            Object addressResolver = addressResolverClass.getConstructor(sessionClass).newInstance(session);
            Class<?> queriesClass = loader.loadClass(prefix + "function.FunctionQueries");
            Object queries = queriesClass.getConstructor(sessionClass, addressResolverClass)
                .newInstance(session, addressResolver);
            Object commands = commandsClass.getConstructor(sessionClass, typeResolverClass, queriesClass)
                .newInstance(session, typeResolver, queries);
            long modification = real.getModificationNumber();
            for (String name : new String[] {"handleVariables", "handleFields"}) {
                Method method = commandsClass.getMethod(name, JsonObject.class);
                JsonObject args = new JsonObject();
                args.addProperty("type_name", "/Semantic/Packet");
                args.addProperty("function", "read_count");
                args.addProperty("timeout_secs", 1);
                if (name.equals("handleFields")) args.addProperty("field", "count");
                else args.addProperty("kind", "variable");
                requestMonitor = new TaskMonitorAdapter(true);
                JsonObject baseline = (JsonObject) method.invoke(commands, args);
                check(baseline.getAsJsonArray("uses").size() == 1, "Missing native baseline: " + baseline);
                check(baseline.getAsJsonObject("scan").get("complete").getAsBoolean(), baseline.toString());
                for (String mode : new String[] {"cancel", "timeout"}) {
                    requestMonitor = new TaskMonitorAdapter(true);
                    TaskMonitorAdapter oldMonitor = requestMonitor;
                    fault = mode;
                    try {
                        JsonObject result = (JsonObject) method.invoke(commands, args);
                        check(mode.equals("timeout"), "Cancelled search returned partial success: " + result);
                        check(result.getAsJsonArray("uses").isEmpty(), "Timed-out function leaked uses: " + result);
                        JsonObject scan = result.getAsJsonObject("scan");
                        check(!scan.get("complete").getAsBoolean(), "Timeout masqueraded as exhaustive empty scan");
                        check(scan.getAsJsonArray("failed_functions").get(0).getAsJsonObject()
                            .get("reason").getAsString().equals("timeout"), result.toString());
                    } catch (InvocationTargetException failure) {
                        if (!mode.equals("cancel") || !(failure.getCause() instanceof CancelledException)) throw failure;
                    }
                    check(fault == null, "Native fault callback was not reached");
                    check(engine() == null, "Failed native decompiler survived " + mode);
                    requestMonitor = new TaskMonitorAdapter(true);
                    check(baseline.equals(method.invoke(commands, args)), "Search did not recover after " + mode);
                    oldMonitor.clearCancelled();
                    oldMonitor.cancel();
                    check(baseline.equals(method.invoke(commands, args)), "Old request monitor cancelled a later search");
                }
            }
            check(real.getModificationNumber() == modification && !real.isChanged(),
                "Semantic queries changed the read-only saved program");
        } catch (InvocationTargetException failure) {
            throw new IllegalStateException("Semantic probe failed: " + failure.getCause(), failure.getCause());
        } finally {
            try {
                if (session != null) sessionClass.getMethod("closeProgram").invoke(session);
            } finally {
                real.release(reader);
            }
        }
    }
}
