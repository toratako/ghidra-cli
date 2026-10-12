import com.google.gson.JsonObject;
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.EquateTable;
import ghidra.util.task.TaskMonitor;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;

public class CheckNullMessageFailure extends GhidraScript {
    private Program selected;
    private TaskMonitor requestMonitor;
    private boolean edited;

    private static void check(boolean condition, String message) {
        if (!condition) throw new IllegalStateException(message);
    }

    private static Method method(Class<?> type, String name, Class<?>... arguments) throws Exception {
        Method result = type.getDeclaredMethod(name, arguments);
        result.setAccessible(true);
        return result;
    }

    private static Object invoke(Method method, Object target, Object... args) throws Throwable {
        try { return method.invoke(target, args); }
        catch (InvocationTargetException failure) { throw failure.getCause(); }
    }

    private static JsonObject response(Object reply) throws Exception {
        Field field = reply.getClass().getDeclaredField("completion");
        field.setAccessible(true);
        Object supplier = ((CompletableFuture<?>) field.get(reply)).get();
        return (JsonObject) ((Supplier<?>) supplier).get();
    }

    public void run() throws Exception {
        Class<?> caller = StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
            .walk(frames -> frames.map(StackWalker.StackFrame::getDeclaringClass)
                .filter(type -> type.getSimpleName().equals("ScriptCommands")
                    && type.getPackageName().equals(String.join(".", "ghidracli", "script")))
                .findFirst().orElseThrow());
        ClassLoader loader = caller.getClassLoader();
        String prefix = caller.getPackageName().substring(0, caller.getPackageName().lastIndexOf('.') + 1);
        var folder = state.getProject().getProjectData().getRootFolder()
            .createFolder("null-message-" + UUID.randomUUID());
        DomainFile file = currentProgram.getDomainFile().copyTo(folder, monitor);
        Object owner = new Object();
        Program real = (Program) file.getDomainObject(owner, true, false, monitor);
        Object session = null;
        try {
            String name = "must-roll-back";
            EquateTable equates = (EquateTable) Proxy.newProxyInstance(EquateTable.class.getClassLoader(),
                new Class<?>[] { EquateTable.class }, (proxy, operation, inputs) -> {
                    Object result = invoke(operation, real.getEquateTable(), inputs);
                    if (operation.getName().equals("createEquate")) {
                        edited = true;
                        throw new IllegalStateException();
                    }
                    return result;
                });
            selected = (Program) Proxy.newProxyInstance(Program.class.getClassLoader(),
                new Class<?>[] { Program.class }, (proxy, operation, inputs) -> {
                    if (operation.getName().equals("getEquateTable")) return equates;
                    return invoke(operation, real, inputs);
                });
            requestMonitor = monitor;
            Class<?> accessType = loader.loadClass(prefix + "session.ScriptAccess");
            Object access = Proxy.newProxyInstance(loader, new Class<?>[] { accessType },
                (proxy, operation, inputs) -> {
                    switch (operation.getName()) {
                        case "program": return selected;
                        case "setProgram": selected = (Program) inputs[0]; return null;
                        case "monitor": return requestMonitor;
                        case "setMonitor": requestMonitor = (TaskMonitor) inputs[0]; return null;
                        case "state": return state;
                        default: throw new UnsupportedOperationException(operation.getName());
                    }
                });
            Class<?> sessionType = loader.loadClass(prefix + "session.ProgramSession");
            session = sessionType.getConstructor(accessType).newInstance(access);
            Class<?> commandsType = loader.loadClass(prefix + "runtime.CommandDispatcher");
            Constructor<?> commandsConstructor = commandsType.getDeclaredConstructor(sessionType);
            commandsConstructor.setAccessible(true);
            Object commands = commandsConstructor.newInstance(session);
            Class<?> schedulerType = loader.loadClass(prefix + "runtime.JobScheduler");
            Constructor<?> schedulerConstructor = schedulerType.getDeclaredConstructor(sessionType, commandsType);
            schedulerConstructor.setAccessible(true);
            Object scheduler = schedulerConstructor.newInstance(session, commands);
            method(schedulerType, "start").invoke(scheduler);
            Method request = method(schedulerType, "handleRequest", String.class);
            String id = UUID.randomUUID().toString();
            JsonObject args = new JsonObject();
            args.addProperty("name", name);
            args.addProperty("value", "123");
            JsonObject mutation = new JsonObject();
            mutation.addProperty("command", "equate_create");
            mutation.addProperty("job_id", id);
            mutation.add("args", args);
            Object pending = request.invoke(scheduler, mutation.toString());
            method(schedulerType, "beginShutdown").invoke(scheduler);
            method(schedulerType, "runProgramJobs").invoke(scheduler);
            JsonObject result = response(pending);
            check(edited, "Failure injection did not follow a native edit");
            check("error".equals(result.get("status").getAsString()), result.toString());
            check("java.lang.IllegalStateException".equals(result.get("message").getAsString()), result.toString());
            check(result.getAsJsonObject("detail").get("rolled_back").getAsBoolean(), result.toString());
            check(file.getPathname().equals(result.getAsJsonObject("detail").get("program").getAsString()), result.toString());
            check(real.getEquateTable().getEquate(name) == null, "The failed mutation survived rollback");
            Object reader = new Object();
            Program saved = (Program) file.getReadOnlyDomainObject(reader, DomainFile.DEFAULT_VERSION, TaskMonitor.DUMMY);
            try {
                check(saved.getEquateTable().getEquate(name) == null, "The failed mutation reached the saved database");
            } finally {
                saved.release(reader);
            }
            JsonObject recovery = new JsonObject();
            recovery.addProperty("command", "job_result");
            JsonObject target = new JsonObject();
            target.addProperty("job_id", id);
            recovery.add("args", target);
            JsonObject retained = response(request.invoke(scheduler, recovery.toString())).getAsJsonObject("data");
            check("failed".equals(retained.get("state").getAsString()), retained.toString());
            check(result.equals(retained.getAsJsonObject("response")), "Retained error lost its original diagnostics");
            println("null-message native failure preserved rollback diagnostics");
        } finally {
            if (session != null) method(session.getClass(), "closeProgram").invoke(session);
            real.release(owner);
            file.delete();
            folder.delete();
        }
    }
}
