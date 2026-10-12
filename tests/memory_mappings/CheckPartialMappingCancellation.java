import com.google.gson.JsonObject;
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;

/** Cancel while recovering a mapped block's readable prefix after its bulk read failed. */
public class CheckPartialMappingCancellation extends GhidraScript {
    public void run() throws Exception {
        Class<?> caller = StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
            .walk(frames -> frames.map(StackWalker.StackFrame::getDeclaringClass)
                .filter(type -> type.getSimpleName().equals("ScriptCommands")
                    && type.getPackageName().equals("ghidracli.script")).findFirst().orElseThrow());
        ClassLoader loader = caller.getClassLoader();
        String prefix = caller.getPackageName()
            .substring(0, caller.getPackageName().lastIndexOf('.') + 1);
        Object reader = new Object();
        Program real = (Program) currentProgram.getDomainFile()
            .getReadOnlyDomainObject(reader, DomainFile.DEFAULT_VERSION, TaskMonitor.DUMMY);
        TaskMonitorAdapter requestMonitor = new TaskMonitorAdapter(true);
        int[] reads = {0};
        boolean[] cancel = {true};
        Object session = null;
        try {
            Memory memory = (Memory) Proxy.newProxyInstance(Memory.class.getClassLoader(),
                new Class<?>[]{Memory.class}, (proxy, method, args) -> {
                    Object result;
                    try { result = method.invoke(real.getMemory(), args); }
                    catch (InvocationTargetException failure) { throw failure.getCause(); }
                    if (method.getName().equals("getByte") && ++reads[0] == 2 && cancel[0]) {
                        requestMonitor.cancel();
                    }
                    return result;
                });
            Program[] selected = {(Program) Proxy.newProxyInstance(Program.class.getClassLoader(),
                new Class<?>[]{Program.class}, (proxy, method, args) -> {
                    if (method.getName().equals("getMemory")) return memory;
                    try { return method.invoke(real, args); }
                    catch (InvocationTargetException failure) { throw failure.getCause(); }
                })};
            Class<?> accessClass = loader.loadClass(prefix + "session.ScriptAccess");
            Object access = Proxy.newProxyInstance(loader, new Class<?>[]{accessClass},
                (proxy, method, args) -> {
                    switch (method.getName()) {
                        case "program": return selected[0];
                        case "setProgram": selected[0] = (Program) args[0]; return null;
                        case "monitor": return requestMonitor;
                        default: throw new UnsupportedOperationException(method.getName());
                    }
                });
            Class<?> sessionClass = loader.loadClass(prefix + "session.ProgramSession");
            session = sessionClass.getConstructor(accessClass).newInstance(access);
            Class<?> resolverClass = loader.loadClass(prefix + "query.AddressResolver");
            Object resolver = resolverClass.getConstructor(sessionClass).newInstance(session);
            Class<?> commandsClass = loader.loadClass(prefix + "memory.MemoryCommands");
            Object commands = commandsClass.getConstructor(sessionClass, resolverClass)
                .newInstance(session, resolver);
            var read = commandsClass.getMethod("handleReadMemory", JsonObject.class);
            JsonObject args = new JsonObject();
            args.addProperty("address", "0x3000");
            args.addProperty("size", 256);
            JsonObject failed = (JsonObject) read.invoke(commands, args);
            if (!requestMonitor.isCancelled() || reads[0] != 2 || !failed.has("error")) {
                throw new IllegalStateException("Cancelled prefix read returned partial success: " + failed);
            }
            requestMonitor.clearCancelled();
            cancel[0] = false;
            JsonObject recovered = (JsonObject) read.invoke(commands, args);
            if (recovered.has("error") || recovered.get("size").getAsInt() != 128) {
                throw new IllegalStateException("Fresh monitor failed to recover the readable prefix: " + recovered);
            }
        } finally {
            requestMonitor.clearCancelled();
            try {
                if (session != null) session.getClass().getMethod("closeProgram").invoke(session);
            } finally { real.release(reader); }
        }
    }
}
