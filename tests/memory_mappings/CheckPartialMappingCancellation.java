import com.google.gson.JsonObject;
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidra.util.exception.CancelledException;
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
        String[] cancelledRead = {"getByte"};
        Object session = null;
        try {
            Memory memory = (Memory) Proxy.newProxyInstance(Memory.class.getClassLoader(),
                new Class<?>[]{Memory.class}, (proxy, method, args) -> {
                    Object result;
                    try { result = method.invoke(real.getMemory(), args); }
                    catch (InvocationTargetException failure) { throw failure.getCause(); }
                    if (method.getName().equals(cancelledRead[0]) && ++reads[0] == 2 && cancel[0]) {
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
            cancelledRead[0] = "getBlock";
            reads[0] = 0;
            cancel[0] = true;
            args.addProperty("address", "0x1800");
            args.addProperty("size", 16);
            JsonObject mapped = (JsonObject) read.invoke(commands, args);
            if (!requestMonitor.isCancelled() || reads[0] != 2 || !mapped.has("error"))
                throw new IllegalStateException("Cancelled mapping traversal returned partial success: " + mapped);
            requestMonitor.clearCancelled();
            cancel[0] = false;
            JsonObject mappedRecovery = (JsonObject) read.invoke(commands, args);
            if (mappedRecovery.has("error") || mappedRecovery.get("size").getAsInt() != 16)
                throw new IllegalStateException("Mapping traversal did not recover: " + mappedRecovery);

            Class<?> stringsClass = loader.loadClass(prefix + "listing.StringQueries");
            Object strings = stringsClass.getConstructor(sessionClass).newInstance(session);
            Class<?> searchClass = loader.loadClass(prefix + "listing.SearchCommands");
            Object searches = searchClass.getConstructor(sessionClass, resolverClass, stringsClass)
                .newInstance(session, resolver, strings);
            JsonObject searchArgs = new JsonObject();
            searchArgs.addProperty("hex", "5a5a");
            searchArgs.addProperty("text", "ZZ");
            searchArgs.addProperty("encoding", "ascii");
            searchArgs.addProperty("pattern", "ZZ");
            String[] searchMethods = {"handleFindBytes", "handleFindText", "handleFindBytesRegex"};
            for (String searchMethod : searchMethods) {
                var search = searchClass.getMethod(searchMethod, JsonObject.class);
                cancelledRead[0] = "getBytes";
                reads[0] = 0;
                cancel[0] = true;
                JsonObject stopped = (JsonObject) search.invoke(searches, searchArgs);
                if (!requestMonitor.isCancelled() || !stopped.has("error"))
                    throw new IllegalStateException("Cancelled search returned partial success: " + stopped);
                requestMonitor.clearCancelled();
                cancel[0] = false;
                JsonObject resumed = (JsonObject) search.invoke(searches, searchArgs);
                int expected = searchMethod.equals("handleFindBytesRegex") ? 24 : 45;
                if (resumed.has("error") || resumed.get("count").getAsInt() != expected)
                    throw new IllegalStateException("Mapped search did not recover: " + resumed);
            }
            Class<?> tableClass = loader.loadClass(prefix + "listing.AddressTableSearch");
            Object tables = tableClass.getConstructor(sessionClass, resolverClass).newInstance(session, resolver);
            var find = tableClass.getMethod("handleFindAddressTables", JsonObject.class);
            JsonObject tableArgs = new JsonObject();
            tableArgs.addProperty("start", "0x1800");
            tableArgs.addProperty("end", "0x1800");
            cancelledRead[0] = "getByte";
            reads[0] = 0;
            cancel[0] = true;
            try {
                find.invoke(tables, tableArgs);
                throw new IllegalStateException("Cancelled mapped scalar returned table success");
            } catch (InvocationTargetException failure) {
                if (!(failure.getCause() instanceof CancelledException))
                    throw new IllegalStateException("Mapped scalar changed cancellation type: "
                        + failure.getCause().getClass().getSimpleName());
            }
            if (!requestMonitor.isCancelled() || reads[0] != 2)
                throw new IllegalStateException("Did not cancel inside mapped scalar read");
            requestMonitor.clearCancelled();
            cancel[0] = false;
            JsonObject tablesRecovered = (JsonObject) find.invoke(tables, tableArgs);
            if (tablesRecovered.get("count").getAsInt() != 0)
                throw new IllegalStateException("Mapped scalar did not recover: " + tablesRecovered);
        } finally {
            requestMonitor.clearCancelled();
            try {
                if (session != null) session.getClass().getMethod("closeProgram").invoke(session);
            } finally { real.release(reader); }
        }
    }
}
