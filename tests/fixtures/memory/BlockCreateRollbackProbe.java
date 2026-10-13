
import com.google.gson.JsonObject;
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;

public class BlockCreateRollbackProbe extends GhidraScript {
    private Program selected;
    private boolean nativeCreationObserved;
    private String editFault;
    private boolean read, write, execute, isVolatile;
    private final TaskMonitorAdapter requestMonitor = new TaskMonitorAdapter(true);
    private void require(boolean condition, String message) {
        if (!condition) throw new IllegalStateException(message);
    }
    private void checkAbsent(Program program) throws Exception {
        require(program.getAddressFactory().getAddressSpace("late_bank") == null,
            "Cancelled creation retained its new overlay space");
        require(program.getMemory().getBlocks().length == 1,
            "Cancelled creation retained a block");
        var seed = program.getMemory().getBlock("seed");
        require(seed != null && seed.isRead() == read && seed.isWrite() == write
            && seed.isExecute() == execute && seed.isVolatile() == isVolatile
            && seed.getSize() == 16
            && program.getMemory().getByte(seed.getStart()) == (byte) 0x17,
            "Cancellation changed existing memory");
    }
    public void run() throws Exception {
        var folder = state.getProject().getProjectData().getRootFolder().createFolder(getScriptArgs()[0]);
        DomainFile file = currentProgram.getDomainFile().copyTo(folder, monitor);
        Object owner = new Object();
        Program real = (Program) file.getDomainObject(owner, true, false, monitor);
        var original = real.getMemory().getBlock("seed");
        read = original.isRead(); write = original.isWrite();
        execute = original.isExecute(); isVolatile = original.isVolatile();
        Object session = null;
        try {
            Class<?> caller = StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
                .walk(frames -> frames.map(StackWalker.StackFrame::getDeclaringClass)
                    .filter(type -> type.getSimpleName().equals("ScriptCommands")
                        && type.getPackageName().equals("ghidracli.script")).findFirst().orElseThrow());
            var loader = caller.getClassLoader();
            String prefix = caller.getPackageName()
                .substring(0, caller.getPackageName().lastIndexOf('.') + 1);

            Memory memory = (Memory) Proxy.newProxyInstance(Memory.class.getClassLoader(),
                new Class<?>[]{Memory.class}, (proxy, method, args) -> {
                    Object result;
                    try { result = method.invoke(real.getMemory(), args); }
                    catch (InvocationTargetException error) { throw error.getCause(); }
                    if (method.getName().equals("createInitializedBlock")) {
                        var space = real.getAddressFactory().getAddressSpace("late_bank");
                        require(space != null && space.isOverlaySpace(),
                            "Cancellation preceded native overlay creation");
                        var address = space.getAddressInThisSpaceOnly(0x2000);
                        var block = real.getMemory().getBlock(address);
                        require(block != null && block.getSize() == 16
                            && block.getStart().equals(address)
                            && real.getMemory().getByte(address) == (byte) 0x5a,
                            "Cancellation preceded native initialized block creation");
                        nativeCreationObserved = true;
                        requestMonitor.cancel();
                    }
                    if (editFault != null && method.getName().equals("getBlock")
                            && result instanceof ghidra.program.model.mem.MemoryBlock block) {
                        var blockClass = ghidra.program.model.mem.MemoryBlock.class;
                        return Proxy.newProxyInstance(blockClass.getClassLoader(),
                            new Class<?>[]{blockClass}, (blockProxy, blockMethod, blockArgs) -> {
                                Object value;
                                try { value = blockMethod.invoke(block, blockArgs); }
                                catch (InvocationTargetException error) { throw error.getCause(); }
                                if (blockMethod.getName().equals("setVolatile")) {
                                    require(block.getName().equals(".edited") && block.isExecute()
                                        && !block.isRead() && !block.isWrite()
                                        && block.isVolatile() != isVolatile,
                                        "Fault preceded compound native edits");
                                    String mode = editFault;
                                    editFault = null;
                                    if (mode.equals("cancel")) requestMonitor.cancel();
                                    else throw new IllegalStateException("injected error after compound edits");
                                }
                                return value;
                            });
                    }
                    return result;
                });
            selected = (Program) Proxy.newProxyInstance(Program.class.getClassLoader(),
                new Class<?>[]{Program.class}, (proxy, method, args) -> {
                    if (method.getName().equals("getMemory")) return memory;
                    try { return method.invoke(real, args); }
                    catch (InvocationTargetException error) { throw error.getCause(); }
                });
            var accessClass = loader.loadClass(prefix + "session.ScriptAccess");
            Object access = Proxy.newProxyInstance(loader, new Class<?>[]{accessClass}, (proxy, method, args) -> {
                switch (method.getName()) {
                    case "program": return selected;
                    case "setProgram": selected = (Program) args[0]; return null;
                    case "state": return state;
                    case "monitor": return requestMonitor;
                    case "logError": printerr((String) args[0]); return null;
                    default: throw new UnsupportedOperationException(method.getName());
                }
            });
            var sessionClass = loader.loadClass(prefix + "session.ProgramSession");
            var sessionConstructor = sessionClass.getDeclaredConstructor(accessClass);
            sessionConstructor.setAccessible(true);
            session = sessionConstructor.newInstance(access);
            var dispatcherClass = loader.loadClass(prefix + "runtime.CommandDispatcher");
            var dispatcherConstructor = dispatcherClass.getDeclaredConstructor(sessionClass);
            dispatcherConstructor.setAccessible(true);
            Object dispatcher = dispatcherConstructor.newInstance(session);
            var execute = dispatcherClass.getDeclaredMethod("execute", String.class, JsonObject.class);
            execute.setAccessible(true);
            var args = new JsonObject();
            args.addProperty("name", ".late_block");
            args.addProperty("start", "ram:0x2000");
            args.addProperty("size", 16);
            args.addProperty("fill", 0x5a);
            args.addProperty("permissions", "rw");
            args.addProperty("overlay", "late_bank");
            var response = (JsonObject) execute.invoke(dispatcher, "memory_block_create", args);
            require(nativeCreationObserved, "Test did not reach native overlay/block creation");
            require(response.get("status").getAsString().equals("error"), response.toString());
            var detail = response.getAsJsonObject("detail");
            require(detail.get("cancelled").getAsBoolean(), response.toString());
            require(detail.get("rolled_back").getAsBoolean(), response.toString());
            require(!detail.has("partial_changes_saved"), response.toString());
            requestMonitor.clearCancelled();
            checkAbsent(real);
            for (String mode : new String[]{"error", "cancel"}) {
                editFault = mode;
                var edit = new JsonObject();
                edit.addProperty("block_start", "0x100");
                edit.addProperty("name", ".edited");
                edit.addProperty("permissions", "x");
                edit.addProperty("volatile", !isVolatile);
                var failed = (JsonObject) execute.invoke(dispatcher, "memory_block_set", edit);
                require(editFault == null, "Test did not reach compound native edits");
                require(failed.get("status").getAsString().equals("error"), failed.toString());
                var failure = failed.getAsJsonObject("detail");
                require(failure.get("rolled_back").getAsBoolean(), failed.toString());
                if (mode.equals("cancel")) require(failure.get("cancelled").getAsBoolean(), failed.toString());
                requestMonitor.clearCancelled();
                checkAbsent(real);
            }
            Object reader = new Object();
            Program saved = (Program) file.getReadOnlyDomainObject(reader,
                DomainFile.DEFAULT_VERSION, TaskMonitor.DUMMY);
            try { checkAbsent(saved); }
            finally { saved.release(reader); }
        } finally {
            requestMonitor.clearCancelled();
            try {
                if (session != null) {
                    var close = session.getClass().getDeclaredMethod("closeProgram");
                    close.setAccessible(true);
                    close.invoke(session);
                }
            } finally { real.release(owner); }
        }
    }
}
