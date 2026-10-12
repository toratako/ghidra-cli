import com.google.gson.JsonObject;
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

public class CheckBinaryExportBounds extends GhidraScript {
    private void require(boolean condition, String message) {
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
        Path output = Path.of(getScriptArgs()[0]);
        byte[] previous = {11, 22, 33};
        Object reader = new Object();
        Program real = (Program) currentProgram.getDomainFile()
            .getReadOnlyDomainObject(reader, DomainFile.DEFAULT_VERSION, TaskMonitor.DUMMY);
        Class<?> sessionClass = loader.loadClass(prefix + "session.ProgramSession");
        Object session = null;
        try {
            var space = real.getAddressFactory().getDefaultAddressSpace();
            // A 4 GiB contiguous range narrows to zero in native BinaryExporter.
            // The proxy avoids allocating a multi-gigabyte fixture or artifact.
            var initialized = new AddressSet(space.getAddress(0x1000),
                space.getAddress(0x1_0000_0fffL));
            MemoryBlock block = (MemoryBlock) Proxy.newProxyInstance(MemoryBlock.class.getClassLoader(),
                new Class<?>[] {MemoryBlock.class}, (proxy, method, args) -> {
                    switch (method.getName()) {
                        case "getStart": return initialized.getMinAddress();
                        case "getEnd": return initialized.getMaxAddress();
                        case "getSize": return 0x1_0000_0000L;
                        case "isMapped": return false;
                        case "isInitialized": return true;
                        default: throw new UnsupportedOperationException(method.getName());
                    }
                });
            TaskMonitorAdapter requestMonitor = new TaskMonitorAdapter(true);
            int[] reads = {0};
            String[] mode = {"cancel"};
            Memory memory = (Memory) Proxy.newProxyInstance(Memory.class.getClassLoader(),
                new Class<?>[] {Memory.class}, (proxy, method, args) -> {
                    switch (method.getName()) {
                        case "getAllInitializedAddressSet": return initialized;
                        case "getBlocks": return new MemoryBlock[] {block};
                        case "getBlock": return initialized.contains((ghidra.program.model.address.Address) args[0])
                            ? block : null;
                        case "getAddressRanges":
                            return args == null || args.length == 0
                                ? initialized.getAddressRanges()
                                : initialized.getAddressRanges((Boolean) args[0]);
                        case "getBytes":
                            reads[0]++;
                            byte[] buffer = (byte[]) args[1];
                            int offset = args.length == 2 ? 0 : (Integer) args[2];
                            int length = args.length == 2 ? buffer.length : (Integer) args[3];
                            require(length > 0 && length <= 64 * 1024,
                                "Unbounded or narrowed binary read: " + length);
                            if (mode[0].equals("error") && reads[0] == 2) {
                                throw new MemoryAccessException("injected binary read failure");
                            }
                            Arrays.fill(buffer, offset, offset + length, (byte) 0x5a);
                            if (mode[0].equals("cancel")) requestMonitor.cancel();
                            return length;
                        default:
                            try { return method.invoke(real.getMemory(), args); }
                            catch (InvocationTargetException failure) { throw failure.getCause(); }
                    }
                });
            Program program = (Program) Proxy.newProxyInstance(Program.class.getClassLoader(),
                new Class<?>[] {Program.class}, (proxy, method, args) -> {
                    if (method.getName().equals("getMemory")) return memory;
                    try { return method.invoke(real, args); }
                    catch (InvocationTargetException failure) { throw failure.getCause(); }
                });
            Program[] selected = {program};
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
            var constructor = sessionClass.getDeclaredConstructor(accessClass);
            constructor.setAccessible(true);
            session = constructor.newInstance(access);
            var commandsClass = loader.loadClass(prefix + "program.ProgramExportCommands");
            var commandsConstructor = commandsClass.getDeclaredConstructor(sessionClass);
            commandsConstructor.setAccessible(true);
            Object commands = commandsConstructor.newInstance(session);
            var export = commandsClass.getDeclaredMethod("handleProgramExport", JsonObject.class);
            export.setAccessible(true);
            JsonObject args = new JsonObject();
            args.addProperty("format", "binary");
            args.addProperty("output", output.toString());
            for (String fault : new String[] {"cancel", "error"}) {
                mode[0] = fault;
                for (boolean existing : new boolean[] {true, false}) {
                    if (existing) Files.write(output, previous);
                    else Files.deleteIfExists(output);
                    reads[0] = 0;
                    requestMonitor.clearCancelled();
                    JsonObject result = (JsonObject) export.invoke(commands, args);
                    require(result.has("error"), "Incomplete binary export succeeded: " + result);
                    if (fault.equals("cancel")) {
                        require(requestMonitor.isCancelled() && reads[0] == 1,
                            "Large binary export did not reach bounded cancellable reads: " + result);
                    } else {
                        require(reads[0] == 2 && result.get("error").getAsString()
                            .contains("injected binary read failure"), result.toString());
                    }
                    require(existing ? Arrays.equals(Files.readAllBytes(output), previous)
                        : !Files.exists(output), "Failed binary export published partial bytes");
                }
            }
            requestMonitor.clearCancelled();
            try (var entries = Files.list(output.getParent())) {
                require(entries.noneMatch(path -> path.getFileName().toString()
                    .startsWith(".ghidra-cli-export-")), "Failed binary export leaked staging");
            }
        } finally {
            try {
                if (session != null) {
                    var close = sessionClass.getDeclaredMethod("closeProgram");
                    close.setAccessible(true);
                    close.invoke(session);
                }
            } finally { real.release(reader); }
        }
    }
}
