package ghidracli;

import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import static ghidracli.JsonProtocol.errorResult;
import static ghidracli.JsonProtocol.getNonnegativeLongArg;

/** Native block edits within the request transaction owned by ProgramSession. */
final class MemoryBlockCommands {
    private final ProgramSession session;

    MemoryBlockCommands(ProgramSession session) {
        this.session = session;
    }

    JsonObject handleCreate(JsonObject args) throws Exception {
        if (session.program() == null) return errorResult("No program loaded");
        String name = blockName(args);
        Address start = address(args, "start");
        long size = integer(args, "size", 1, Memory.MAX_BLOCK_SIZE);
        Address end = start.addNoWrap(size - 1);
        int permissions = permissions(args);
        boolean isVolatile = booleanArg(args, "volatile", false);
        boolean uninitialized = booleanArg(args, "uninitialized", false);
        boolean hasFill = args.has("fill");
        if (uninitialized == hasFill) {
            throw new IllegalArgumentException("Specify exactly one of uninitialized=true or fill");
        }
        byte fill = hasFill ? (byte) integer(args, "fill", 0, 255) : 0;

        String overlayName = args.has("overlay") ? string(args, "overlay") : null;
        var program = session.program();
        if (overlayName != null) {
            if (!AddressSpace.isValidName(overlayName)) {
                throw new IllegalArgumentException("Invalid overlay address space name: " + overlayName);
            }
            if (program.getAddressFactory().getAddressSpace(overlayName) != null) {
                throw new IllegalArgumentException("Address space already exists: " + overlayName);
            }
            if (start.getAddressSpace().isOverlaySpace()) {
                throw new IllegalArgumentException("A new overlay requires a physical start address");
            }
        } else {
            rejectCollision(start, end, null);
        }

        session.monitor().checkCancelled();
        if (overlayName != null) {
            AddressSpace overlay = program.createOverlaySpace(overlayName, start.getAddressSpace());
            if (overlay == null || !overlayName.equals(overlay.getName())) {
                throw new IllegalStateException("Ghidra did not create the requested overlay address space");
            }
            start = overlay.getAddressInThisSpaceOnly(start.getOffset());
            end = start.addNoWrap(size - 1);
        }
        Memory memory = program.getMemory();
        MemoryBlock created = uninitialized
            ? memory.createUninitializedBlock(name, start, size, false)
            : memory.createInitializedBlock(name, start, size, fill, session.monitor(), false);
        session.monitor().checkCancelled();
        if (created == null) throw new IllegalStateException("Ghidra did not create the memory block");
        created.setPermissions((permissions & MemoryBlock.READ) != 0,
            (permissions & MemoryBlock.WRITE) != 0, (permissions & MemoryBlock.EXECUTE) != 0);
        created.setVolatile(isVolatile);
        session.monitor().checkCancelled();
        MemoryBlock actual = retainedBlock(start, end);
        if (!actual.getName().equals(name) || actual.isInitialized() == uninitialized
                || actual.isVolatile() != isVolatile || permissionFlags(actual) != permissions) {
            throw new IllegalStateException("Ghidra did not retain the requested block attributes");
        }
        return receipt("created", null, MemoryBlockInfo.describe(actual));
    }

    JsonObject handleRename(JsonObject args) throws Exception {
        if (session.program() == null) return errorResult("No program loaded");
        MemoryBlock block = selectedBlock(args);
        String name = blockName(args);
        JsonObject before = MemoryBlockInfo.describe(block);
        if (block.getName().equals(name)) return receipt("unchanged", before, before);
        Address start = block.getStart();
        Address end = block.getEnd();
        session.monitor().checkCancelled();
        block.setName(name);
        session.monitor().checkCancelled();
        MemoryBlock actual = retainedBlock(start, end);
        if (!actual.getName().equals(name)) {
            throw new IllegalStateException("Ghidra did not retain the requested block name");
        }
        return receipt("updated", before, MemoryBlockInfo.describe(actual));
    }

    JsonObject handleSetPermissions(JsonObject args) throws Exception {
        if (session.program() == null) return errorResult("No program loaded");
        MemoryBlock block = selectedBlock(args);
        int permissions = permissions(args);
        JsonObject before = MemoryBlockInfo.describe(block);
        if (permissionFlags(block) == permissions) return receipt("unchanged", before, before);
        session.monitor().checkCancelled();
        block.setPermissions((permissions & MemoryBlock.READ) != 0,
            (permissions & MemoryBlock.WRITE) != 0, (permissions & MemoryBlock.EXECUTE) != 0);
        session.monitor().checkCancelled();
        if (permissionFlags(block) != permissions) {
            throw new IllegalStateException("Ghidra did not retain the requested block permissions");
        }
        return receipt("updated", before, MemoryBlockInfo.describe(block));
    }

    JsonObject handleSetVolatile(JsonObject args) throws Exception {
        if (session.program() == null) return errorResult("No program loaded");
        MemoryBlock block = selectedBlock(args);
        boolean value = booleanArg(args, "value", null);
        JsonObject before = MemoryBlockInfo.describe(block);
        if (block.isVolatile() == value) return receipt("unchanged", before, before);
        session.monitor().checkCancelled();
        block.setVolatile(value);
        session.monitor().checkCancelled();
        if (block.isVolatile() != value) {
            throw new IllegalStateException("Ghidra did not retain the requested volatile attribute");
        }
        return receipt("updated", before, MemoryBlockInfo.describe(block));
    }

    JsonObject handleMove(JsonObject args) throws Exception {
        if (session.program() == null) return errorResult("No program loaded");
        MemoryBlock block = selectedBlock(args);
        Address start = address(args, "start");
        if (!start.getAddressSpace().equals(block.getStart().getAddressSpace())) {
            throw new IllegalArgumentException("Block move requires the same address space");
        }
        if (block.isOverlay() && block.getStart().isNonLoadedMemoryAddress()) {
            throw new IllegalArgumentException("Nonloaded overlay blocks cannot be moved");
        }
        Address end = start.addNoWrap(block.getSize() - 1);
        JsonObject before = MemoryBlockInfo.describe(block);
        if (start.equals(block.getStart())) return receipt("unchanged", before, before);
        rejectCollision(start, end, block);
        AddressSet affected = new AddressSet(block.getStart(), block.getEnd());
        affected.add(start, end);
        rejectMappedSources(affected);

        session.monitor().checkCancelled();
        session.program().getMemory().moveBlock(block, start, session.monitor());
        session.monitor().checkCancelled();
        // Native movement invalidates the memory cache and listing objects.
        MemoryBlock actual = retainedBlock(start, end);
        return receipt("moved", before, MemoryBlockInfo.describe(actual));
    }

    JsonObject handleDelete(JsonObject args) throws Exception {
        if (session.program() == null) return errorResult("No program loaded");
        MemoryBlock block = selectedBlock(args);
        JsonObject before = MemoryBlockInfo.describe(block);
        Address start = block.getStart();
        Address end = block.getEnd();
        AddressSpace space = start.getAddressSpace();
        rejectMappedSources(new AddressSet(start, end));
        session.monitor().checkCancelled();
        session.program().getMemory().removeBlock(block, session.monitor());
        session.monitor().checkCancelled();
        if (session.program().getMemory().intersects(start, end)) {
            throw new IllegalStateException("Ghidra did not remove the memory block");
        }
        JsonObject result = receipt("deleted", before, null);
        result.addProperty("overlay_removed", space.isOverlaySpace()
            && session.program().getAddressFactory().getAddressSpace(space.getName()) == null);
        return result;
    }

    private MemoryBlock selectedBlock(JsonObject args) throws CancelledException {
        Address start = address(args, "block_start");
        session.monitor().checkCancelled();
        MemoryBlock block = session.program().getMemory().getBlock(start);
        if (block == null || !start.equals(block.getStart())) {
            throw new IllegalArgumentException("block_start must identify the exact start of a memory block: "
                + AddressCodec.format(start));
        }
        if (block.isMapped()) {
            throw new IllegalArgumentException("Bit/byte-mapped blocks cannot be edited: "
                + AddressCodec.format(start));
        }
        return block;
    }

    private MemoryBlock retainedBlock(Address start, Address end) {
        MemoryBlock block = session.program().getMemory().getBlock(start);
        if (block == null || !start.equals(block.getStart()) || !end.equals(block.getEnd())) {
            throw new IllegalStateException("Unexpected memory block range after edit: "
                + AddressCodec.format(start));
        }
        return block;
    }

    private void rejectCollision(Address start, Address end, MemoryBlock excluded)
            throws CancelledException {
        AddressSet occupied = new AddressSet(session.program().getMemory());
        if (excluded != null) occupied.delete(excluded.getStart(), excluded.getEnd());
        session.monitor().checkCancelled();
        if (occupied.intersects(start, end)) {
            throw new IllegalArgumentException("Block range overlaps existing memory: "
                + AddressCodec.format(start) + " through " + AddressCodec.format(end));
        }
    }

    private void rejectMappedSources(AddressSet affected) throws CancelledException {
        for (MemoryBlock block : session.program().getMemory().getBlocks()) {
            session.monitor().checkCancelled();
            if (!block.isMapped()) continue;
            for (var source : block.getSourceInfos()) {
                var mapped = source.getMappedRange();
                if (mapped.isPresent()) {
                    AddressRange range = mapped.get();
                    if (affected.intersects(range.getMinAddress(), range.getMaxAddress())) {
                        throw new IllegalArgumentException("Block edit affects the source of mapped block "
                            + block.getName() + " at " + AddressCodec.format(block.getStart()));
                    }
                }
            }
        }
    }

    private Address address(JsonObject args, String key) {
        String value = string(args, key);
        Address address = AddressCodec.parse(session.program().getAddressFactory(), value);
        if (address == null || !address.getAddressSpace().isMemorySpace()) {
            throw new IllegalArgumentException(key + " must be an explicit memory address");
        }
        return address;
    }

    private static String blockName(JsonObject args) {
        String name = string(args, "name");
        if (!Memory.isValidMemoryBlockName(name)) {
            throw new IllegalArgumentException("Invalid memory block name: " + name);
        }
        return name;
    }

    private static String string(JsonObject args, String key) {
        JsonElement value = args == null ? null : args.get(key);
        if (value == null || !value.isJsonPrimitive() || !value.getAsJsonPrimitive().isString()
                || value.getAsString().isBlank()) {
            throw new IllegalArgumentException(key + " must be a nonempty string");
        }
        return value.getAsString();
    }

    private static boolean booleanArg(JsonObject args, String key, Boolean defaultValue) {
        JsonElement value = args == null ? null : args.get(key);
        if (value == null && defaultValue != null) return defaultValue;
        if (value == null || !value.isJsonPrimitive() || !value.getAsJsonPrimitive().isBoolean()) {
            throw new IllegalArgumentException(key + " must be a boolean");
        }
        return value.getAsBoolean();
    }

    private static long integer(JsonObject args, String key, long min, long max) {
        if (args == null || !args.has(key) || args.get(key).isJsonNull()) {
            throw new IllegalArgumentException(key + " is required");
        }
        long value = getNonnegativeLongArg(args, key);
        if (value < min || value > max) {
            throw new IllegalArgumentException(key + " must be an integer from " + min + " to " + max);
        }
        return value;
    }

    private static int permissions(JsonObject args) {
        String value = string(args, "permissions");
        if (value.equals("none")) return 0;
        int flags = 0;
        for (int index = 0; index < value.length(); index++) {
            int flag = switch (value.charAt(index)) {
                case 'r' -> MemoryBlock.READ;
                case 'w' -> MemoryBlock.WRITE;
                case 'x' -> MemoryBlock.EXECUTE;
                default -> 0;
            };
            if (flag == 0 || (flags & flag) != 0) {
                throw new IllegalArgumentException("permissions must be a combination of r, w, x or none");
            }
            flags |= flag;
        }
        return flags;
    }

    private static int permissionFlags(MemoryBlock block) {
        return (block.isRead() ? MemoryBlock.READ : 0)
            | (block.isWrite() ? MemoryBlock.WRITE : 0)
            | (block.isExecute() ? MemoryBlock.EXECUTE : 0);
    }

    private static JsonObject receipt(String status, JsonObject before, JsonObject after) {
        JsonObject result = new JsonObject();
        result.addProperty("status", status);
        result.addProperty("changed", !status.equals("unchanged"));
        result.add("before", before == null ? JsonNull.INSTANCE : before);
        result.add("after", after == null ? JsonNull.INSTANCE : after);
        return result;
    }
}
