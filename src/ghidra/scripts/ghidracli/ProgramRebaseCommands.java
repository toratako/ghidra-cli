package ghidracli;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.SegmentedAddress;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.exception.CancelledException;
import java.math.BigInteger;
import java.util.ArrayList;
import static ghidracli.JsonProtocol.errorResult;

final class ProgramRebaseCommands {
    private final ProgramSession session;

    ProgramRebaseCommands(ProgramSession session) {
        this.session = session;
    }

    JsonObject handleRebase(JsonObject args) throws Exception {
        Program program = session.program();
        if (program == null) return errorResult("No program loaded");
        JsonElement value = args == null ? null : args.get("base");
        if (value == null || !value.isJsonPrimitive()
                || !value.getAsJsonPrimitive().isString()) {
            throw new IllegalArgumentException("base must be an explicit address string");
        }
        Address base = AddressCodec.parse(program.getAddressFactory(), value.getAsString());
        AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
        if (base == null || !space.equals(base.getAddressSpace())) {
            throw new IllegalArgumentException("base must be an explicit address in the default address space");
        }
        if (base instanceof SegmentedAddress segmented && segmented.getSegmentOffset() != 0) {
            throw new IllegalArgumentException("A segmented image base must have a zero segment offset");
        }

        Address oldBase = program.getImageBase();
        BigInteger delta = byteOffset(base).subtract(byteOffset(oldBase));
        var blocks = new ArrayList<BlockMove>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            session.monitor().checkCancelled();
            Address start = block.getStart();
            Address end = block.getEnd();
            String reason = !space.equals(start.getAddressSpace())
                ? (start.getAddressSpace().isOverlaySpace() ? "overlay" : "other_address_space")
                : delta.signum() == 0 ? "same_base" : null;
            blocks.add(new BlockMove(block.getName(), start, end,
                reason == null ? shifted(start, delta, block.getName()) : start,
                reason == null ? shifted(end, delta, block.getName()) : end, reason));
        }

        // Every block in the default space receives the same non-wrapping translation,
        // so disjoint blocks stay disjoint. Other address spaces cannot collide with it.
        // Native setImageBase uses addWrap for starts; its own fit check is insufficient.
        if (delta.signum() != 0) validateMetadata(program, space, delta);
        session.monitor().checkCancelled();
        if (delta.signum() != 0) program.setImageBase(base, true);
        session.monitor().checkCancelled();
        if (!base.equals(program.getImageBase())) {
            throw new IllegalStateException("Ghidra did not retain the requested image base");
        }

        JsonArray moved = new JsonArray();
        JsonArray unchanged = new JsonArray();
        for (BlockMove block : blocks) {
            session.monitor().checkCancelled();
            MemoryBlock actual = program.getMemory().getBlock(block.newStart());
            if (actual == null || !block.name().equals(actual.getName())
                    || !block.newStart().equals(actual.getStart())
                    || !block.newEnd().equals(actual.getEnd())) {
                throw new IllegalStateException("Unexpected memory range after rebasing block: " + block.name());
            }
            JsonObject row = new JsonObject();
            row.addProperty("name", block.name());
            if (block.reason() == null) {
                row.addProperty("old_start", AddressCodec.format(block.oldStart()));
                row.addProperty("old_end", AddressCodec.format(block.oldEnd()));
                row.addProperty("new_start", AddressCodec.format(actual.getStart()));
                row.addProperty("new_end", AddressCodec.format(actual.getEnd()));
                moved.add(row);
            } else {
                row.addProperty("start", AddressCodec.format(actual.getStart()));
                row.addProperty("end", AddressCodec.format(actual.getEnd()));
                row.addProperty("reason", block.reason());
                unchanged.add(row);
            }
        }

        JsonObject result = new JsonObject();
        result.addProperty("old_base", AddressCodec.format(oldBase));
        result.addProperty("new_base", AddressCodec.format(program.getImageBase()));
        result.addProperty("delta_bytes", delta.toString());
        result.add("moved_blocks", moved);
        result.add("unchanged_blocks", unchanged);
        return result;
    }

    private void validateMetadata(Program program, AddressSpace space, BigInteger delta)
            throws CancelledException {
        BigInteger min = byteOffset(space.getMinAddress());
        BigInteger max = byteOffset(space.getMaxAddress());
        BigInteger first = delta.signum() > 0 ? max.subtract(delta).add(BigInteger.ONE) : min;
        BigInteger last = delta.signum() > 0 ? max : min.subtract(delta).subtract(BigInteger.ONE);
        Address start = space.getAddressInThisSpaceOnly(first.longValue());
        Address end = space.getAddressInThisSpaceOnly(last.longValue());
        AddressSet wrapping = new AddressSet(start, end);

        // Relocatable address-map keys also move when they refer to unmapped memory.
        // Restrict queries to the interval that would wrap, without rejecting unused
        // portions of Ghidra's coarsely allocated address-map key buckets.
        var symbols = program.getSymbolTable().getSymbolIterator(start, true);
        while (symbols.hasNext()) {
            session.monitor().checkCancelled();
            var symbol = symbols.next();
            if (!wrapping.contains(symbol.getAddress())) break;
            // Native rebasing restores pinned labels at their absolute addresses;
            // pinned functions still move their bodies and receive a separate label.
            if (!symbol.isPinned() || symbol.getSymbolType() == SymbolType.FUNCTION) {
                throw metadataWrap("symbol '" + symbol.getName() + "'", symbol.getAddress());
            }
        }
        var references = program.getReferenceManager();
        rejectAddresses(references.getReferenceSourceIterator(wrapping, true), "reference source");
        rejectAddresses(references.getReferenceDestinationIterator(wrapping, true), "reference destination");
        rejectAddresses(program.getListing().getCommentAddressIterator(wrapping, true), "comment");
        var context = program.getProgramContext();
        for (var register : context.getRegistersWithValues()) {
            session.monitor().checkCancelled();
            if (!register.equals(register.getBaseRegister())) continue;
            // This API returns stored values only, excluding language defaults.
            var ranges = context.getRegisterValueAddressRanges(register, start, end);
            if (ranges.hasNext()) {
                throw metadataWrap("register context '" + register.getName() + "'",
                    ranges.next().getMinAddress());
            }
        }
        session.monitor().checkCancelled();
        var bookmarks = program.getBookmarkManager().getBookmarksIterator(start, true);
        if (bookmarks.hasNext()) {
            Address address = bookmarks.next().getAddress();
            if (wrapping.contains(address)) throw metadataWrap("bookmark", address);
        }
        var properties = program.getUsrPropertyManager();
        var names = properties.propertyManagers();
        while (names.hasNext()) {
            session.monitor().checkCancelled();
            String name = names.next();
            rejectAddresses(properties.getPropertyMap(name).getPropertyIterator(wrapping),
                "user property '" + name + "'");
        }
        session.monitor().checkCancelled();
        var relocations = program.getRelocationTable().getRelocations(wrapping);
        if (relocations.hasNext()) throw metadataWrap("relocation", relocations.next().getAddress());
        rejectAddresses(program.getEquateTable().getEquateAddresses(wrapping), "equate reference");
        session.monitor().checkCancelled();
        var functions = program.getFunctionManager().getFunctionsOverlapping(wrapping);
        if (functions.hasNext()) {
            var function = functions.next();
            throw metadataWrap("function body '" + function.getName() + "'",
                function.getBody().intersect(wrapping).getMinAddress());
        }
        // Listing definitions and source-map entries are constrained by native APIs
        // to mapped memory, whose complete ranges have already passed preflight.
    }

    private void rejectAddresses(AddressIterator addresses, String kind) throws CancelledException {
        session.monitor().checkCancelled();
        if (addresses.hasNext()) throw metadataWrap(kind, addresses.next());
    }

    private static IllegalArgumentException metadataWrap(String kind, Address address) {
        return new IllegalArgumentException("Rebase would wrap or exceed the address space for "
            + kind + " at " + AddressCodec.format(address));
    }

    private static Address shifted(Address address, BigInteger delta, String blockName) {
        AddressSpace space = address.getAddressSpace();
        BigInteger offset = byteOffset(address).add(delta);
        if (offset.compareTo(byteOffset(space.getMinAddress())) < 0
                || offset.compareTo(byteOffset(space.getMaxAddress())) > 0) {
            throw new IllegalArgumentException("Rebase would wrap or exceed the address space for block: "
                + blockName + " at " + AddressCodec.format(address));
        }
        return space.getAddressInThisSpaceOnly(offset.longValue());
    }

    private static BigInteger byteOffset(Address address) {
        return address.getAddressSpace().hasSignedOffset()
            ? BigInteger.valueOf(address.getOffset()) : address.getOffsetAsBigInteger();
    }

    private record BlockMove(String name, Address oldStart, Address oldEnd,
            Address newStart, Address newEnd, String reason) {}
}
