package ghidracli;

import com.google.gson.JsonObject;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.OverlayAddressSpace;
import ghidra.program.model.mem.MemoryBlock;

/** Shared block identity and permissions for memory and function queries. */
final class MemoryBlockInfo {
    private MemoryBlockInfo() {}

    static JsonObject summary(MemoryBlock block) {
        String permissions = (block.isRead() ? "r" : "")
            + (block.isWrite() ? "w" : "") + (block.isExecute() ? "x" : "");
        JsonObject result = new JsonObject();
        result.addProperty("name", block.getName());
        result.addProperty("permissions", permissions);
        return result;
    }

    /** Full block description for memory queries and mutation receipts. */
    static JsonObject describe(MemoryBlock block) {
        AddressSpace space = block.getStart().getAddressSpace();
        JsonObject result = summary(block);
        result.addProperty("start", AddressCodec.format(block.getStart()));
        result.addProperty("end", AddressCodec.format(block.getEnd()));
        result.addProperty("size", block.getSize());
        result.addProperty("initialized", block.isInitialized());
        result.addProperty("is_loaded", block.isLoaded());
        result.addProperty("address_space", space.getName());
        result.addProperty("overlay", space.isOverlaySpace());
        result.addProperty("base_space", space instanceof OverlayAddressSpace overlay
            ? overlay.getOverlayedSpace().getName() : null);
        result.addProperty("type", switch (block.getType()) {
            case DEFAULT -> "default";
            case BIT_MAPPED -> "bit_mapped";
            case BYTE_MAPPED -> "byte_mapped";
        });
        result.addProperty("volatile", block.isVolatile());
        return result;
    }
}
