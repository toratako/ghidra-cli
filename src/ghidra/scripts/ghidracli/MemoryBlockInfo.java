package ghidracli;

import com.google.gson.JsonObject;
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
}
