package ghidracli;

import com.google.gson.JsonArray;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

import static ghidracli.JsonProtocol.errorResult;
import static ghidracli.JsonProtocol.getArgString;

/** Classifies the existing listing at an address without reading data values. */
final class MemoryInfoCommands {
    private final ProgramSession session;
    private final AddressResolver addressResolver;

    MemoryInfoCommands(ProgramSession session, AddressResolver addressResolver) {
        this.session = session;
        this.addressResolver = addressResolver;
    }

    JsonObject handleInfo(JsonObject args) throws Exception {
        if (session.program() == null) return errorResult("No program loaded");
        String target = getArgString(args, "address");
        if (target == null || target.isBlank()) return errorResult("Address required");

        session.monitor().checkCancelled();
        Address address = addressResolver.resolveAddress(target);
        if (address == null) return errorResult("Invalid address: " + target);

        var program = session.program();
        var listing = program.getListing();
        MemoryBlock block = program.getMemory().getBlock(address);
        Instruction instruction = listing.getInstructionContaining(address);
        Data data = listing.getDefinedDataContaining(address);
        Function function = program.getFunctionManager().getFunctionContaining(address);

        JsonObject result = new JsonObject();
        result.addProperty("address", AddressCodec.format(address));
        result.addProperty("kind", block == null ? "unmapped"
            : instruction != null ? "instruction" : data != null ? "data" : "undefined");

        JsonObject instructionInfo = null;
        if (instruction != null) {
            instructionInfo = boundaries(instruction, address);
            instructionInfo.addProperty("mnemonic", instruction.getMnemonicString());
        }
        result.add("instruction", instructionInfo == null ? JsonNull.INSTANCE : instructionInfo);

        JsonObject dataInfo = null;
        if (data != null) {
            dataInfo = boundaries(data, address);
            dataInfo.addProperty("type", data.getDataType().getDisplayName());
            dataInfo.addProperty("type_path", data.getDataType().getPathName());
        }
        result.add("data", dataInfo == null ? JsonNull.INSTANCE : dataInfo);

        JsonObject functionInfo = null;
        if (function != null) {
            functionInfo = new JsonObject();
            functionInfo.addProperty("name", function.getName());
            functionInfo.addProperty("address", AddressCodec.format(function.getEntryPoint()));
        }
        result.add("function", functionInfo == null ? JsonNull.INSTANCE : functionInfo);

        JsonObject memoryInfo = null;
        if (block != null) {
            memoryInfo = MemoryBlockInfo.describe(block);
        }
        result.add("memory", memoryInfo == null ? JsonNull.INSTANCE : memoryInfo);
        result.add("file_mapping", MemorySources.describe(session, address));
        session.monitor().checkCancelled();
        return result;
    }

    private static JsonObject boundaries(CodeUnit unit, Address address) {
        JsonObject result = new JsonObject();
        result.addProperty("address", AddressCodec.format(unit.getMinAddress()));
        result.addProperty("end", AddressCodec.format(unit.getMaxAddress()));
        result.addProperty("size", unit.getLength());
        result.addProperty("offset", address.subtract(unit.getMinAddress()));
        return result;
    }

    JsonObject handleMemoryMap() {
        if (session.program() == null) {
            return errorResult("No program loaded");
        }

        JsonArray blocks = new JsonArray();
        Memory memory = session.program().getMemory();

        for (MemoryBlock block : memory.getBlocks()) {
            JsonObject blockData = MemoryBlockInfo.describe(block);
            blockData.add("is_initialized", blockData.remove("initialized"));
            blocks.add(blockData);
        }

        JsonObject result = new JsonObject();
        result.add("blocks", blocks);
        result.addProperty("count", blocks.size());
        return result;
    }
}
