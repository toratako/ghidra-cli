package ghidracli.listing;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryAccessException;
import ghidracli.memory.MemoryReads;
import ghidracli.query.AddressCodec;
import ghidracli.query.ListQuery;
import ghidracli.session.ProgramSession;
import java.util.HexFormat;

/** Shared instruction rows for address, range, and whole-function disassembly. */
public final class InstructionListing {
    private final ProgramSession session;

    public InstructionListing(ProgramSession session) {
        this.session = session;
    }

    public JsonObject instructionsIn(AddressSetView range, JsonObject args) throws Exception {
        long limit = ListQuery.pageArgument(args, "limit");
        JsonArray instructions = new JsonArray();
        MemoryReads reads = new MemoryReads(session);
        for (Instruction instruction : session.program().getListing().getInstructions(range, true)) {
            session.monitor().checkCancelled();
            if (!range.contains(instruction.getAddress())) continue;
            instructions.add(instructionToJson(instruction, reads));
            if (limit > 0 && instructions.size() >= limit) break;
        }
        JsonObject result = new JsonObject();
        result.add("instructions", instructions);
        result.addProperty("count", instructions.size());
        return result;
    }

    JsonArray instructionsFrom(Instruction instruction, long limit) throws Exception {
        JsonArray instructions = new JsonArray();
        MemoryReads reads = new MemoryReads(session);
        while (instruction != null && (limit == 0 || instructions.size() < limit)) {
            session.monitor().checkCancelled();
            instructions.add(instructionToJson(instruction, reads));
            instruction = instruction.getNext();
        }
        return instructions;
    }

    private JsonObject instructionToJson(Instruction instr, MemoryReads reads) throws Exception {
        byte[] bytes = new byte[instr.getLength()];
        if (reads.read(instr.getAddress(), bytes, 0, bytes.length) != bytes.length)
            throw new MemoryAccessException("Couldn't get all bytes for instruction");
        String bytesHex = HexFormat.of().formatHex(bytes);

        JsonArray operands = new JsonArray();
        int numOperands = instr.getNumOperands();
        for (int j = 0; j < numOperands; j++) {
            operands.add(new JsonPrimitive(instr.getDefaultOperandRepresentation(j)));
        }

        JsonObject instrData = new JsonObject();
        instrData.addProperty("address", AddressCodec.format(instr.getAddress()));
        instrData.addProperty("bytes", bytesHex);
        instrData.addProperty("mnemonic", instr.getMnemonicString());
        instrData.add("operands", operands);
        return instrData;
    }
}
