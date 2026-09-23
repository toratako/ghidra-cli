package ghidracli.listing;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryAccessException;
import ghidracli.query.AddressCodec;
import ghidracli.query.ListQuery;
import ghidracli.session.ProgramSession;

/** Shared instruction rows for address, range, and whole-function disassembly. */
public final class InstructionListing {
    private final ProgramSession session;

    public InstructionListing(ProgramSession session) {
        this.session = session;
    }

    public JsonObject instructionsIn(AddressSetView range, JsonObject args) throws Exception {
        long limit = ListQuery.pageArgument(args, "limit");
        JsonArray instructions = new JsonArray();
        for (Instruction instruction : session.program().getListing().getInstructions(range, true)) {
            session.monitor().checkCancelled();
            if (!range.contains(instruction.getAddress())) continue;
            instructions.add(instructionToJson(instruction));
            if (limit > 0 && instructions.size() >= limit) break;
        }
        JsonObject result = new JsonObject();
        result.add("instructions", instructions);
        result.addProperty("count", instructions.size());
        return result;
    }

    JsonArray instructionsFrom(Instruction instruction, long limit) throws Exception {
        JsonArray instructions = new JsonArray();
        while (instruction != null && (limit == 0 || instructions.size() < limit)) {
            session.monitor().checkCancelled();
            instructions.add(instructionToJson(instruction));
            instruction = instruction.getNext();
        }
        return instructions;
    }

    private JsonObject instructionToJson(Instruction instr) throws MemoryAccessException {
        byte[] byteArray = instr.getBytes();
        StringBuilder bytesHex = new StringBuilder();
        for (byte b : byteArray) {
            bytesHex.append(String.format("%02x", b & 0xff));
        }

        JsonArray operands = new JsonArray();
        int numOperands = instr.getNumOperands();
        for (int j = 0; j < numOperands; j++) {
            operands.add(new JsonPrimitive(instr.getDefaultOperandRepresentation(j)));
        }

        JsonObject instrData = new JsonObject();
        instrData.addProperty("address", AddressCodec.format(instr.getAddress()));
        instrData.addProperty("bytes", bytesHex.toString());
        instrData.addProperty("mnemonic", instr.getMnemonicString());
        instrData.add("operands", operands);
        return instrData;
    }
}
