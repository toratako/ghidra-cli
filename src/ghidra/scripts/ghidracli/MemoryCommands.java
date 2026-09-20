package ghidracli;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.util.PseudoDisassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.ByteMemBufferImpl;
import ghidra.program.model.mem.MemoryAccessException;
import java.util.Arrays;
import static ghidracli.JsonProtocol.errorResult;
import static ghidracli.JsonProtocol.getArgString;

final class MemoryCommands {
    private final ProgramSession session;
    private final AddressResolver addressResolver;
    private final FunctionQueries functionQueries;

    MemoryCommands(ProgramSession session, AddressResolver addressResolver, FunctionQueries functionQueries) {
        this.session = session;
        this.addressResolver = addressResolver;
        this.functionQueries = functionQueries;
    }

    JsonObject handleMemoryWrite(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");

        String addressStr = getArgString(args, "address");
        String hexData = getArgString(args, "hex");
        if (addressStr == null || hexData == null) {
            return errorResult("Address and hex data required");
        }

        try {
            Address addr = addressResolver.resolveAddress(addressStr);
            if (addr == null) return errorResult("Invalid address: " + addressStr);

            String hexClean = hexData.replace("0x", "").replace(" ", "");
            if (hexClean.isEmpty() || (hexClean.length() % 2) != 0
                    || !hexClean.matches("[0-9a-fA-F]+")) {
                return errorResult("Hex data must contain complete byte pairs (two hex digits per byte); "
                    + "provide non-empty, even-length hex data");
            }
            byte[] patchData = new byte[hexClean.length() / 2];
            for (int i = 0; i < patchData.length; i++) {
                patchData[i] = (byte) Integer.parseInt(hexClean.substring(i * 2, i * 2 + 2), 16);
            }

            MemoryPatch.write(session, addr, patchData);

            JsonObject result = new JsonObject();
            result.addProperty("status", "patched");
            result.addProperty("address", AddressCodec.format(addr));
            result.addProperty("bytes", patchData.length);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to patch bytes: " + e.getMessage());
        }
    }

    JsonObject handleDisasm(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");

        String addressStr = getArgString(args, "address");

        if (addressStr == null || addressStr.isEmpty()) {
            return errorResult("Address required");
        }

        try {
            long limit = ListQuery.pageArgument(args, "limit");
            // Use resolveAddress which handles 0x prefix and symbol lookup
            Address addr = addressResolver.resolveAddress(addressStr);
            if (addr == null) return errorResult("Invalid address: " + addressStr);

            Listing listing = session.program().getListing();
            Instruction instruction = listing.getInstructionAt(addr);

            // If no instruction at exact address, try containing instruction (mid-instruction)
            if (instruction == null) {
                instruction = listing.getInstructionContaining(addr);
            }

            if (instruction == null) {
                return errorResult("No instruction at address " + AddressCodec.format(addr) +
                    ". Address may be data or unanalyzed code.");
            }

            JsonArray results = instructionsFrom(instruction, limit);

            JsonObject result = new JsonObject();
            result.add("instructions", results);
            result.addProperty("count", results.size());
            return result;
        } catch (Exception e) {
            return errorResult("Failed to disassemble: " + e.getMessage());
        }
    }

    JsonObject handleFunctionDisasm(JsonObject args) throws Exception {
        if (session.program() == null) return errorResult("No program loaded");
        String target = getArgString(args, "target");
        if (target == null || target.isEmpty()) return errorResult("Function target required");
        Function function = functionQueries.findFunctionByNameOrAddress(target);
        if (function == null) return errorResult(functionQueries.buildFunctionTargetHint(target));
        return instructionsIn(function.getBody(), args);
    }

    JsonObject handleDisasmRange(JsonObject args) throws Exception {
        if (session.program() == null) return errorResult("No program loaded");
        String start = getArgString(args, "start");
        String end = getArgString(args, "end");
        if (start == null || end == null) return errorResult("Start and end addresses required");
        AddressSetView range = addressResolver.instructionRange(start, end);
        return instructionsIn(range, args);
    }

    private JsonObject instructionsIn(AddressSetView range, JsonObject args) throws Exception {
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

    private JsonArray instructionsFrom(Instruction instruction, long limit) throws Exception {
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

    /** Define code without returning instruction rows; disasm owns reading. */
    JsonObject handleDefineCode(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");

        String addressStr = getArgString(args, "target");
        if (addressStr == null || addressStr.isEmpty()) {
            return errorResult("Target required");
        }

        try {
            for (String option : new String[]{"limit", "count", "filter", "sort", "offset", "fields", "format"}) {
                if (args.has(option)) return errorResult("define_code does not support " + option
                    + "; use disassemble to read instructions");
            }
            Address addr = addressResolver.resolveAddress(addressStr);
            if (addr == null) return errorResult("Invalid address: " + addressStr);
            String endStr = getArgString(args, "end");
            Address end = endStr == null ? null : addressResolver.resolveAddress(endStr);
            if (endStr != null && end == null) return errorResult("Invalid end address: " + endStr);
            if (end != null) {
                if (!addr.getAddressSpace().equals(end.getAddressSpace())) {
                    return errorResult("Start and end must be in the same address space");
                }
                if (addr.compareTo(end) > 0) return errorResult("Start address must not be after end address");
            }

            Listing listing = session.program().getListing();
            boolean alreadyPresent = listing.getInstructionAt(addr) != null;
            boolean ok = alreadyPresent;
            boolean changed = false;
            AddressSet permitted = !alreadyPresent && end != null ? definitionStarts(addr, end) : null;

            if (!alreadyPresent && (permitted == null || permitted.contains(addr))) {
                DisassembleCommand command = new DisassembleCommand(addr, permitted, true);
                command.enableCodeAnalysis(false);
                ok = command.applyTo(session.program(), session.monitor());
                changed = !command.getDisassembledAddressSet().isEmpty();
            }
            session.monitor().checkCancelled();

            boolean landed = listing.getInstructionAt(addr) != null;

            JsonObject result = new JsonObject();
            result.addProperty("address", AddressCodec.format(addr));
            result.addProperty("end", end == null ? null : AddressCodec.format(end));
            result.addProperty("already_defined", alreadyPresent);
            result.addProperty("changed", changed);
            result.addProperty("ok", ok);
            result.addProperty("landed", landed);
            result.addProperty("status", ok && landed ? (changed ? "defined" : "unchanged") : "failed");

            if (!ok || !landed) {
                result.addProperty("error", "Failed to define code at " + AddressCodec.format(addr)
                    + (landed ? ": Ghidra did not complete disassembly"
                        : ": no complete instruction was created within the requested range"));
                Function owner = session.program().getFunctionManager().getFunctionContaining(addr);
                if (owner != null) {
                    result.addProperty("hint", "Address falls inside existing function "
                        + owner.getName() + "@" + AddressCodec.format(owner.getEntryPoint())
                        + "; stale/overlapping instructions may be blocking disassembly. Try `ghidra-cli clear` first.");
                }
            }
            return result;
        } catch (Exception e) {
            return errorResult("Failed to define code at " + addressStr + ": " + e.getMessage());
        }
    }

    /**
     * Ghidra's restrictedSet bounds instruction starts, not complete instructions
     * or delay slots. Preview the ordinary flow-following command and roll it back,
     * excluding starts of any groups that cross the byte bounds before the real run.
     * Retaining the native command preserves processor future context (e.g. Thumb
     * IT), custom decoders, and no-return handling. Auto-analysis is not run here.
     */
    private AddressSet definitionStarts(Address start, Address end) throws Exception {
        AddressSet bounds = new AddressSet(start, end);
        AddressSet permitted = new AddressSet(start, end);
        while (permitted.contains(start)) {
            session.monitor().checkCancelled();
            AddressSet excluded = session.preview("Preview bounded code definition", () -> {
                DisassembleCommand command = new DisassembleCommand(start, permitted, true);
                command.enableCodeAnalysis(false);
                command.applyTo(session.program(), session.monitor());
                session.monitor().checkCancelled();
                AddressSet rejected = new AddressSet();
                Listing listing = session.program().getListing();
                for (Instruction instruction : listing.getInstructions(command.getDisassembledAddressSet(), true)) {
                    session.monitor().checkCancelled();
                    if (bounds.contains(instruction.getMinAddress(), instruction.getMaxAddress())) continue;
                    // A delay slot belongs to its preceding branch, not an independent start.
                    Instruction group = instruction;
                    while (group.isInDelaySlot()) {
                        Instruction previous = group.getPrevious();
                        if (previous == null) throw new IllegalStateException("Delay slot without its parent instruction");
                        group = previous;
                    }
                    rejected.add(group.getAddress());
                }
                return rejected;
            });
            if (excluded.isEmpty()) return permitted;
            if (!permitted.intersects(excluded)) {
                throw new IllegalStateException("Cannot safely constrain code definition to the requested range");
            }
            permitted.delete(excluded);
        }
        return permitted;
    }

    /**
     * Clear all code units overlapping [start, end] (retroactively undoing
     * auto-analysis that linearly disassembled through inline data), optionally
     * re-disassembling at a precise address in the same call.
     */
    JsonObject handleClearRange(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");

        String startStr = getArgString(args, "start");
        String endStr = getArgString(args, "end");
        String disasmAtStr = getArgString(args, "disasm_at");
        if (startStr == null || endStr == null) {
            return errorResult("start and end addresses required");
        }

        try {
            Address start = AddressCodec.parseCanonical(session.program().getAddressFactory(), startStr);
            if (start == null) return errorResult("Invalid start address: " + startStr
                + ". Use a 0x-prefixed address.");
            Address end = AddressCodec.parseCanonical(session.program().getAddressFactory(), endStr);
            if (end == null) return errorResult("Invalid end address: " + endStr
                + ". Use a 0x-prefixed address.");
            if (!start.getAddressSpace().equals(end.getAddressSpace())) {
                return errorResult("Start and end must be in the same address space");
            }
            if (start.compareTo(end) > 0) {
                return errorResult("Start address must not be after end address");
            }

            Address disasmAt = null;
            if (disasmAtStr != null && !disasmAtStr.isEmpty()) {
                disasmAt = addressResolver.resolveAddress(disasmAtStr);
                if (disasmAt == null) return errorResult("Invalid disasm_at address: " + disasmAtStr);
            }

            JsonObject result = new JsonObject();
            session.clearListing(start, end);
            result.addProperty("status", "cleared");
            result.addProperty("start", AddressCodec.format(start));
            result.addProperty("end", AddressCodec.format(end));

            if (disasmAt != null) {
                boolean ok = session.disassemble(disasmAt);
                boolean landed = session.program().getListing().getInstructionAt(disasmAt) != null;
                result.addProperty("disasm_at", AddressCodec.format(disasmAt));
                result.addProperty("ok", ok);
                result.addProperty("landed", landed);
                result.addProperty("status", (ok && landed) ? "cleared_and_disassembled" : "failed");
                if (!ok || !landed) {
                    result.addProperty("error", "Failed to clear range and disassemble at "
                        + AddressCodec.format(disasmAt) + ": disassembly did not complete");
                }
                if (!landed) {
                    result.addProperty("hint", "clearEnd may need to extend further past disasm_at: "
                        + "disassemble() can silently land no instruction if the new instruction's "
                        + "tail bytes would still overlap a stale code unit outside the cleared range.");
                }
            }
            return result;
        } catch (Exception e) {
            return errorResult("Failed to clear range: " + e.getMessage());
        }
    }

    JsonObject handleReadMemory(JsonObject args) {
        String addrStr = getArgString(args, "address");
        if (addrStr == null) return errorResult("Address required");

        int size = 200;
        if (args != null && args.has("size")) {
            size = args.get("size").getAsInt();
        }

        try {
            ghidra.program.model.mem.Memory mem = session.program().getMemory();

            Address baseAddr = addressResolver.resolveAddress(addrStr);
            if (baseAddr == null) {
                return errorResult("Invalid address: " + addrStr);
            }

            // Read bytes
            byte[] bytes = new byte[size];
            int bytesRead = mem.getBytes(baseAddr, bytes);

            // Build hex string
            StringBuilder hexStr = new StringBuilder();
            for (int i = 0; i < bytesRead; i++) {
                hexStr.append(String.format("%02x", bytes[i] & 0xFF));
            }

            int pointerSize = session.program().getDefaultPointerSize();
            boolean bigEndian = mem.isBigEndian();
            JsonArray pointers = new JsonArray();
            for (int i = 0; i <= bytesRead - pointerSize; i += pointerSize) {
                Address pointerAddr = baseAddr.add(i);
                ByteMemBufferImpl buffer = new ByteMemBufferImpl(mem, pointerAddr,
                    Arrays.copyOfRange(bytes, i, i + pointerSize), bigEndian);
                JsonObject ptrObj = new JsonObject();
                ptrObj.addProperty("offset", i);
                ptrObj.addProperty("address", AddressCodec.format(pointerAddr));
                ptrObj.addProperty("value", String.format("0x%0" + (pointerSize * 2) + "x",
                    buffer.getBigInteger(0, pointerSize, false)));

                // Ghidra handles unsigned offsets and the source address space's
                // overlay, segmented, and addressable-word pointer semantics.
                Address funcAddr = PointerDataType.getAddressValue(buffer, pointerSize,
                    pointerAddr.getAddressSpace());
                if (funcAddr != null) {
                    Address entry = PseudoDisassembler.getNormalizedDisassemblyAddress(session.program(), funcAddr);
                    // Removing a code-mode bit must not escape an overlay into its physical space.
                    if (entry.getAddressSpace().equals(funcAddr.getAddressSpace()) && mem.contains(entry)) {
                        Function func = session.program().getFunctionManager().getFunctionAt(entry);
                        if (func != null) {
                            ptrObj.addProperty("function", func.getName());
                        }
                    }
                }

                pointers.add(ptrObj);
            }

            JsonObject result = new JsonObject();
            result.addProperty("address", AddressCodec.format(baseAddr));
            result.addProperty("size", bytesRead);
            result.addProperty("hex", hexStr.toString());
            result.add("pointers", pointers);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to read memory: " + e.getMessage());
        }
    }
}
