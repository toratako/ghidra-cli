package ghidracli;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.TaskMonitor;
import java.io.File;
import java.util.Arrays;
import static ghidracli.JsonProtocol.errorResult;
import static ghidracli.JsonProtocol.getArgInt;
import static ghidracli.JsonProtocol.getArgString;

final class MemoryCommands {
    private final ProgramSession session;
    private final AddressResolver addressResolver;

    MemoryCommands(ProgramSession session, AddressResolver addressResolver) {
        this.session = session;
        this.addressResolver = addressResolver;
    }

    JsonObject handlePatchBytes(JsonObject args) {
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
            byte[] patchData = new byte[hexClean.length() / 2];
            for (int i = 0; i < patchData.length; i++) {
                patchData[i] = (byte) Integer.parseInt(hexClean.substring(i * 2, i * 2 + 2), 16);
            }

            Memory memory = session.program().getMemory();
            Listing listing = session.program().getListing();
            MemoryBlock block = memory.getBlock(addr);
            boolean restoreReadOnly = block != null && !block.isWrite();
            ProgramTransaction transaction = session.transaction("Patch bytes");
            boolean commit = false;
            try {
                if (restoreReadOnly) block.setWrite(true);
                Address endAddr = addr.add(patchData.length - 1);
                listing.clearCodeUnits(addr, endAddr, false);
                memory.setBytes(addr, patchData);
                commit = true;
            } finally {
                if (restoreReadOnly) block.setWrite(false);
                transaction.end(commit);
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "patched");
            result.addProperty("address", addr.toString());
            result.addProperty("bytes", patchData.length);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to patch bytes: " + e.getMessage());
        }
    }

    JsonObject handlePatchNop(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");

        String addressStr = getArgString(args, "address");
        if (addressStr == null) return errorResult("Address required");

        int count = getArgInt(args, "count", 1);
        if (count < 1) return errorResult("count must be >= 1");

        try {
            Address addr = addressResolver.resolveAddress(addressStr);
            if (addr == null) return errorResult("Invalid address: " + addressStr);

            Listing listing = session.program().getListing();
            Memory memory = session.program().getMemory();
            MemoryBlock block = memory.getBlock(addr);
            boolean restoreReadOnly = block != null && !block.isWrite();
            String processor = session.program().getLanguage().getProcessor().toString();
            byte nopByte = processor.toLowerCase().contains("x86") ? (byte) 0x90 : (byte) 0x00;

            JsonArray nopped = new JsonArray();
            int totalBytes = 0;
            ProgramTransaction transaction = session.transaction("NOP instructions");
            boolean commit = false;
            try {
                if (restoreReadOnly) block.setWrite(true);
                Address cur = addr;
                for (int i = 0; i < count; i++) {
                    Instruction instruction = listing.getInstructionAt(cur);
                    if (instruction == null) {
                        if (i == 0) {
                            return errorResult("No instruction at address: " + cur.toString());
                        }
                        break;
                    }

                    int instrLength = instruction.getLength();
                    Address next = cur.add(instrLength);
                    byte[] nopBytes = new byte[instrLength];
                    Arrays.fill(nopBytes, nopByte);
                    listing.clearCodeUnits(cur, cur.add(instrLength - 1), false);
                    memory.setBytes(cur, nopBytes);

                    JsonObject entry = new JsonObject();
                    entry.addProperty("address", cur.toString());
                    entry.addProperty("bytes", instrLength);
                    nopped.add(entry);
                    totalBytes += instrLength;
                    cur = next;
                }
                commit = true;
            } finally {
                if (restoreReadOnly) block.setWrite(false);
                transaction.end(commit);
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "nopped");
            result.addProperty("address", addr.toString());
            result.addProperty("count", nopped.size());
            result.addProperty("bytes", totalBytes);
            result.add("instructions", nopped);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to NOP instruction: " + e.getMessage());
        }
    }

    JsonObject handlePatchExport(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");

        String outputPath = getArgString(args, "output");
        if (outputPath == null || outputPath.isEmpty()) {
            return errorResult("Output path required");
        }

        try {
            // Use reflection to access BinaryExporter which may not always be available.
            // The base Exporter.export() declares its second parameter as DomainObject
            // (not Program), and the exact signature has drifted across Ghidra versions,
            // so resolve the method by name + 4-arg arity rather than exact param types
            // (a hardcoded Program.class lookup throws NoSuchMethodException on Ghidra 12).
            Class<?> exporterClass = Class.forName("ghidra.app.util.exporter.BinaryExporter");
            Object exporter = exporterClass.getDeclaredConstructor().newInstance();

            java.lang.reflect.Method exportMethod = null;
            for (java.lang.reflect.Method m : exporterClass.getMethods()) {
                if (m.getName().equals("export") && m.getParameterCount() == 4) {
                    exportMethod = m;
                    break;
                }
            }
            if (exportMethod == null) {
                return errorResult(
                    "BinaryExporter.export(File, DomainObject, AddressSetView, TaskMonitor) not found");
            }

            File outputFile = new File(outputPath);
            TaskMonitor mon = session.monitor();
            exportMethod.invoke(exporter, outputFile, session.program(), null, mon);

            JsonObject result = new JsonObject();
            result.addProperty("status", "exported");
            result.addProperty("output", outputPath);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to export binary: " + e.getMessage());
        }
    }

    JsonObject handleDisasm(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");

        String addressStr = getArgString(args, "address");
        int count = getArgInt(args, "count", 10);

        if (addressStr == null || addressStr.isEmpty()) {
            return errorResult("Address required");
        }

        try {
            // Use resolveAddress which handles 0x prefix and symbol lookup
            Address addr = addressResolver.resolveAddress(addressStr);
            if (addr == null) return errorResult("Invalid address: " + addressStr);

            Listing listing = session.program().getListing();
            Instruction instruction = listing.getInstructionAt(addr);

            // If no instruction at exact address, try containing instruction (mid-instruction)
            if (instruction == null) {
                instruction = listing.getInstructionContaining(addr);
            }

            // If still null, try starting from containing function's entry point
            if (instruction == null) {
                Function func = session.program().getFunctionManager().getFunctionContaining(addr);
                if (func != null) {
                    instruction = listing.getInstructionAt(func.getEntryPoint());
                }
            }

            if (instruction == null) {
                return errorResult("No instruction at address " + addressStr +
                    ". Address may be data or unanalyzed code.");
            }

            JsonArray results = new JsonArray();
            Instruction current = instruction;

            for (int i = 0; i < count && current != null; i++) {
                results.add(instructionToJson(current));
                current = current.getNext();
            }

            JsonObject result = new JsonObject();
            result.add("instructions", results);
            result.addProperty("count", results.size());
            return result;
        } catch (Exception e) {
            return errorResult("Failed to disassemble: " + e.getMessage());
        }
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
        instrData.addProperty("address", instr.getAddress().toString());
        instrData.addProperty("bytes", bytesHex.toString());
        instrData.addProperty("mnemonic", instr.getMnemonicString());
        instrData.add("operands", operands);
        return instrData;
    }

    /**
     * Disassemble at ADDRESS if no instruction is there yet (auto-analysis
     * often never reaches computed-jump targets / inline-table resume
     * addresses), then report whether an instruction actually landed there --
     * disassemble() can return false, or even true while the target still has
     * no instruction, with no exception either way.
     */
    JsonObject handleDisasmAt(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");

        String addressStr = getArgString(args, "address");
        int count = getArgInt(args, "count", 1);
        if (addressStr == null || addressStr.isEmpty()) {
            return errorResult("Address required");
        }

        try {
            Address addr = addressResolver.resolveAddress(addressStr);
            if (addr == null) return errorResult("Invalid address: " + addressStr);

            Listing listing = session.program().getListing();
            boolean alreadyPresent = listing.getInstructionAt(addr) != null;
            boolean ok = alreadyPresent;

            ProgramTransaction transaction = session.transaction("Disassemble at address");
            try {
                if (!alreadyPresent) {
                    ok = session.disassemble(addr);
                }
                transaction.end(true);
            } catch (Exception e) {
                transaction.end(true);
                throw e;
            }

            boolean landed = listing.getInstructionAt(addr) != null;

            JsonObject result = new JsonObject();
            result.addProperty("address", addr.toString());
            result.addProperty("already_disassembled", alreadyPresent);
            result.addProperty("ok", ok);
            result.addProperty("landed", landed);
            result.addProperty("status", landed ? "disassembled" : "failed");

            if (landed) {
                JsonArray instrs = new JsonArray();
                Instruction current = listing.getInstructionAt(addr);
                for (int i = 0; i < count && current != null; i++) {
                    instrs.add(instructionToJson(current));
                    current = current.getNext();
                }
                result.add("instructions", instrs);
            } else {
                Function owner = session.program().getFunctionManager().getFunctionContaining(addr);
                if (owner != null) {
                    result.addProperty("hint", "Address falls inside existing function "
                        + owner.getName() + "@" + owner.getEntryPoint()
                        + "; stale/overlapping instructions may be blocking disassembly. Try `ghidra clear` first.");
                }
            }
            return result;
        } catch (Exception e) {
            return errorResult("Failed to disassemble at " + addressStr + ": " + e.getMessage());
        }
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
            Address start = addressResolver.resolveAddress(startStr);
            if (start == null) return errorResult("Invalid start address: " + startStr);
            Address end = addressResolver.resolveAddress(endStr);
            if (end == null) return errorResult("Invalid end address: " + endStr);

            Address disasmAt = null;
            if (disasmAtStr != null && !disasmAtStr.isEmpty()) {
                disasmAt = addressResolver.resolveAddress(disasmAtStr);
                if (disasmAt == null) return errorResult("Invalid disasm_at address: " + disasmAtStr);
            }

            JsonObject result = new JsonObject();
            ProgramTransaction transaction = session.transaction("Clear code units");
            try {
                session.clearListing(start, end);
                result.addProperty("status", "cleared");
                result.addProperty("start", start.toString());
                result.addProperty("end", end.toString());

                if (disasmAt != null) {
                    boolean ok = session.disassemble(disasmAt);
                    boolean landed = session.program().getListing().getInstructionAt(disasmAt) != null;
                    result.addProperty("disasm_at", disasmAt.toString());
                    result.addProperty("ok", ok);
                    result.addProperty("landed", landed);
                    result.addProperty("status", (ok && landed) ? "cleared_and_disassembled" : "cleared_disasm_incomplete");
                    if (!landed) {
                        result.addProperty("hint", "clearEnd may need to extend further past disasm_at: "
                            + "disassemble() can silently land no instruction if the new instruction's "
                            + "tail bytes would still overlap a stale code unit outside the cleared range.");
                    }
                }
                transaction.end(true);
            } catch (Exception e) {
                transaction.end(true);
                throw e;
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

            // Also interpret as array of 8-byte pointers
            JsonArray pointers = new JsonArray();
            for (int i = 0; i + 7 < bytesRead; i += 8) {
                long val = 0;
                for (int j = 0; j < 8; j++) {
                    val |= ((long)(bytes[i+j] & 0xFF)) << (8*j);
                }
                JsonObject ptrObj = new JsonObject();
                ptrObj.addProperty("offset", i);
                ptrObj.addProperty("address", baseAddr.add(i).toString());
                ptrObj.addProperty("value", String.format("0x%016x", val));

                // Check if value looks like a code address
                if (val >= 0x00401000L && val <= 0x05bb99ffL) {
                    ghidra.program.model.address.Address funcAddr =
                        session.program().getAddressFactory().getDefaultAddressSpace().getAddress(val);
                    ghidra.program.model.listing.Function func = session.program().getFunctionManager().getFunctionAt(funcAddr);
                    if (func != null) {
                        ptrObj.addProperty("function", func.getName());
                    }
                }

                pointers.add(ptrObj);
            }

            JsonObject result = new JsonObject();
            result.addProperty("address", baseAddr.toString());
            result.addProperty("size", bytesRead);
            result.addProperty("hex", hexStr.toString());
            result.add("pointers", pointers);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to read memory: " + e.getMessage());
        }
    }
}
