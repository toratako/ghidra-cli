package ghidracli.listing;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidracli.query.AddressCodec;
import ghidracli.query.AddressResolver;
import ghidracli.query.ListQuery;
import ghidracli.session.ProgramSession;

import static ghidracli.protocol.JsonProtocol.errorResult;
import static ghidracli.protocol.JsonProtocol.getArgString;

public final class ListingCommands {
    private final ProgramSession session;
    private final AddressResolver addressResolver;
    private final StringQueries stringQueries;
    private final InstructionListing instructions;

    public ListingCommands(ProgramSession session, AddressResolver addressResolver,
            StringQueries stringQueries, InstructionListing instructions) {
        this.session = session;
        this.addressResolver = addressResolver;
        this.stringQueries = stringQueries;
        this.instructions = instructions;
    }

    public JsonObject handleListStrings(JsonObject args) throws ghidra.util.exception.CancelledException {
        if (session.program() == null) {
            return errorResult("No program loaded");
        }

        JsonArray strings = stringQueries.list(args, null);

        JsonObject result = new JsonObject();
        result.add("strings", strings);
        result.addProperty("count", strings.size());
        return result;
    }

    public JsonObject handleDisasm(JsonObject args) {
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

            JsonArray results = instructions.instructionsFrom(instruction, limit);

            JsonObject result = new JsonObject();
            result.add("instructions", results);
            result.addProperty("count", results.size());
            return result;
        } catch (Exception e) {
            return errorResult("Failed to disassemble: " + e.getMessage());
        }
    }

    public JsonObject handleDisasmRange(JsonObject args) throws Exception {
        if (session.program() == null) return errorResult("No program loaded");
        String start = getArgString(args, "start");
        String end = getArgString(args, "end");
        if (start == null || end == null) return errorResult("Start and end addresses required");
        AddressSetView range = addressResolver.instructionRange(start, end);
        return instructions.instructionsIn(range, args);
    }

    /** Define code without returning instruction rows; disasm owns reading. */
    public JsonObject handleDefineCode(JsonObject args) {
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
                        + "; stale/overlapping instructions may be blocking disassembly. Try `ghidra-cli listing undefine START --end END` first.");
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
    public JsonObject handleClearRange(JsonObject args) {
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
}
