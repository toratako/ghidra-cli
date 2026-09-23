package ghidracli.listing;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.BitFieldDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Dynamic;
import ghidra.program.model.data.FactoryDataType;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.MemoryBufferImpl;
import ghidracli.query.AddressCodec;
import ghidracli.query.AddressResolver;
import ghidracli.query.ListQuery;
import ghidracli.session.ProgramSession;
import ghidracli.types.TypeResolver;

import static ghidracli.protocol.JsonProtocol.errorResult;
import static ghidracli.protocol.JsonProtocol.getArgBool;
import static ghidracli.protocol.JsonProtocol.getArgString;

public final class ListingCommands {
    private final ProgramSession session;
    private final TypeResolver typeResolver;
    private final AddressResolver addressResolver;
    private final StringQueries stringQueries;
    private final InstructionListing instructions;

    public ListingCommands(ProgramSession session, AddressResolver addressResolver,
            StringQueries stringQueries, InstructionListing instructions, TypeResolver typeResolver) {
        this.session = session;
        this.typeResolver = typeResolver;
        this.addressResolver = addressResolver;
        this.stringQueries = stringQueries;
        this.instructions = instructions;
    }

    public JsonObject handleDefineData(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");

        String addressStr = getArgString(args, "address");
        String typeName = getArgString(args, "type_name");
        boolean force = getArgBool(args, "force", false);
        if (addressStr == null || typeName == null) {
            return errorResult("Address and type_name required");
        }

        try {
            Address addr = AddressCodec.parse(session.program().getAddressFactory(), addressStr);
            if (addr == null) return errorResult("Invalid address: " + addressStr);

            DataType dataType = typeResolver.resolveDataType(typeName);
            if (dataType == null) {
                return errorResult("Type not found: " + typeName);
            }

            // Mirror listing applicability and sizing before any destructive clear.
            if (dataType instanceof FactoryDataType) {
                dataType = ((FactoryDataType) dataType).getDataType(
                    new MemoryBufferImpl(session.program().getMemory(), addr));
                if (dataType == null) return errorResult("Failed to resolve data type: " + typeName);
                dataType = dataType.clone(session.program().getDataTypeManager());
            }
            if (dataType instanceof BitFieldDataType)
                return errorResult("Bitfields not supported for Data");
            DataType baseType = dataType instanceof TypeDef
                ? ((TypeDef) dataType).getBaseDataType() : dataType;
            if (baseType instanceof FunctionDefinition)
                dataType = new PointerDataType(dataType, session.program().getDataTypeManager());
            int length = dataType instanceof Dynamic
                ? ((Dynamic) dataType).getLength(new MemoryBufferImpl(session.program().getMemory(), addr), -1)
                : dataType.getLength();
            if (length <= 0 || dataType.isZeroLength())
                return errorResult("Type must have a positive applicable data length: " + typeName);
            Address clearEnd = addr.addNoWrap(length - 1);
            if (!session.program().getMemory().contains(addr, clearEnd))
                return errorResult("Type range extends outside program memory: "
                    + AddressCodec.format(addr) + "-" + AddressCodec.format(clearEnd));

            // Captured before the clear below (which can silently remove the Function
            // object along with its code) so a `--force` that lands on a function's own
            // entry -- rather than an actual conflicting data unit -- is still reported.
            ghidra.program.model.listing.Function forcedFunctionEntry = force
                ? session.program().getFunctionManager().getFunctionAt(addr)
                : null;

            Listing listing = session.program().getListing();
            try {
                if (force) {
                    listing.clearCodeUnits(addr, clearEnd, false);
                }
                listing.createData(addr, dataType, length);
            } catch (ghidra.program.model.util.CodeUnitInsertionException e) {
                // Surface the conflicting code unit's own type/length/range.
                return defineDataConflictError(addr, typeName, e);
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "applied");
            result.addProperty("address", AddressCodec.format(addr));
            result.addProperty("type", typeName);
            if (force) {
                result.addProperty("cleared_conflicting", true);
                // `--force` means force: clearing a function's own entry point (as opposed
                // to an actual conflicting data unit) "succeeds" the same way, but silently
                // -- `function get` still reports the function's old name/size afterward,
                // and only a later `function disassemble` failing with "No instruction at
                // address" exposes the corruption. Flag it here instead.
                if (forcedFunctionEntry != null) {
                    result.addProperty("is_function_entry", true);
                    result.addProperty("warning", "Cleared the entry point of function '"
                        + forcedFunctionEntry.getName() + "' (code, not a conflicting data "
                        + "unit) and replaced it with " + typeName
                        + " data -- the function's code is gone, not just its conflicting bytes.");
                }
            }
            return result;
        } catch (Exception e) {
            return errorResult("Failed to apply type: " + e.getMessage(), e);
        }
    }

    private JsonObject defineDataConflictError(Address addr, String typeName, Exception cause) {
        Listing listing = session.program().getListing();
        CodeUnit cu = listing.getCodeUnitContaining(addr);

        JsonObject detail = new JsonObject();
        String description = "unknown";
        if (cu != null) {
            detail.addProperty("conflicting_start", AddressCodec.format(cu.getMinAddress()));
            detail.addProperty("conflicting_end", AddressCodec.format(cu.getMaxAddress()));
            detail.addProperty("conflicting_length", cu.getLength());
            if (cu instanceof Instruction) {
                detail.addProperty("conflicting_kind", "instruction");
                detail.addProperty("conflicting_mnemonic", ((Instruction) cu).getMnemonicString());
                description = "an instruction (" + ((Instruction) cu).getMnemonicString() + ")";
            } else if (cu instanceof Data) {
                Data d = (Data) cu;
                detail.addProperty("conflicting_kind", "data");
                detail.addProperty("conflicting_type", d.getDataType().getName());
                detail.addProperty("conflicting_defined", d.isDefined());
                description = (d.isDefined() ? "defined data of type " + d.getDataType().getName()
                    : "undefined data") + " spanning " + AddressCodec.format(cu.getMinAddress())
                    + "-" + AddressCodec.format(cu.getMaxAddress());
            }
        }

        JsonObject err = errorResult("Conflicting data exists at " + AddressCodec.format(addr) + " for type " + typeName
            + ": conflicts with " + description + ". Use --force to clear the conflicting range first.");
        err.add("detail", detail);
        return err;
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
