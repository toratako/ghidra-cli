package ghidracli.listing;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidracli.query.AddressCodec;
import ghidracli.session.ProgramSession;
import java.util.Locale;
import java.util.Objects;

import static ghidracli.protocol.JsonProtocol.errorResult;

/** Changes interpretation through native instruction metadata without analysis or byte edits. */
public final class ListingFlowCommands {
    private final ProgramSession session;

    public ListingFlowCommands(ProgramSession session) {
        this.session = session;
    }

    public JsonObject handleGet(JsonObject args) throws Exception {
        if (session.program() == null) return errorResult("No program loaded");
        session.monitor().checkCancelled();
        return describe(requireInstruction(requireString(args, "address")));
    }

    public JsonObject handleSet(JsonObject args) throws Exception {
        if (session.program() == null) return errorResult("No program loaded");
        Instruction instruction = requireInstruction(requireString(args, "address"));
        FlowOverride override = has(args, "override") ? requireOverride(args) : null;
        boolean noFallthrough = booleanArg(args, "no_fallthrough");
        boolean explicitFallthrough = has(args, "fallthrough");
        if (explicitFallthrough && noFallthrough) {
            throw new IllegalArgumentException("fallthrough and no_fallthrough are mutually exclusive");
        }
        if (override == null && !explicitFallthrough && !noFallthrough) {
            throw new IllegalArgumentException("Specify override, fallthrough, or no_fallthrough");
        }
        if (override != null && !InstructionFlow.hasRawTransfer(instruction)) {
            throw new IllegalArgumentException("Flow override requires a branch, call, or return at "
                + AddressCodec.format(instruction.getAddress()));
        }
        Address fallthrough = null;
        if (explicitFallthrough) {
            fallthrough = requireInstruction(requireString(args, "fallthrough")).getAddress();
            if (!instruction.getAddress().getAddressSpace().equals(fallthrough.getAddressSpace())) {
                throw new IllegalArgumentException("fallthrough must be in the instruction's address space");
            }
        }
        JsonObject before = describe(instruction);
        boolean preservedFallthroughOverride = instruction.isFallThroughOverridden();
        Address preservedFallthrough = instruction.getFallThrough();
        session.monitor().checkCancelled();
        if (override != null) instruction.setFlowOverride(override);
        if (override != null && instruction.getFlowOverride() != override) {
            throw new IllegalStateException("Ghidra did not retain the requested flow override");
        }
        session.monitor().checkCancelled();
        if (explicitFallthrough) {
            setFallthrough(instruction, fallthrough);
        } else if (noFallthrough) {
            instruction.setFallThrough(null);
            // Ghidra normalizes a raw terminal instruction's null target to no override,
            // even when a CALL override has introduced a fallthrough. Do not report a
            // successful suppression that the native program cannot actually represent.
            if (instruction.getFallThrough() != null || !instruction.isFallThroughOverridden()) {
                throw new IllegalArgumentException("Ghidra cannot retain an explicit no-fallthrough "
                    + "override for this instruction (raw fallthrough is absent)");
            }
        }
        if (!explicitFallthrough && !noFallthrough
                && (instruction.isFallThroughOverridden() != preservedFallthroughOverride
                    || (preservedFallthroughOverride
                        && !Objects.equals(instruction.getFallThrough(), preservedFallthrough)))) {
            throw new IllegalStateException("Ghidra did not preserve the existing fallthrough override");
        }
        session.monitor().checkCancelled();
        return receipt(before, describe(instruction));
    }

    public JsonObject handleClear(JsonObject args) throws Exception {
        if (session.program() == null) return errorResult("No program loaded");
        Instruction instruction = requireInstruction(requireString(args, "address"));
        boolean override = booleanArg(args, "override");
        boolean fallthrough = booleanArg(args, "fallthrough");
        if (!override && !fallthrough) {
            throw new IllegalArgumentException("Specify override or fallthrough to clear");
        }
        JsonObject before = describe(instruction);
        session.monitor().checkCancelled();
        if (override) instruction.setFlowOverride(FlowOverride.NONE);
        session.monitor().checkCancelled();
        if (fallthrough) instruction.clearFallThroughOverride();
        session.monitor().checkCancelled();
        return receipt(before, describe(instruction));
    }

    private void setFallthrough(Instruction instruction, Address target) {
        instruction.setFallThrough(target);
        if (!Objects.equals(instruction.getFallThrough(), target)) {
            // setFallThrough compares against the raw prototype, whereas getFallThrough
            // includes flow overrides. A native reference represents an explicit target
            // equal to the raw default after a RETURN override removed that default.
            session.program().getReferenceManager().addMemoryReference(instruction.getAddress(),
                target, RefType.FALL_THROUGH, SourceType.USER_DEFINED, Reference.MNEMONIC);
        }
        if (!Objects.equals(instruction.getFallThrough(), target)) {
            throw new IllegalArgumentException("Ghidra did not retain the requested fallthrough");
        }
    }

    private Instruction requireInstruction(String text) {
        Address address = AddressCodec.parse(session.program().getAddressFactory(), text);
        if (address == null || !address.isMemoryAddress()) {
            throw new IllegalArgumentException("Instruction requires an explicit memory address: " + text);
        }
        Instruction instruction = session.program().getListing().getInstructionAt(address);
        if (instruction == null) {
            throw new IllegalArgumentException("No instruction starts at " + AddressCodec.format(address));
        }
        return instruction;
    }

    private static FlowOverride requireOverride(JsonObject args) {
        String text = requireString(args, "override");
        return switch (text) {
            case "branch" -> FlowOverride.BRANCH;
            case "call" -> FlowOverride.CALL;
            case "call-return" -> FlowOverride.CALL_RETURN;
            case "return" -> FlowOverride.RETURN;
            default -> throw new IllegalArgumentException(
                "override must be branch, call, call-return, or return");
        };
    }

    private static boolean has(JsonObject args, String key) {
        return args != null && args.has(key) && !args.get(key).isJsonNull();
    }

    private static String requireString(JsonObject args, String key) {
        JsonElement value = args == null ? null : args.get(key);
        if (value == null || !value.isJsonPrimitive() || !value.getAsJsonPrimitive().isString()
                || value.getAsString().isBlank()) {
            throw new IllegalArgumentException(key + " must be a nonempty string");
        }
        return value.getAsString();
    }

    private static boolean booleanArg(JsonObject args, String key) {
        if (!has(args, key)) return false;
        JsonElement value = args.get(key);
        if (!value.isJsonPrimitive() || !value.getAsJsonPrimitive().isBoolean()) {
            throw new IllegalArgumentException(key + " must be a boolean");
        }
        return value.getAsBoolean();
    }

    private JsonObject describe(Instruction instruction) {
        JsonObject result = new JsonObject();
        result.addProperty("address", AddressCodec.format(instruction.getAddress()));
        result.addProperty("instruction", instruction.toString());
        result.addProperty("raw_flow", InstructionFlow.rawFlowType(instruction).toString());
        result.addProperty("effective_flow", instruction.getFlowType().toString());
        result.addProperty("override", instruction.getFlowOverride().name()
            .toLowerCase(Locale.ROOT).replace('_', '-'));
        JsonObject fallthrough = new JsonObject();
        address(fallthrough, "raw", InstructionFlow.rawFallthrough(instruction));
        address(fallthrough, "default", instruction.getDefaultFallThrough());
        address(fallthrough, "effective", instruction.getFallThrough());
        fallthrough.addProperty("overridden", instruction.isFallThroughOverridden());
        result.add("fallthrough", fallthrough);
        result.addProperty("delay_slot_depth", instruction.getDelaySlotDepth());
        result.addProperty("in_delay_slot", instruction.isInDelaySlot());
        JsonArray references = new JsonArray();
        for (Reference reference : instruction.getReferencesFrom()) {
            if (!reference.getReferenceType().isFlow()) continue;
            JsonObject row = new JsonObject();
            address(row, "to", reference.getToAddress());
            row.addProperty("type", reference.getReferenceType().toString());
            row.addProperty("operand", reference.getOperandIndex());
            row.addProperty("source", reference.getSource().toString());
            row.addProperty("primary", reference.isPrimary());
            references.add(row);
        }
        result.add("flow_references", references);
        return result;
    }

    private static void address(JsonObject result, String key, Address address) {
        result.addProperty(key, address == null ? null : AddressCodec.format(address));
    }

    private static JsonObject receipt(JsonObject before, JsonObject after) {
        JsonObject result = new JsonObject();
        result.addProperty("address", after.get("address").getAsString());
        result.addProperty("changed", !before.equals(after));
        result.add("before", before);
        result.add("after", after);
        return result;
    }
}
