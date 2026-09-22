package ghidracli;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.OverlayAddressSpace;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;
import static ghidracli.JsonProtocol.errorResult;
import static ghidracli.JsonProtocol.getArgString;
import static ghidracli.JsonProtocol.getArgBool;

final class XrefCommands {
    private final ProgramSession session;
    private final AddressResolver addressResolver;
    private final FunctionQueries functionQueries;

    XrefCommands(ProgramSession session, AddressResolver addressResolver, FunctionQueries functionQueries) {
        this.session = session;
        this.addressResolver = addressResolver;
        this.functionQueries = functionQueries;
    }

    JsonObject handleCreateMemory(JsonObject args) throws ghidra.util.exception.CancelledException {
        Target target = mutationTarget(args);
        RefType type = referenceType(getArgString(args, "ref_type"));
        if ((type.isCall() || type.isJump()) && !(target.unit instanceof Instruction)) {
            throw new IllegalArgumentException("Call and jump references require an instruction at FROM");
        }
        if (source(args) != SourceType.USER_DEFINED) {
            throw new IllegalArgumentException("Memory reference creation requires source USER_DEFINED");
        }
        ReferenceManager refs = session.program().getReferenceManager();
        Reference existing = refs.getReference(target.from, target.to, target.operand);
        if (existing != null) {
            requireOrdinaryMemory(existing);
            if (existing.getReferenceType() != type || existing.getSource() != SourceType.USER_DEFINED) {
                throw conflict("Reference already exists with a different ref_type or source", existing);
            }
            JsonObject row = referenceRow(existing);
            return receipt(target, false, 0, row, row.deepCopy());
        }
        for (Reference reference : refs.getReferencesFrom(target.from, target.operand)) {
            session.monitor().checkCancelled();
            // addMemoryReference would silently delete these references.
            if (!reference.isMemoryReference()) {
                throw conflict("Operand already has a non-memory reference", reference);
            }
        }
        if (target.to.getAddressSpace() instanceof OverlayAddressSpace
                && !((OverlayAddressSpace) target.to.getAddressSpace()).translateAddress(target.to)
                    .equals(target.to)) {
            // Native addReference also delegates to addMemoryReference and translates
            // an unmapped overlay destination to its physical space. Never retarget it.
            throw new IllegalArgumentException("Ghidra cannot preserve this unmapped overlay destination: "
                + AddressCodec.format(target.to) + ". Choose a mapped overlay address or an explicit physical address.");
        }
        session.monitor().checkCancelled();
        Reference created = refs.addMemoryReference(target.from, target.to, type,
            SourceType.USER_DEFINED, target.operand);
        if (created == null || !target.to.equals(created.getToAddress())
                || created.getReferenceType() != type || created.getSource() != SourceType.USER_DEFINED) {
            throw new IllegalStateException("Ghidra did not create the requested memory reference");
        }
        return receipt(target, true, 1, JsonNull.INSTANCE, referenceRow(created));
    }

    JsonObject handleDelete(JsonObject args) throws ghidra.util.exception.CancelledException {
        Target target = mutationTarget(args);
        SourceType expectedSource = source(args);
        ReferenceManager refs = session.program().getReferenceManager();
        Reference reference = refs.getReference(target.from, target.to, target.operand);
        if (reference == null) return receipt(target, false, 0, JsonNull.INSTANCE, JsonNull.INSTANCE);
        requireOrdinaryMemory(reference);
        requireSource(reference, expectedSource);
        JsonObject before = referenceRow(reference);
        session.monitor().checkCancelled();
        refs.delete(reference);
        if (refs.getReference(target.from, target.to, target.operand) != null) {
            throw new IllegalStateException("Ghidra did not delete the requested memory reference");
        }
        return receipt(target, true, 1, before, JsonNull.INSTANCE);
    }

    JsonObject handleSetPrimary(JsonObject args) throws ghidra.util.exception.CancelledException {
        Target target = mutationTarget(args);
        SourceType expectedSource = source(args);
        ReferenceManager refs = session.program().getReferenceManager();
        Reference reference = refs.getReference(target.from, target.to, target.operand);
        if (reference == null) throw new IllegalArgumentException("Memory reference not found");
        requireOrdinaryMemory(reference);
        requireSource(reference, expectedSource);
        JsonArray before = operandReferences(target);
        boolean changed = !reference.isPrimary();
        if (changed) {
            Reference previous = refs.getPrimaryReferenceFrom(target.from, target.operand);
            if (previous != null) requireOrdinaryMemory(previous);
            session.monitor().checkCancelled();
            refs.setPrimary(reference, true);
            Reference updated = refs.getReference(target.from, target.to, target.operand);
            if (updated == null || !updated.isPrimary()) {
                throw new IllegalStateException("Ghidra did not make the requested reference primary");
            }
        }
        return receipt(target, changed, changed ? 1 : 0, before, operandReferences(target));
    }

    private Target mutationTarget(JsonObject args) {
        if (session.program() == null) throw new IllegalArgumentException("No program loaded");
        Address from = memoryAddress(args, "from");
        Address to = memoryAddress(args, "to");
        int operand = operandIndex(args);
        CodeUnit unit = session.program().getListing().getInstructionAt(from);
        if (unit == null) unit = session.program().getListing().getDefinedDataAt(from);
        if (unit == null) {
            throw new IllegalArgumentException("FROM must be an instruction or defined data start: "
                + AddressCodec.format(from));
        }
        if (operand >= unit.getNumOperands()) {
            String validOperands = unit.getNumOperands() == 0 ? "use -1 for the mnemonic"
                : "use -1 for the mnemonic or an operand from 0 to " + (unit.getNumOperands() - 1);
            throw new IllegalArgumentException("operand_index " + operand + " does not exist at "
                + AddressCodec.format(from) + "; " + validOperands);
        }
        return new Target(from, to, operand, unit);
    }

    private Address memoryAddress(JsonObject args, String name) {
        Address address = AddressCodec.parse(session.program().getAddressFactory(), getArgString(args, name));
        if (address == null || !address.isMemoryAddress()) {
            throw new IllegalArgumentException(name + " must be an explicit memory address (0x... or space:0x...)");
        }
        return address;
    }

    private static int operandIndex(JsonObject args) {
        JsonElement value = args == null ? null : args.get("operand_index");
        try {
            if (value != null && value.isJsonPrimitive() && value.getAsJsonPrimitive().isNumber()) {
                int operand = value.getAsBigDecimal().intValueExact();
                if (operand >= -1) return operand;
            }
        } catch (ArithmeticException | NumberFormatException e) {
            // The wire boundary must not round or wrap an index into another operand.
        }
        throw new IllegalArgumentException("operand_index is required and must be an integer of -1 or greater");
    }

    private static SourceType source(JsonObject args) {
        String name = getArgString(args, "source");
        if (name == null) return SourceType.USER_DEFINED;
        switch (name.toUpperCase(Locale.ROOT)) {
            case "USER_DEFINED": return SourceType.USER_DEFINED;
            case "ANALYSIS": return SourceType.ANALYSIS;
            case "IMPORTED": return SourceType.IMPORTED;
            case "DEFAULT": return SourceType.DEFAULT;
            default: throw new IllegalArgumentException("source must be USER_DEFINED, ANALYSIS, IMPORTED, or DEFAULT");
        }
    }

    private static RefType referenceType(String name) {
        if (name != null) {
            switch (name.toUpperCase(Locale.ROOT)) {
                case "DATA": return RefType.DATA;
                case "READ": return RefType.READ;
                case "WRITE": return RefType.WRITE;
                case "READ_WRITE": return RefType.READ_WRITE;
                case "INDIRECTION": return RefType.INDIRECTION;
                case "UNCONDITIONAL_CALL": return RefType.UNCONDITIONAL_CALL;
                case "CONDITIONAL_CALL": return RefType.CONDITIONAL_CALL;
                case "COMPUTED_CALL": return RefType.COMPUTED_CALL;
                case "UNCONDITIONAL_JUMP": return RefType.UNCONDITIONAL_JUMP;
                case "CONDITIONAL_JUMP": return RefType.CONDITIONAL_JUMP;
                case "COMPUTED_JUMP": return RefType.COMPUTED_JUMP;
            }
        }
        throw new IllegalArgumentException("ref_type is required: DATA, READ, WRITE, READ_WRITE, INDIRECTION, "
            + "UNCONDITIONAL_CALL, CONDITIONAL_CALL, COMPUTED_CALL, UNCONDITIONAL_JUMP, CONDITIONAL_JUMP, or COMPUTED_JUMP");
    }

    private static void requireOrdinaryMemory(Reference reference) {
        if (!reference.isMemoryReference() || reference.isOffsetReference() || reference.isShiftedReference()) {
            throw conflict("Only ordinary memory references can be edited; offset, shifted, and non-memory references are excluded", reference);
        }
        if (reference.getReferenceType() == RefType.FALL_THROUGH || reference.getReferenceType().isOverride()) {
            throw conflict("Fallthrough and override references require instruction flow editing", reference);
        }
    }

    private static void requireSource(Reference reference, SourceType expected) {
        if (reference.getSource() != expected) {
            throw conflict("Reference source mismatch: expected " + expected.name()
                + ", current " + reference.getSource().name(), reference);
        }
    }

    private static JsonProtocol.CommandException conflict(String message, Reference reference) {
        JsonObject detail = new JsonObject();
        detail.add("reference", referenceRow(reference));
        return new JsonProtocol.CommandException(message, detail);
    }

    private JsonArray operandReferences(Target target) throws ghidra.util.exception.CancelledException {
        JsonArray rows = new JsonArray();
        for (Reference reference : session.program().getReferenceManager()
                .getReferencesFrom(target.from, target.operand)) {
            session.monitor().checkCancelled();
            rows.add(referenceRow(reference));
        }
        return rows;
    }

    private static JsonObject referenceRow(Reference reference) {
        JsonObject row = new JsonObject();
        row.addProperty("from", AddressCodec.format(reference.getFromAddress()));
        row.addProperty("to", AddressCodec.format(reference.getToAddress()));
        row.addProperty("ref_type", reference.getReferenceType().toString());
        addReferenceMetadata(row, reference);
        return row;
    }

    private static JsonObject receipt(Target target, boolean changed, int count,
            JsonElement before, JsonElement after) {
        JsonObject result = new JsonObject();
        result.addProperty("from", AddressCodec.format(target.from));
        result.addProperty("to", AddressCodec.format(target.to));
        result.addProperty("operand_index", target.operand);
        result.addProperty("changed", changed);
        result.addProperty("count", count);
        result.add("before", before);
        result.add("after", after);
        return result;
    }

    private static final class Target {
        final Address from;
        final Address to;
        final int operand;
        final CodeUnit unit;

        Target(Address from, Address to, int operand, CodeUnit unit) {
            this.from = from;
            this.to = to;
            this.operand = operand;
            this.unit = unit;
        }
    }

    JsonObject handleXrefsTo(JsonObject args) throws ghidra.util.exception.CancelledException {
        if (session.program() == null) {
            return errorResult("No program loaded");
        }

        String addrStr = getArgString(args, "address");
        if (addrStr == null || addrStr.isEmpty()) {
            return errorResult("No address provided");
        }

        LinkedHashSet<Address> targetAddrs = addressResolver.resolveXrefTargets(addrStr);
        if (targetAddrs.isEmpty()) {
            return errorResult(functionQueries.buildFunctionTargetHint(addrStr));
        }

        JsonArray xrefs = new JsonArray();
        ReferenceManager refMgr = session.program().getReferenceManager();
        FunctionManager fm = session.program().getFunctionManager();
        SymbolTable st = session.program().getSymbolTable();
        Set<String> seen = new HashSet<>();

        for (Address addr : targetAddrs) {
            session.monitor().checkCancelled();
            for (Reference ref : refMgr.getReferencesTo(addr)) {
                session.monitor().checkCancelled();
                Address fromAddr = ref.getFromAddress();
                String dedupKey = AddressCodec.format(fromAddr) + "|" + AddressCodec.format(addr)
                    + "|" + ref.getOperandIndex() + "|" + ref.getReferenceType();
                if (!seen.add(dedupKey)) continue;

                Function fromFunc = fm.getFunctionContaining(fromAddr);
                Function toFunc = fm.getFunctionContaining(addr);

                JsonObject xrefData = referenceRow(ref);
                if (fromFunc != null) {
                    xrefData.addProperty("from_function", fromFunc.getName());
                } else {
                    xrefData.add("from_function", JsonNull.INSTANCE);
                }
                if (toFunc != null) {
                    xrefData.addProperty("to_function", toFunc.getName());
                } else {
                    Symbol toSym = st.getPrimarySymbol(addr);
                    if (toSym != null) {
                        xrefData.addProperty("to_function", toSym.getName());
                    } else {
                        xrefData.add("to_function", JsonNull.INSTANCE);
                    }
                }
                xrefs.add(xrefData);
            }
        }

        JsonObject result = new JsonObject();
        result.add("xrefs", xrefs);
        result.addProperty("count", xrefs.size());
        return result;
    }

    JsonObject handleXrefsFrom(JsonObject args) throws ghidra.util.exception.CancelledException {
        if (session.program() == null) return errorResult("No program loaded");

        String target = getArgString(args, "address");
        if (target == null || target.isEmpty()) return errorResult("No address provided");

        JsonArray xrefs = new JsonArray();
        if (getArgBool(args, "function", false)) {
            Function function = functionQueries.findFunctionByNameOrAddress(target);
            if (function == null) return errorResult(functionQueries.buildFunctionTargetHint(target));
            ghidra.program.model.address.AddressIterator addresses = function.getBody().getAddresses(true);
            while (addresses.hasNext()) {
                session.monitor().checkCancelled();
                appendReferencesFrom(addresses.next(), xrefs);
            }
        } else {
            Address address = addressResolver.resolveAddress(target);
            if (address == null) return errorResult(functionQueries.buildFunctionTargetHint(target));
            appendReferencesFrom(address, xrefs);
        }

        JsonObject result = new JsonObject();
        result.add("xrefs", xrefs);
        result.addProperty("count", xrefs.size());
        return result;
    }

    private void appendReferencesFrom(Address address, JsonArray xrefs)
            throws ghidra.util.exception.CancelledException {
        FunctionManager functions = session.program().getFunctionManager();
        Function fromFunction = functions.getFunctionContaining(address);
        for (Reference reference : session.program().getReferenceManager().getReferencesFrom(address)) {
            session.monitor().checkCancelled();
            Address destination = reference.getToAddress();
            Function toFunction = functions.getFunctionContaining(destination);
            JsonObject row = referenceRow(reference);
            row.addProperty("from_function", fromFunction == null ? null : fromFunction.getName());
            row.addProperty("to_function", toFunction == null ? null : toFunction.getName());
            xrefs.add(row);
        }
    }

    private static void addReferenceMetadata(JsonObject row, Reference reference) {
        row.addProperty("operand_index", reference.getOperandIndex());
        row.addProperty("source", reference.getSource().name());
        row.addProperty("primary", reference.isPrimary());
    }
}
