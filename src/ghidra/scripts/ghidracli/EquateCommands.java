package ghidracli;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import ghidra.program.database.symbol.EquateManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.DynamicHash;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Equate;
import ghidra.program.model.symbol.EquateReference;
import ghidra.program.model.symbol.EquateTable;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import static ghidracli.JsonProtocol.getArgString;
import static ghidracli.JsonProtocol.getNonnegativeIntArg;

/** Named integer definitions and narrowly selected instruction uses. */
final class EquateCommands {
    private final ProgramSession session;

    EquateCommands(ProgramSession session) {
        this.session = session;
    }

    JsonObject handleList(JsonObject args) throws Exception {
        EquateTable table = table();
        int limit = getNonnegativeIntArg(args, "limit", 0);
        List<Equate> all = new ArrayList<>();
        Iterator<Equate> iterator = table.getEquates();
        while (iterator.hasNext()) {
            session.monitor().checkCancelled();
            all.add(iterator.next());
        }
        all.sort(Comparator.comparing(Equate::getName));
        JsonArray rows = new JsonArray();
        for (Equate equate : all) {
            session.monitor().checkCancelled();
            if (limit > 0 && rows.size() >= limit) break;
            rows.add(definition(equate));
        }
        JsonObject result = new JsonObject();
        result.add("equates", rows);
        result.addProperty("count", rows.size());
        return result;
    }

    JsonObject handleGet(JsonObject args) throws Exception {
        Equate equate = requireEquate(args);
        JsonObject result = definition(equate);
        List<Reference> references = new ArrayList<>();
        Map<Address, Map<Integer, Integer>> counts = new HashMap<>();
        for (EquateReference reference : equate.getReferences()) {
            session.monitor().checkCancelled();
            references.add(new Reference(equate, reference));
            counts.computeIfAbsent(reference.getAddress(), key -> new HashMap<>())
                .merge((int) reference.getOpIndex(), 1, Integer::sum);
        }
        references.sort(Comparator.comparing((Reference ref) -> ref.address)
            .thenComparingInt(ref -> ref.operand).thenComparingLong(ref -> ref.hash));
        JsonArray rows = new JsonArray();
        for (Reference reference : references) {
            session.monitor().checkCancelled();
            JsonObject row = reference.toJson();
            int selected = counts.get(reference.address).get(reference.operand);
            row.addProperty("operand_selectable", reference.operand >= 0 && selected == 1);
            rows.add(row);
        }
        result.add("references", rows);
        return result;
    }

    JsonObject handleCreate(JsonObject args) throws Exception {
        EquateTable table = table();
        String name = name(args);
        if (name.startsWith(EquateManager.DATATYPE_TAG)) {
            throw new IllegalArgumentException("Equate names beginning with '"
                + EquateManager.DATATYPE_TAG + "' are reserved for enum-backed definitions");
        }
        long value = value(args);
        Equate equate = table.getEquate(name);
        boolean created = equate == null;
        if (!created && equate.getValue() != value) {
            JsonObject detail = new JsonObject();
            detail.add("existing", definition(equate));
            throw new JsonProtocol.CommandException("Equate '" + name
                + "' already has a different value", detail);
        }
        session.monitor().checkCancelled();
        if (created) equate = table.createEquate(name, value);
        if (equate == null) throw new IllegalStateException("Failed to create equate '" + name + "'");
        session.monitor().checkCancelled();
        JsonObject result = definition(equate);
        result.addProperty("status", "created");
        result.addProperty("created", created);
        return result;
    }

    JsonObject handleAttach(JsonObject args) throws Exception {
        Equate equate = requireOrdinary(args);
        Instruction instruction = instruction(args);
        int operand = operand(args, instruction);
        Address address = instruction.getAddress();
        validateScalar(instruction, operand, equate.getValue());
        List<Reference> before = referencesAt(address);
        List<Reference> selected = selected(before, equate.getName(), operand);
        if (selected.size() > 1) throw conflict("Multiple equate references select this operand", before);
        for (Reference reference : before) {
            if (reference.operand == operand && !reference.name.equals(equate.getName())) {
                throw conflict("Another equate is attached to the selected operand", before);
            }
        }
        if (selected.size() == 1) return attachment(equate, address, operand, "attached", 0);

        long[] hashes = DynamicHash.calcConstantHash(instruction, equate.getValue());
        long hash = hashes.length == 1 ? hashes[0] : 0;
        for (Reference reference : before) {
            // Native insertion replaces matching hashes across the entire instruction.
            if ((hash != 0 && reference.hash == hash)
                    || (hash == 0 && reference.hash == 0 && reference.operand == operand)) {
                throw conflict("Attaching this equate would replace an existing reference", before);
            }
        }
        session.monitor().checkCancelled();
        equate.addReference(address, operand);
        List<Reference> expected = new ArrayList<>(before);
        expected.add(new Reference(equate.getName(), equate.getValue(), address, operand, hash));
        verifyReferences(address, expected);
        return attachment(equate, address, operand, "attached", 1);
    }

    JsonObject handleDetach(JsonObject args) throws Exception {
        Equate equate = requireOrdinary(args);
        Instruction instruction = instruction(args);
        int operand = operand(args, instruction);
        Address address = instruction.getAddress();
        List<Reference> before = referencesAt(address);
        List<Reference> selected = selected(before, equate.getName(), operand);
        if (selected.size() > 1) throw conflict("Multiple equate references select this operand", before);
        if (selected.isEmpty()) {
            for (Reference reference : before) {
                if (reference.name.equals(equate.getName()) && reference.operand < 0) {
                    throw conflict("A dynamic-only equate reference cannot be selected by operand", before);
                }
            }
            return attachment(equate, address, operand, "detached", 0);
        }
        session.monitor().checkCancelled();
        equate.removeReference(address, operand);
        List<Reference> expected = new ArrayList<>(before);
        expected.remove(selected.get(0));
        verifyReferences(address, expected);
        return attachment(equate, address, operand, "detached", 1);
    }

    JsonObject handleDelete(JsonObject args) throws Exception {
        Equate equate = requireOrdinary(args);
        JsonObject result = definition(equate);
        String name = equate.getName();
        int count = equate.getReferenceCount();
        session.monitor().checkCancelled();
        if (!table().removeEquate(name) || table().getEquate(name) != null) {
            throw new IllegalStateException("Failed to delete equate '" + name + "'");
        }
        session.monitor().checkCancelled();
        result.addProperty("status", "deleted");
        result.addProperty("references_removed", count);
        return result;
    }

    private EquateTable table() {
        if (session.program() == null) throw new IllegalArgumentException("No program loaded");
        return session.program().getEquateTable();
    }

    private static String name(JsonObject args) {
        String name = getArgString(args, "name");
        if (name == null || name.isBlank()) throw new IllegalArgumentException("Equate name required");
        return name;
    }

    private Equate requireEquate(JsonObject args) {
        EquateTable table = table();
        String name = name(args);
        Equate equate = table.getEquate(name);
        if (equate == null) throw new IllegalArgumentException("No equate named '" + name + "'");
        return equate;
    }

    private Equate requireOrdinary(JsonObject args) {
        Equate equate = requireEquate(args);
        if (equate.isEnumBased()) throw new IllegalArgumentException("Enum-backed equates cannot be edited");
        return equate;
    }

    private static long value(JsonObject args) {
        JsonElement raw = args == null ? null : args.get("value");
        String error = "value must be a signed 64-bit decimal/hex integer or an unsigned 64-bit 0x-prefixed bit pattern";
        if (raw == null || !raw.isJsonPrimitive() || !raw.getAsJsonPrimitive().isString()) {
            throw new IllegalArgumentException(error);
        }
        String text = raw.getAsString();
        try {
            BigInteger number = IntegerLiteral.parse(text);
            if (text.startsWith("0x") || text.startsWith("0X")) {
                if (number.bitLength() <= 64) return number.longValue();
            } else {
                return number.longValueExact();
            }
        } catch (NumberFormatException | ArithmeticException ignored) {
            // Report the operand's range together with its accepted spelling.
        }
        throw new IllegalArgumentException(error);
    }

    private Instruction instruction(JsonObject args) {
        String text = getArgString(args, "address");
        Address address = AddressCodec.parse(session.program().getAddressFactory(), text);
        if (address == null) throw new IllegalArgumentException("An explicit instruction address is required");
        Instruction instruction = session.program().getListing().getInstructionAt(address);
        if (instruction == null) throw new IllegalArgumentException("No instruction starts at " + AddressCodec.format(address));
        return instruction;
    }

    private static int operand(JsonObject args, Instruction instruction) {
        int operand = getNonnegativeIntArg(args, "operand_index", -1);
        if (operand < 0 || operand >= instruction.getNumOperands()) {
            throw new IllegalArgumentException("operand_index must select an existing nonnegative instruction operand");
        }
        return operand;
    }

    private void validateScalar(Instruction instruction, int operand, long value) throws Exception {
        int selectedCount = 0;
        int matches = 0;
        Scalar selected = null;
        JsonArray candidates = new JsonArray();
        for (int index = 0; index < instruction.getNumOperands(); index++) {
            for (Object object : instruction.getOpObjects(index)) {
                session.monitor().checkCancelled();
                if (!(object instanceof Scalar)) continue;
                Scalar scalar = (Scalar) object;
                if (index == operand) { selectedCount++; selected = scalar; }
                if (scalar.getValue() == value) matches++;
                JsonObject row = new JsonObject();
                row.addProperty("operand_index", index);
                row.addProperty("value", hex(scalar.getUnsignedValue()));
                row.addProperty("signed_value", Long.toString(scalar.getSignedValue()));
                row.addProperty("bits", scalar.bitLength());
                row.addProperty("signed", scalar.isSigned());
                candidates.add(row);
            }
        }
        String error = selectedCount != 1 ? "Selected operand must contain exactly one scalar"
            : selected.getValue() != value ? "Equate value does not match the scalar's width and signedness"
            : matches != 1 ? "The same scalar value occurs multiple times in this instruction" : null;
        if (error != null) {
            JsonObject detail = new JsonObject();
            detail.add("candidates", candidates);
            throw new JsonProtocol.CommandException(error, detail);
        }
    }

    private List<Reference> referencesAt(Address address) throws Exception {
        List<Reference> references = new ArrayList<>();
        Set<String> names = new HashSet<>();
        for (Equate equate : table().getEquates(address)) {
            session.monitor().checkCancelled();
            // Ghidra returns a definition once for each reference at this address.
            if (!names.add(equate.getName())) continue;
            for (EquateReference reference : equate.getReferences(address)) {
                session.monitor().checkCancelled();
                references.add(new Reference(equate, reference));
            }
        }
        return references;
    }

    private static List<Reference> selected(List<Reference> references, String name, int operand) {
        List<Reference> selected = new ArrayList<>();
        for (Reference reference : references) {
            if (reference.name.equals(name) && reference.operand == operand) selected.add(reference);
        }
        return selected;
    }

    private void verifyReferences(Address address, List<Reference> expected) throws Exception {
        List<Reference> remaining = referencesAt(address);
        for (Reference reference : expected) {
            if (!remaining.remove(reference)) {
                throw new IllegalStateException("Equate edit changed an unselected reference; rolling back");
            }
        }
        if (!remaining.isEmpty()) throw new IllegalStateException("Equate edit produced unexpected references; rolling back");
        session.monitor().checkCancelled();
    }

    private static JsonProtocol.CommandException conflict(String message, List<Reference> references) {
        JsonObject detail = new JsonObject();
        JsonArray rows = new JsonArray();
        for (Reference reference : references) {
            JsonObject row = reference.toJson();
            row.addProperty("name", reference.name);
            rows.add(row);
        }
        detail.add("references", rows);
        return new JsonProtocol.CommandException(message, detail);
    }

    private static String hex(long value) { return "0x" + Long.toHexString(value); }

    private static JsonObject definition(Equate equate) {
        JsonObject result = new JsonObject();
        result.addProperty("name", equate.getName());
        result.addProperty("value", hex(equate.getValue()));
        result.addProperty("signed_value", Long.toString(equate.getValue()));
        result.addProperty("kind", equate.isEnumBased() ? "enum" : "ordinary");
        result.addProperty("reference_count", equate.getReferenceCount());
        return result;
    }

    private static JsonObject attachment(Equate equate, Address address, int operand, String action, int count) {
        JsonObject result = definition(equate);
        result.addProperty("status", action);
        result.addProperty("address", AddressCodec.format(address));
        result.addProperty("operand_index", operand);
        result.addProperty(action, count);
        return result;
    }

    /** Detached reference values survive native replacement/deletion of their DB records. */
    private record Reference(String name, long value, Address address, int operand, long hash) {
        Reference(Equate equate, EquateReference reference) {
            this(equate.getName(), equate.getValue(), reference.getAddress(),
                reference.getOpIndex(), reference.getDynamicHashValue());
        }

        JsonObject toJson() {
            JsonObject result = new JsonObject();
            result.addProperty("address", AddressCodec.format(address));
            if (operand < 0) result.add("operand_index", JsonNull.INSTANCE);
            else result.addProperty("operand_index", operand);
            result.addProperty("dynamic_hash", hex(hash));
            return result;
        }
    }
}
