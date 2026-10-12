package ghidracli.function;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.AbstractFloatDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.task.TaskMonitor;
import ghidracli.query.AddressCodec;
import ghidracli.query.IntegerLiteral;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Set;

/** Byte locations for function values. External offsets follow the value's memory representation. */
public final class VariableStorageCodec {
    private VariableStorageCodec() {}

    private static boolean usable(Register register) {
        return !register.isProcessorContext() && !register.isZero()
            && register.getBitLength() > 0 && register.getBitLength() % 8 == 0
            && register.getLeastSignificantBit() % 8 == 0;
    }

    private static Register register(Program program, String name) {
        Register register = program.getRegister(name);
        if (register == null || !usable(register)) {
            throw new IllegalArgumentException("Not a byte-addressable ABI register: " + name
                + "; use program list-registers for this program's register names and widths");
        }
        return register;
    }

    public static JsonArray registers(Program program, TaskMonitor monitor) throws Exception {
        List<Register> registers = new ArrayList<>(program.getLanguage().getRegisters());
        registers.sort(Comparator.comparing(Register::getName));
        JsonArray rows = new JsonArray();
        for (Register register : registers) {
            monitor.checkCancelled();
            if (!usable(register)) continue;
            JsonObject row = new JsonObject();
            row.addProperty("name", register.getName());
            row.addProperty("bit_length", register.getBitLength());
            row.addProperty("size", register.getMinimumByteSize());
            row.addProperty("address", AddressCodec.format(register.getAddress()));
            row.addProperty("base_register", register.getBaseRegister().getName());
            rows.add(row);
        }
        return rows;
    }

    private record Piece(int offset, int size, String kind, String register, int stackOffset) {}

    static VariableStorage decode(Program program, DataType type, JsonArray input,
            TaskMonitor monitor) throws Exception {
        if (VoidDataType.isVoidDataType(type)) {
            throw new IllegalArgumentException("A void return has no storage; omit its location");
        }
        if (type.getLength() <= 0) throw new IllegalArgumentException("Storage requires a fixed positive type size");
        if (input.isEmpty()) throw new IllegalArgumentException("Storage requires at least one location");
        List<Piece> pieces = new ArrayList<>();
        boolean simple = false;
        for (JsonElement element : input) {
            monitor.checkCancelled();
            JsonObject value = element.getAsJsonObject();
            String kind = text(value, "kind");
            if (!kind.equals("register") && !kind.equals("stack")) {
                throw new IllegalArgumentException("Storage kind must be register or stack");
            }
            keys(value, kind.equals("register")
                ? Set.of("kind", "register", "value_offset", "size")
                : Set.of("kind", "stack_offset", "value_offset", "size"));
            boolean explicit = value.has("value_offset") || value.has("size");
            int offset = explicit ? integer(value, "value_offset", 0, Integer.MAX_VALUE) : 0;
            int size = explicit ? integer(value, "size", 1, Integer.MAX_VALUE) : type.getLength();
            simple |= !explicit;
            pieces.add(new Piece(offset, size, kind,
                kind.equals("register") ? text(value, "register") : null,
                kind.equals("stack") ? integer(value, "stack_offset", Integer.MIN_VALUE, Integer.MAX_VALUE) : 0));
        }
        if (simple && pieces.size() != 1) {
            throw new IllegalArgumentException("Use one simple location or a complete set of storage pieces");
        }
        pieces.sort(Comparator.comparingInt(Piece::offset));
        long end = 0;
        List<Varnode> nodes = new ArrayList<>();
        for (Piece piece : pieces) {
            monitor.checkCancelled();
            if (piece.offset() != end) {
                throw new IllegalArgumentException("Storage pieces must cover consecutive bytes starting at 0 without gaps or overlaps");
            }
            end += piece.size();
            if (end > Integer.MAX_VALUE) throw new IllegalArgumentException("Storage is too large");
            if (piece.kind().equals("register")) {
                Register register = register(program, piece.register());
                if (piece.size() > register.getMinimumByteSize()) {
                    throw new IllegalArgumentException("Storage piece does not fit register " + register.getName());
                }
                Address start = lowAddress(register, piece.size());
                nodes.add(new Varnode(start, piece.size()));
            } else {
                var stack = program.getCompilerSpec().getStackSpace();
                if (stack == null || !stack.isStackSpace()) throw new IllegalArgumentException("Compiler specification has no stack space");
                long last = (long) piece.stackOffset() + piece.size() - 1;
                if (last > Integer.MAX_VALUE) throw new IllegalArgumentException("Stack interval exceeds signed stack offsets");
                Address start = stack.getAddress(piece.stackOffset());
                start.addNoWrap(piece.size() - 1L);
                nodes.add(new Varnode(start, piece.size()));
            }
        }
        // Native compound storage and join records use significance order. Convert
        // memory-layout offsets to that order (see VariableStorage.getRegisterOffset).
        if (!program.getLanguage().isBigEndian()) Collections.reverse(nodes);
        boolean extendedFloat = pieces.size() == 1 && pieces.get(0).kind().equals("register")
            && floatType(type) && end >= type.getLength();
        if (end != type.getLength() && !extendedFloat) {
            throw new IllegalArgumentException("Storage size " + end + " does not match type size " + type.getLength());
        }
        return new VariableStorage(program, nodes);
    }

    private static boolean floatType(DataType type) {
        while (type instanceof TypeDef alias) type = alias.getBaseDataType();
        return type instanceof AbstractFloatDataType;
    }

    private static Address lowAddress(Register register, int size) {
        return register.isBigEndian()
            ? register.getAddress().add(register.getMinimumByteSize() - size) : register.getAddress();
    }

    static JsonArray encode(Program program, VariableStorage storage) {
        JsonArray result = new JsonArray();
        Varnode[] nodes = storage.getVarnodes();
        int offset = 0;
        for (int i = 0; i < nodes.length; i++) {
            Varnode node = nodes[program.getLanguage().isBigEndian() ? i : nodes.length - 1 - i];
            JsonObject piece = new JsonObject();
            piece.addProperty("value_offset", offset);
            piece.addProperty("size", node.getSize());
            piece.addProperty("address", AddressCodec.format(node.getAddress()));
            if (node.getAddress().isStackAddress()) {
                piece.addProperty("kind", "stack");
                piece.addProperty("stack_offset", node.getOffset());
            } else {
                // Native ABI registers may live in a memory space (for example
                // PIC24 W0). Identify the register before classifying its address.
                Register register = program.getRegister(node.getAddress(), node.getSize());
                if (register == null || register.getMinimumByteSize() < node.getSize()
                        || !lowAddress(register, node.getSize()).equals(node.getAddress())) {
                    register = program.getLanguage().getRegisters().stream()
                        .filter(r -> usable(r) && r.getMinimumByteSize() >= node.getSize()
                            && lowAddress(r, node.getSize()).equals(node.getAddress()))
                        .min(Comparator.comparingInt(Register::getMinimumByteSize).thenComparing(Register::getName))
                        .orElse(null);
                }
                if (register != null || node.getAddress().isRegisterAddress()) {
                    piece.addProperty("kind", "register");
                    piece.addProperty("register", register == null ? null : register.getName());
                } else {
                    piece.addProperty("kind", node.getAddress().getAddressSpace().getName());
                }
            }
            result.add(piece);
            offset += node.getSize();
        }
        return result;
    }

    static String text(JsonObject object, String field) {
        JsonElement value = object.get(field);
        if (value == null || !value.isJsonPrimitive() || !value.getAsJsonPrimitive().isString()
                || value.getAsString().isBlank()) throw new IllegalArgumentException(field + " must be a nonempty string");
        return value.getAsString();
    }

    static int integer(JsonObject object, String field, int minimum, int maximum) {
        JsonElement value = object.get(field);
        if (value == null || !value.isJsonPrimitive()) throw new IllegalArgumentException(field + " must be an integer");
        int number;
        try { number = IntegerLiteral.parse(value.getAsString()).intValueExact(); }
        catch (RuntimeException invalid) { throw new IllegalArgumentException(field + " must be a decimal or 0x integer in [" + minimum + ", " + maximum + "]"); }
        if (number < minimum || number > maximum) throw new IllegalArgumentException(field + " is out of range");
        return number;
    }

    static void keys(JsonObject object, Set<String> allowed) {
        for (String key : object.keySet()) if (!allowed.contains(key)) throw new IllegalArgumentException("Unknown storage field: " + key);
    }
}
