package ghidracli;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.OverlayAddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.ProgramContext;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.TreeSet;
import static ghidracli.JsonProtocol.errorResult;

/** Stored processor context and language defaults, without initiating analysis. */
final class ProgramContextCommands {
    private final ProgramSession session;

    ProgramContextCommands(ProgramSession session) {
        this.session = session;
    }

    JsonObject handleList(JsonObject args) throws Exception {
        if (session.program() == null) return errorResult("No program loaded");
        var registers = new ArrayList<>(session.program().getProgramContext().getContextRegisters());
        registers.sort(Comparator.comparing(Register::getName));
        JsonArray rows = new JsonArray();
        for (Register register : registers) {
            session.monitor().checkCancelled();
            JsonObject row = new JsonObject();
            row.addProperty("name", register.getName());
            row.addProperty("bit_length", register.getBitLength());
            rows.add(row);
        }
        JsonObject result = new JsonObject();
        result.addProperty("count", rows.size());
        result.add("registers", rows);
        return result;
    }

    JsonObject handleGet(JsonObject args) throws Exception {
        if (session.program() == null) return errorResult("No program loaded");
        Register register = requireRegister(args);
        Address[] range = requireRange(args, false);
        return describe(register, range[0], range[1]);
    }

    JsonObject handleSet(JsonObject args) throws Exception {
        return mutate(args, false);
    }

    JsonObject handleClear(JsonObject args) throws Exception {
        return mutate(args, true);
    }

    private JsonObject mutate(JsonObject args, boolean clear) throws Exception {
        if (session.program() == null) return errorResult("No program loaded");
        Register register = requireRegister(args);
        Address[] range = requireRange(args, true);
        BigInteger value = clear ? null : requireValue(args, register);
        session.monitor().checkCancelled();
        ProgramContext context = session.program().getProgramContext();
        try {
            // Native subregister operations preserve sibling bits. ProgramSession owns rollback/save.
            if (clear) context.remove(range[0], range[1], register);
            else context.setValue(register, range[0], range[1], value);
        } catch (ContextChangeException error) {
            JsonObject detail = receipt(register, range[0], range[1]);
            detail.addProperty("reason", error.getMessage());
            detail.addProperty("hint", "Inspect existing instructions, then use listing undefine before changing context; define code separately afterwards.");
            throw new JsonProtocol.CommandException("Cannot change processor context: "
                + error.getMessage(), detail);
        }
        JsonObject result = describe(register, range[0], range[1]);
        result.addProperty("status", clear ? "cleared" : "set");
        return result;
    }

    private Register requireRegister(JsonObject args) {
        String name = requireString(args, "register");
        for (Register register : session.program().getProgramContext().getContextRegisters()) {
            if (register.getName().equals(name)) return register;
        }
        throw new IllegalArgumentException("Unknown processor context register: " + name);
    }

    private Address[] requireRange(JsonObject args, boolean requireEnd) {
        var factory = session.program().getAddressFactory();
        Address start = AddressCodec.parse(factory, requireString(args, "start"));
        Address end = requireEnd || args.has("end")
            ? AddressCodec.parse(factory, requireString(args, "end")) : start;
        if (start == null || end == null) {
            throw new IllegalArgumentException("start and end require explicit 0x-prefixed addresses");
        }
        if (!start.isMemoryAddress() || !end.isMemoryAddress()) {
            throw new IllegalArgumentException("Processor context requires memory-space addresses");
        }
        if (!start.getAddressSpace().equals(end.getAddressSpace())) {
            throw new IllegalArgumentException("start and end must be in the same address space");
        }
        if (start.compareTo(end) > 0) {
            throw new IllegalArgumentException("end must not precede start");
        }
        // Context describes the address space, including currently unmapped memory addresses.
        return new Address[] {start, end};
    }

    private static String requireString(JsonObject args, String key) {
        JsonElement value = args == null ? null : args.get(key);
        if (value == null || !value.isJsonPrimitive() || !value.getAsJsonPrimitive().isString()) {
            throw new IllegalArgumentException(key + " must be a string");
        }
        return value.getAsString();
    }

    private static BigInteger requireValue(JsonObject args, Register register) {
        String text = requireString(args, "value");
        BigInteger value = IntegerLiteral.parse(text);
        if (value.signum() < 0)
            throw new IllegalArgumentException("value must be a nonnegative decimal or 0x-prefixed integer");
        if (value.bitLength() > register.getBitLength()) {
            throw new IllegalArgumentException("value does not fit processor context register "
                + register.getName() + " (" + register.getBitLength() + " bits)");
        }
        return value;
    }

    private JsonObject describe(Register register, Address start, Address end) throws Exception {
        ProgramContext context = session.program().getProgramContext();
        TreeSet<Address> boundaries = new TreeSet<>();
        boundaries.add(start);
        addBoundaries(boundaries, context.getRegisterValueAddressRanges(register, start, end),
            start, end);
        // Native default lookup translates overlay addresses, but its range iterator does not.
        Address defaultStart = start;
        Address defaultEnd = end;
        if (start.getAddressSpace() instanceof OverlayAddressSpace overlay) {
            defaultStart = overlay.translateAddress(start, true);
            defaultEnd = overlay.translateAddress(end, true);
        }
        addBoundaries(boundaries,
            context.getDefaultRegisterValueAddressRanges(register, defaultStart, defaultEnd),
            start, end);

        JsonArray rows = new JsonArray();
        JsonObject previous = null;
        for (Address cursor : boundaries) {
            session.monitor().checkCancelled();
            Address next = boundaries.higher(cursor);
            Address rangeEnd = next == null ? end : next.previous();
            JsonObject stored = bits(context.getNonDefaultValue(register, cursor));
            JsonObject defaults = bits(context.getDefaultValue(register, cursor));
            JsonObject effective = bits(context.getRegisterValue(register, cursor));
            if (previous != null && stored.equals(previous.get("stored"))
                    && defaults.equals(previous.get("default"))
                    && effective.equals(previous.get("effective"))) {
                previous.addProperty("end", AddressCodec.format(rangeEnd));
                continue;
            }
            JsonObject row = new JsonObject();
            row.addProperty("start", AddressCodec.format(cursor));
            row.addProperty("end", AddressCodec.format(rangeEnd));
            row.add("stored", stored);
            row.add("default", defaults);
            row.add("effective", effective);
            rows.add(row);
            previous = row;
        }
        JsonObject result = receipt(register, start, end);
        result.add("ranges", rows);
        return result;
    }

    private void addBoundaries(TreeSet<Address> boundaries, AddressRangeIterator ranges,
            Address start, Address end) throws Exception {
        AddressSpace space = start.getAddressSpace();
        for (AddressRange range : ranges) {
            session.monitor().checkCancelled();
            Address first = space.getAddressInThisSpaceOnly(range.getMinAddress().getOffset());
            Address last = space.getAddressInThisSpaceOnly(range.getMaxAddress().getOffset());
            if (first.compareTo(start) > 0 && first.compareTo(end) <= 0) boundaries.add(first);
            if (last.compareTo(start) >= 0 && last.compareTo(end) < 0) boundaries.add(last.next());
        }
    }

    private static JsonObject bits(RegisterValue value) {
        BigInteger mask = value == null ? BigInteger.ZERO : value.getValueMask();
        BigInteger number = value == null ? BigInteger.ZERO : value.getUnsignedValueIgnoreMask().and(mask);
        JsonObject result = new JsonObject();
        result.addProperty("value", "0x" + number.toString(16));
        result.addProperty("mask", "0x" + mask.toString(16));
        return result;
    }

    private static JsonObject receipt(Register register, Address start, Address end) {
        JsonObject result = new JsonObject();
        result.addProperty("register", register.getName());
        result.addProperty("bit_length", register.getBitLength());
        result.addProperty("start", AddressCodec.format(start));
        result.addProperty("end", AddressCodec.format(end));
        return result;
    }
}
