package ghidracli.analysis;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidracli.protocol.JsonProtocol;
import ghidracli.query.AddressCodec;
import ghidracli.query.AddressResolver;
import ghidracli.session.ProgramSession;

/** Bounded reads of explicitly selected ABI layouts; never searches for table boundaries. */
final class VtableReader {
    private static final int MAX_ENTRIES = 65536;

    private final ProgramSession session;
    private final AddressResolver addresses;

    VtableReader(ProgramSession session, AddressResolver addresses) {
        this.session = session;
        this.addresses = addresses;
    }

    JsonObject read(JsonObject args) throws Exception {
        String target = string(args, "target", null);
        String abi = string(args, "abi", null);
        String encoding = string(args, "encoding", "absolute");
        if (!abi.equals("itanium") && !abi.equals("msvc")) {
            throw new IllegalArgumentException("abi must be itanium or msvc");
        }
        if (!encoding.equals("absolute") && !encoding.equals("relative32")) {
            throw new IllegalArgumentException("encoding must be absolute or relative32");
        }
        boolean relative = encoding.equals("relative32");
        if (relative && !abi.equals("itanium")) {
            throw new IllegalArgumentException("relative32 encoding requires the itanium ABI");
        }
        int count = JsonProtocol.getNonnegativeIntArg(args, "entries", 0);
        if (count < 1 || count > MAX_ENTRIES) {
            throw new IllegalArgumentException("entries must be an integer from 1 to " + MAX_ENTRIES);
        }
        int pointerSize = session.program().getDefaultPointerSize();
        if (pointerSize != 4 && pointerSize != 8) {
            throw new IllegalArgumentException("Vtable layouts require 4-byte or 8-byte native pointers");
        }
        Address address = addresses.resolveAddress(target);
        if (address == null || !address.isMemoryAddress()) {
            throw new IllegalArgumentException("Invalid vtable address point: " + target);
        }
        if (address.getAddressSpace().getAddressableUnitSize() != 1) {
            throw new IllegalArgumentException("Vtable layouts require byte-addressed memory");
        }
        int entrySize = relative ? 4 : pointerSize;
        try {
            VtableHeaders.shift(address, (long) count * entrySize - 1);
        } catch (AddressOverflowException e) {
            throw new IllegalArgumentException("Requested vtable entries exceed the address space");
        }

        VtableHeaders reader = new VtableHeaders(session);
        JsonObject result = new JsonObject();
        result.addProperty("address", AddressCodec.format(address));
        result.addProperty("abi", abi);
        result.addProperty("encoding", encoding);
        result.addProperty("pointer_size", pointerSize);
        result.addProperty("entry_size", entrySize);
        result.addProperty("endian", session.program().getMemory().isBigEndian() ? "big" : "little");
        result.addProperty("requested_entries", count);
        result.add("header", abi.equals("itanium")
            ? reader.itanium(address, relative) : reader.msvc(address));

        JsonArray entries = new JsonArray();
        int read = 0;
        for (int index = 0; index < count; index++) {
            session.monitor().checkCancelled();
            long offset = (long) index * entrySize;
            JsonObject entry = relative
                ? reader.relative(address, offset, address)
                : reader.absolute(address, offset, pointerSize);
            entry.addProperty("index", index);
            entry.addProperty("offset", offset);
            if (entry.get("readable").getAsBoolean()) read++;
            entries.add(entry);
        }
        result.addProperty("read_entries", read);
        result.addProperty("complete", read == count);
        result.add("entries", entries);
        return result;
    }

    private static String string(JsonObject args, String name, String defaultValue) {
        JsonElement value = args == null ? null : args.get(name);
        if (value == null || value.isJsonNull()) {
            if (defaultValue != null) return defaultValue;
            throw new IllegalArgumentException(name + " required");
        }
        if (!value.isJsonPrimitive() || !value.getAsJsonPrimitive().isString()
                || value.getAsString().isBlank()) {
            throw new IllegalArgumentException(name + " must be a non-empty string");
        }
        return value.getAsString();
    }
}
