package ghidracli.analysis;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.mem.ByteMemBufferImpl;
import ghidra.program.model.mem.MemoryAccessException;
import ghidracli.memory.PointerValues;
import ghidracli.query.AddressCodec;
import ghidracli.session.ProgramSession;
import java.math.BigInteger;

/** Reads ABI fields without registering data types, applying markup, or validating a class graph. */
final class VtableHeaders {
    private final ProgramSession session;
    private final PointerValues pointers;

    VtableHeaders(ProgramSession session) {
        this.session = session;
        this.pointers = new PointerValues(session);
    }

    JsonObject itanium(Address addressPoint, boolean relative) throws Exception {
        int width = relative ? 4 : session.program().getDefaultPointerSize();
        JsonObject header = new JsonObject();
        JsonObject offset = scalar(addressPoint, -2L * width, width, true);
        header.add("offset_to_top", offset);
        boolean complete = readable(offset);
        if (!relative) {
            JsonObject rtti = absolute(addressPoint, -width, width);
            header.add("rtti", rtti);
            complete &= readable(rtti);
        } else {
            // LLVM CGVTables::addRelativeComponent uses the address point for every
            // relative component, including the RTTI proxy (not the component address).
            JsonObject reference = relative(addressPoint, -4, addressPoint);
            header.add("rtti_reference", reference);
            complete &= readable(reference) && !reference.has("error");
            Address proxy = target(reference);
            if (proxy == null || isNull(reference)) {
                header.add("rtti", null);
            } else {
                JsonObject rtti = absolute(proxy, 0, session.program().getDefaultPointerSize());
                header.add("rtti", rtti);
                complete &= readable(rtti);
            }
        }
        header.addProperty("complete", complete);
        return header;
    }

    JsonObject msvc(Address addressPoint) throws Exception {
        int width = session.program().getDefaultPointerSize();
        JsonObject header = new JsonObject();
        JsonObject reference = absolute(addressPoint, -width, width);
        header.add("complete_object_locator", reference);
        boolean complete = readable(reference);
        Address locatorAddress = target(reference);
        if (locatorAddress == null || isNull(reference)) {
            header.add("locator", null);
            header.addProperty("complete", complete);
            return header;
        }

        JsonObject locator = new JsonObject();
        locator.addProperty("address", AddressCodec.format(locatorAddress));
        header.add("locator", locator);
        try {
            // MicrosoftCXXABI::getCompleteObjectLocatorType / MSRTTIBuilder emits
            // three u32 fields, two pointers/RVAs, and (64-bit only) a self RVA.
            byte[] bytes = bytes(locatorAddress, width == 8 ? 24 : 20);
            long signature = integer(locatorAddress, bytes, 0, 4, false).longValue();
            locator.addProperty("readable", true);
            locator.addProperty("signature", signature);
            locator.addProperty("offset", integer(locatorAddress, bytes, 4, 4, false));
            locator.addProperty("cd_offset", integer(locatorAddress, bytes, 8, 4, false));
            if (signature != (width == 8 ? 1 : 0)) {
                locator.addProperty("error", "Unsupported Complete Object Locator signature "
                    + signature + " for " + (width * 8) + "-bit pointers");
                complete = false;
            } else if (width == 4) {
                locator.add("type_descriptor", absolute(locatorAddress, 12, 4));
                locator.add("class_descriptor", absolute(locatorAddress, 16, 4));
            } else {
                Address imageBase = locatorAddress.getAddressSpace().getAddressInThisSpaceOnly(
                    session.program().getImageBase().getOffset());
                locator.addProperty("image_base", AddressCodec.format(imageBase));
                JsonObject type = imageRelative(locatorAddress, 12, imageBase);
                JsonObject hierarchy = imageRelative(locatorAddress, 16, imageBase);
                JsonObject self = imageRelative(locatorAddress, 20, imageBase);
                locator.add("type_descriptor", type);
                locator.add("class_descriptor", hierarchy);
                locator.add("self", self);
                boolean matches = locatorAddress.equals(target(self));
                locator.addProperty("self_matches", matches);
                complete &= !type.has("error") && !hierarchy.has("error") && !self.has("error");
                if (!matches) {
                    locator.addProperty("error", "Complete Object Locator self RVA does not resolve "
                        + "to its address using the program image base");
                    complete = false;
                }
            }
        } catch (MemoryAccessException | AddressOverflowException e) {
            locator.addProperty("readable", false);
            locator.addProperty("error", message(e));
            complete = false;
        }
        locator.addProperty("complete", complete);
        header.addProperty("complete", complete);
        return header;
    }

    JsonObject absolute(Address base, long offset, int width) throws Exception {
        Address address = null;
        try {
            address = shift(base, offset);
            shift(address, width - 1);
            JsonObject value = pointers.read(address, width);
            value.addProperty("readable", true);
            value.addProperty("is_null", raw(value).signum() == 0);
            return value;
        } catch (MemoryAccessException | AddressOverflowException e) {
            return unreadable(address, e);
        }
    }

    JsonObject relative(Address base, long offset, Address addressPoint) throws Exception {
        JsonObject value = scalar(base, offset, 4, true);
        value.addProperty("relative_base", AddressCodec.format(addressPoint));
        merge(value, pointers.describeTarget(null));
        if (!readable(value)) {
            value.add("is_null", null);
            return value;
        }
        int displacement = value.remove("signed_value").getAsInt();
        value.addProperty("displacement", displacement);
        value.addProperty("is_null", displacement == 0);
        if (displacement != 0) {
            try {
                merge(value, pointers.describeTarget(shift(addressPoint, displacement)));
            } catch (AddressOverflowException e) {
                value.addProperty("error", "Relative target exceeds the address space");
            }
        }
        return value;
    }

    private JsonObject imageRelative(Address base, long offset, Address imageBase) throws Exception {
        JsonObject value = scalar(base, offset, 4, false);
        value.addProperty("relative_base", AddressCodec.format(imageBase));
        merge(value, pointers.describeTarget(null));
        if (!readable(value)) {
            value.add("is_null", null);
            return value;
        }
        long rva = raw(value).longValue();
        value.addProperty("rva", rva);
        value.addProperty("is_null", rva == 0);
        if (rva != 0) {
            try {
                merge(value, pointers.describeTarget(shift(imageBase, rva)));
            } catch (AddressOverflowException e) {
                value.addProperty("error", "Image-relative target exceeds the address space");
            }
        }
        return value;
    }

    private JsonObject scalar(Address base, long offset, int width, boolean signed) throws Exception {
        Address address = null;
        JsonObject result = new JsonObject();
        result.addProperty("size", width);
        try {
            address = shift(base, offset);
            byte[] bytes = bytes(address, width);
            result.addProperty("address", AddressCodec.format(address));
            result.addProperty("value", String.format("0x%0" + (width * 2) + "x",
                integer(address, bytes, 0, width, false)));
            if (signed) result.addProperty("signed_value", integer(address, bytes, 0, width, true));
            result.addProperty("readable", true);
        } catch (MemoryAccessException | AddressOverflowException e) {
            result.addProperty("address", AddressCodec.format(address));
            result.add("value", null);
            if (signed) result.add("signed_value", null);
            result.addProperty("readable", false);
            result.addProperty("error", message(e));
        }
        return result;
    }

    private byte[] bytes(Address address, int width)
            throws MemoryAccessException, AddressOverflowException, ghidra.util.exception.CancelledException {
        session.monitor().checkCancelled();
        shift(address, width - 1);
        byte[] bytes = new byte[width];
        if (session.program().getMemory().getBytes(address, bytes) != width) {
            throw new MemoryAccessException("Incomplete read at " + AddressCodec.format(address));
        }
        return bytes;
    }

    private BigInteger integer(Address address, byte[] bytes, int offset, int width, boolean signed)
            throws MemoryAccessException {
        var memory = session.program().getMemory();
        return new ByteMemBufferImpl(memory, address, bytes, memory.isBigEndian())
            .getBigInteger(offset, width, signed);
    }

    private JsonObject unreadable(Address address, Exception failure) throws Exception {
        JsonObject result = pointers.describeTarget(null);
        result.addProperty("address", AddressCodec.format(address));
        result.add("value", null);
        result.add("is_null", null);
        result.addProperty("readable", false);
        result.addProperty("error", message(failure));
        return result;
    }

    private Address target(JsonObject value) {
        JsonElement target = value.get("target_address");
        return target == null || target.isJsonNull() ? null
            : AddressCodec.parse(session.program().getAddressFactory(), target.getAsString());
    }

    private static boolean readable(JsonObject value) {
        return value.get("readable").getAsBoolean();
    }

    private static boolean isNull(JsonObject value) {
        JsonElement isNull = value.get("is_null");
        return isNull != null && !isNull.isJsonNull() && isNull.getAsBoolean();
    }

    private static BigInteger raw(JsonObject value) {
        return new BigInteger(value.get("value").getAsString().substring(2), 16);
    }

    private static void merge(JsonObject into, JsonObject fields) {
        for (var field : fields.entrySet()) into.add(field.getKey(), field.getValue());
    }

    private static String message(Exception failure) {
        String message = failure.getMessage();
        return message == null ? failure.getClass().getSimpleName() : message;
    }

    static Address shift(Address base, long displacement) throws AddressOverflowException {
        Address result = base.addNoWrap(displacement);
        // Address arithmetic must not silently leave an overlay when crossing its mapped range.
        return result.getAddressSpace().equals(base.getAddressSpace()) ? result
            : base.getAddressSpace().getAddressInThisSpaceOnly(result.getOffset());
    }
}
