package ghidracli;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.scalar.Scalar;
import java.math.BigInteger;
import static ghidracli.JsonProtocol.getArgString;
import static ghidracli.JsonProtocol.getNonnegativeIntArg;

/** Exact numeric matching over the listing's existing operand Scalar objects. */
final class ConstantSearch {
    private static final BigInteger SIGNED_MIN = BigInteger.ONE.shiftLeft(63).negate();
    private static final BigInteger SIGNED_MAX = BigInteger.ONE.shiftLeft(63).subtract(BigInteger.ONE);
    private static final BigInteger UNSIGNED_MAX = BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE);

    private final BigInteger min;
    private final BigInteger max;
    private final boolean signed;
    private final int bits;

    private ConstantSearch(JsonObject args) {
        BigInteger value = number(args, "value");
        BigInteger min = number(args, "min");
        BigInteger max = number(args, "max");
        if (value != null && min == null && max == null) {
            this.min = value;
            this.max = value;
        } else if (value == null && min != null && max != null) {
            if (min.compareTo(max) > 0) {
                throw new IllegalArgumentException("min must not be greater than max");
            }
            if (min.signum() < 0 && max.compareTo(SIGNED_MAX) > 0) {
                throw new IllegalArgumentException("A signed range requires max to fit a signed 64-bit integer");
            }
            this.min = min;
            this.max = max;
        } else {
            throw new IllegalArgumentException("Provide value or both min and max");
        }
        this.signed = this.min.signum() < 0;
        this.bits = getNonnegativeIntArg(args, "bits", 0);
        if (bits > 64 || (bits == 0 && args.has("bits") && !args.get("bits").isJsonNull())) {
            throw new IllegalArgumentException("bits must be an integer from 1 to 64");
        }
    }

    static JsonObject find(ProgramSession session, AddressResolver resolver, JsonObject args)
            throws Exception {
        ConstantSearch search = new ConstantSearch(args);
        int limit = getNonnegativeIntArg(args, "limit", 0);
        AddressSetView range = resolver.instructionRange(
            getArgString(args, "start"), getArgString(args, "end"));
        JsonArray results = new JsonArray();
        instructions:
        for (Instruction instruction : session.program().getListing().getInstructions(range, true)) {
            session.monitor().checkCancelled();
            Address address = instruction.getAddress();
            if (!range.contains(address)) continue;
            for (int operand = 0; operand < instruction.getNumOperands(); operand++) {
                for (Object object : instruction.getOpObjects(operand)) {
                    session.monitor().checkCancelled();
                    // Address operands, data definitions, and p-code reconstructions
                    // do not supply Scalar occurrences in the disassembled listing.
                    if (!(object instanceof Scalar)) continue;
                    Scalar scalar = (Scalar) object;
                    if (!search.matches(scalar)) continue;
                    JsonObject row = new JsonObject();
                    row.addProperty("address", AddressCodec.format(address));
                    row.addProperty("disasm", instruction.toString());
                    row.addProperty("operand_index", operand);
                    row.addProperty("value", "0x" + unsigned(scalar).toString(16));
                    row.addProperty("signed_value", Long.toString(scalar.getSignedValue()));
                    row.addProperty("bits", scalar.bitLength());
                    Function function = session.program().getFunctionManager().getFunctionContaining(address);
                    if (function != null) row.addProperty("function", function.getName());
                    results.add(row);
                    if (limit > 0 && results.size() >= limit) break instructions;
                }
            }
        }
        session.monitor().checkCancelled();
        JsonObject result = new JsonObject();
        result.add("results", results);
        result.addProperty("count", results.size());
        return result;
    }

    private boolean matches(Scalar scalar) {
        if (bits != 0 && scalar.bitLength() != bits) return false;
        BigInteger value = signed ? BigInteger.valueOf(scalar.getSignedValue()) : unsigned(scalar);
        return value.compareTo(min) >= 0 && value.compareTo(max) <= 0;
    }

    private static BigInteger unsigned(Scalar scalar) {
        return new BigInteger(Long.toUnsignedString(scalar.getUnsignedValue()));
    }

    private static BigInteger number(JsonObject args, String key) {
        if (args == null || !args.has(key) || args.get(key).isJsonNull()) return null;
        JsonElement argument = args.get(key);
        if (!argument.isJsonPrimitive() || !argument.getAsJsonPrimitive().isString()) {
            throw new IllegalArgumentException(key + " must be a decimal or 0x-prefixed integer string");
        }
        BigInteger value;
        try {
            value = IntegerLiteral.parse(argument.getAsString());
        } catch (NumberFormatException error) {
            throw new IllegalArgumentException(key + " must be a decimal or 0x-prefixed integer string");
        }
        if (value.compareTo(SIGNED_MIN) < 0 || value.compareTo(UNSIGNED_MAX) > 0) {
            throw new IllegalArgumentException(key
                + " must be from -9223372036854775808 to 18446744073709551615");
        }
        return value;
    }
}
