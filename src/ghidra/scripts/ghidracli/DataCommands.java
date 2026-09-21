package ghidracli;

import com.google.gson.JsonArray;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.AbstractFloatDataType;
import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.data.BitFieldDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.EndianSettingsDefinition;
import ghidra.program.model.listing.Data;
import ghidra.program.model.mem.DumbMemBufferImpl;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.DataConverter;
import java.math.BigInteger;
import java.util.List;
import static ghidracli.JsonProtocol.errorResult;
import static ghidracli.JsonProtocol.getArgString;
import static ghidracli.JsonProtocol.getNonnegativeIntArg;

/** Reads existing listing data using Ghidra's applied types and component settings. */
final class DataCommands {
    private static final int MAX_DEPTH = 64;
    private static final int MAX_ELEMENTS = 100_000;
    private static final int MAX_VALUE_BYTES = 65_536;

    private final ProgramSession session;
    private final AddressResolver addressResolver;

    DataCommands(ProgramSession session, AddressResolver addressResolver) {
        this.session = session;
        this.addressResolver = addressResolver;
    }

    JsonObject handleList(JsonObject args) throws Exception {
        if (session.program() == null) return errorResult("No program loaded");
        long limit = ListQuery.pageArgument(args, "limit");
        JsonArray items = new JsonArray();
        var data = session.program().getListing().getDefinedData(true);
        while (data.hasNext() && (limit == 0 || items.size() < limit)) {
            session.monitor().checkCancelled();
            items.add(metadata(data.next()));
        }
        JsonObject result = new JsonObject();
        result.add("items", items);
        result.addProperty("count", items.size());
        return result;
    }

    JsonObject handleRead(JsonObject args) throws Exception {
        if (session.program() == null) return errorResult("No program loaded");
        String target = getArgString(args, "target");
        if (target == null || target.isBlank()) return errorResult("Data target required");
        int maxDepth = getNonnegativeIntArg(args, "max_depth", 2);
        int maxElements = getNonnegativeIntArg(args, "max_elements", 100);
        if (maxDepth > MAX_DEPTH) return errorResult("max_depth must be at most " + MAX_DEPTH);
        if (maxElements > MAX_ELEMENTS) {
            return errorResult("max_elements must be at most " + MAX_ELEMENTS);
        }
        Address address = addressResolver.resolveAddress(target);
        if (address == null) return errorResult("Invalid address: " + target);
        Data data = session.program().getListing().getDefinedDataContaining(address);
        if (data == null) {
            return errorResult("No defined data at " + AddressCodec.format(address)
                + ". Inspect memory info or apply a data type first.");
        }

        // Select an interior component without scanning earlier array elements. Stop at
        // overlapping interpretations rather than arbitrarily selecting a union/bit-field.
        JsonArray parents = new JsonArray();
        while (!data.getAddress().equals(address) && !data.hasStringValue()
                && !data.isUnion() && parents.size() < MAX_DEPTH) {
            session.monitor().checkCancelled();
            int offset = (int) address.subtract(data.getAddress());
            List<Data> containing = data.getComponentsContaining(offset);
            if (containing == null || containing.size() != 1) break;
            Data child = containing.get(0);
            if (child == null) break;
            parents.add(metadata(data));
            data = child;
        }

        Budget budget = new Budget(maxDepth, maxElements);
        JsonObject result = read(data, 0, budget);
        result.addProperty("target_address", AddressCodec.format(address));
        result.addProperty("target_offset", address.subtract(data.getAddress()));
        result.add("parents", parents);
        result.addProperty("expanded_elements", maxElements - budget.remaining);
        result.addProperty("max_depth", maxDepth);
        result.addProperty("max_elements", maxElements);
        if (parents.size() == MAX_DEPTH && !data.getAddress().equals(address)) {
            truncate(result, "selection_depth");
        }
        session.monitor().checkCancelled();
        return result;
    }

    private JsonObject read(Data data, int depth, Budget budget) throws Exception {
        session.monitor().checkCancelled();
        JsonObject result = metadata(data);
        result.addProperty("truncated", false);
        result.add("value", JsonNull.INSTANCE);
        boolean aggregate = !data.hasStringValue()
            && (data.isArray() || data.isStructure() || data.isUnion() || data.isDynamic());
        if (!aggregate) {
            readValue(data, result);
            return result;
        }

        result.addProperty("state", "aggregate");
        int count = data.getNumComponents();
        if (count < 0) {
            result.addProperty("state", "unavailable");
            result.addProperty("reason", "incomplete_data_type");
            return result;
        }
        result.addProperty("component_count", count);
        if (data.isUnion()) result.addProperty("overlapping", true);
        JsonArray children = new JsonArray();
        result.add("components", children);
        if (count > 0 && depth >= budget.maxDepth) {
            truncate(result, "max_depth");
            return result;
        }
        for (int index = 0; index < count; index++) {
            session.monitor().checkCancelled();
            if (budget.remaining == 0) {
                truncate(result, "max_elements");
                break;
            }
            Data child = data.getComponent(index);
            if (child == null) {
                truncate(result, "unavailable_component");
                break;
            }
            budget.remaining--;
            JsonObject value = read(child, depth + 1, budget);
            children.add(value);
            if (value.get("truncated").getAsBoolean()) {
                result.addProperty("truncated", true);
            }
        }
        return result;
    }

    private void readValue(Data data, JsonObject result) throws Exception {
        if (data.getLength() > MAX_VALUE_BYTES) {
            result.addProperty("state", "unavailable");
            result.addProperty("reason", "value_size_limit");
            result.addProperty("value_byte_limit", MAX_VALUE_BYTES);
            truncate(result, "value_size_limit");
            return;
        }
        // Data components delegate reads to their root's whole-object byte cache.
        // Use a small native buffer while retaining the applied Data's settings.
        var buffer = new DumbMemBufferImpl(session.program().getMemory(), data.getAddress());
        if (!buffer.isInitializedMemory()) {
            result.addProperty("state", "unavailable");
            result.addProperty("reason", "uninitialized_memory");
            return;
        }
        // isInitializedMemory() only tests the start. Checking the complete
        // value prevents partial/uninitialized storage from becoming numeric zero.
        byte[] bytes = new byte[data.getLength()];
        if (buffer.getBytes(bytes, 0) != bytes.length) {
            result.addProperty("state", "unavailable");
            result.addProperty("reason", "unreadable_memory");
            return;
        }
        if (data.getBaseDataType() instanceof Enum enumType) {
            // Native enum getValue/getRepresentation(MemBuffer) decode only
            // 1/2/4/8-byte enums; other valid widths silently produce zero.
            BigInteger integer = DataConverter.getInstance(
                EndianSettingsDefinition.DEF.isBigEndian(data, buffer))
                .getBigInteger(bytes, bytes.length, enumType.isSigned());
            result.addProperty("state", "available");
            result.addProperty("value", integer.toString());
            result.addProperty("signed", enumType.isSigned());
            result.addProperty("bit_length", bytes.length * 8);
            result.addProperty("representation",
                enumType.getRepresentation(integer, data, bytes.length * 8));
            return;
        }
        Object value = data.getDataType().getValue(buffer, data, data.getLength());
        if (value == null) {
            result.addProperty("state", "unavailable");
            result.addProperty("reason", "no_typed_value");
            return;
        }
        result.addProperty("state", "available");
        if (value instanceof Scalar scalar) {
            result.addProperty("value", scalar.bitLength() == 0 ? "0" : scalar.getBigInteger().toString());
            result.addProperty("signed", scalar.isSigned());
            result.addProperty("bit_length", scalar.bitLength());
        } else if (value instanceof BigInteger integer) {
            result.addProperty("value", integer.toString());
            DataType type = data.getBaseDataType();
            if (type instanceof AbstractIntegerDataType integerType) {
                result.addProperty("signed", integerType.isSigned());
                result.addProperty("bit_length", data.getLength() * 8);
            }
        } else if (value instanceof Address pointer) {
            result.addProperty("value", AddressCodec.format(pointer));
            JsonObject reference = new JsonObject();
            reference.addProperty("address", AddressCodec.format(pointer));
            reference.addProperty("mapped", session.program().getMemory().contains(pointer));
            Symbol symbol = session.program().getSymbolTable().getPrimarySymbol(pointer);
            reference.addProperty("symbol", symbol == null ? null : symbol.getName(true));
            result.add("reference", reference);
        } else if (value instanceof Boolean bool) {
            result.addProperty("value", bool);
        } else {
            // Text also preserves extended floats and NaN/Infinity without lossy
            // conversion to JSON doubles. Integer values above follow the same rule.
            result.addProperty("value", value.toString());
        }
        if (!(value instanceof String)) {
            result.addProperty("representation",
                data.getDataType().getRepresentation(buffer, data, data.getLength()));
        }
    }

    private JsonObject metadata(Data data) {
        JsonObject result = new JsonObject();
        result.addProperty("address", AddressCodec.format(data.getAddress()));
        Symbol symbol = data.getPrimarySymbol();
        String name = data.getParent() == null
            ? (symbol == null ? null : symbol.getName(true)) : data.getFieldName();
        result.addProperty("name", name);
        result.addProperty("type", data.getDataType().getDisplayName());
        result.addProperty("type_path", data.getDataType().getPathName());
        result.addProperty("size", data.getLength());
        result.addProperty("kind", kind(data));
        JsonArray path = new JsonArray();
        for (int index : data.getComponentPath()) path.add(index);
        result.add("component_path", path);
        if (data.getParent() != null) {
            result.addProperty("index", data.getComponentIndex());
            result.addProperty("offset", data.getParentOffset());
        }
        if (data.getBaseDataType() instanceof BitFieldDataType bitField) {
            result.addProperty("bit_offset", bitField.getBitOffset());
            result.addProperty("bit_length", bitField.getBitSize());
        }
        return result;
    }

    private static String kind(Data data) {
        if (data.hasStringValue()) return "string";
        if (data.isPointer()) return "pointer";
        if (data.isStructure()) return "structure";
        if (data.isUnion()) return "union";
        if (data.isArray()) return "array";
        if (data.getValueClass() == Character.class) return "character";
        DataType type = data.getBaseDataType();
        if (type instanceof Enum) return "enum";
        if (type instanceof BitFieldDataType) return "bitfield";
        if (type instanceof AbstractIntegerDataType) return "integer";
        if (type instanceof AbstractFloatDataType) return "float";
        return "scalar";
    }

    private static void truncate(JsonObject result, String reason) {
        result.addProperty("truncated", true);
        JsonArray reasons = result.getAsJsonArray("truncation_reasons");
        if (reasons == null) {
            reasons = new JsonArray();
            result.add("truncation_reasons", reasons);
        }
        reasons.add(reason);
    }

    private static final class Budget {
        final int maxDepth;
        int remaining;

        Budget(int maxDepth, int remaining) {
            this.maxDepth = maxDepth;
            this.remaining = remaining;
        }
    }
}
