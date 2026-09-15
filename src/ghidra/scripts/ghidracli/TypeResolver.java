package ghidracli;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.BuiltInDataTypeManager;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.PointerDataType;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class TypeResolver {
    private final ProgramSession session;

    TypeResolver(ProgramSession session) {
        this.session = session;
    }

    private static final Map<String, String> TYPE_NAME_ALIASES = buildTypeNameAliases();
    private static final Pattern ARRAY_DIMENSION = Pattern.compile("\\[\\s*([0-9]+)\\s*\\]\\s*");

    static final class TypeResolutionException extends JsonProtocol.CommandException {
        TypeResolutionException(String message, JsonObject detail) {
            super(message, detail);
        }
    }

    /**
     * Common C spellings that aren't registered under that literal name in
     * Ghidra's data type managers (fixed-width stdint names, "unsigned X")
     * -- mapped to the canonical Ghidra builtin name that resolveDataType()
     * can find directly.
     */
    private static Map<String, String> buildTypeNameAliases() {
        Map<String, String> m = new HashMap<>();
        m.put("uint8_t", "byte");
        m.put("u8", "byte");
        m.put("int8_t", "sbyte");
        m.put("s8", "sbyte");
        m.put("uint16_t", "ushort");
        m.put("u16", "ushort");
        m.put("int16_t", "short");
        m.put("s16", "short");
        m.put("uint32_t", "uint");
        m.put("u32", "uint");
        m.put("int32_t", "int");
        m.put("s32", "int");
        m.put("uint64_t", "ulonglong");
        m.put("u64", "ulonglong");
        m.put("int64_t", "longlong");
        m.put("s64", "longlong");
        m.put("unsigned", "uint");
        m.put("unsigned int", "uint");
        m.put("unsigned long", "ulong");
        m.put("unsigned long long", "ulonglong");
        m.put("unsigned short", "ushort");
        m.put("unsigned char", "uchar");
        m.put("signed char", "char");
        return m;
    }

    DataType resolveDataType(String name) {
        if (name == null || name.trim().isEmpty()) return null;
        String trimmed = name.trim();
        DataTypeManager dtm = session.program().getDataTypeManager();

        // Handle pointer syntax: "int *" or "char **" -- peel one level and
        // resolve the pointee with the same path/ambiguity rules. The target
        // manager supplies pointer width before a caller measures the type.
        if (trimmed.endsWith("*")) {
            String base = trimmed.substring(0, trimmed.length() - 1).trim();
            DataType baseType = resolveDataType(base);
            return baseType != null ? new PointerDataType(baseType, dtm) : null;
        }

        if (trimmed.indexOf('[') >= 0 || trimmed.indexOf(']') >= 0) {
            return resolveArray(trimmed, dtm);
        }

        // A full path never falls back to another category or an alias.
        // Builtins may still be addressed by their exact path (e.g. /int).
        if (trimmed.startsWith("/")) {
            DataType found = dtm.getDataType(trimmed);
            if (found == null) {
                found = BuiltInDataTypeManager.getDataTypeManager().getDataType(trimmed);
            }
            return found != null ? found.clone(dtm) : null;
        }

        // Scan by simple name: the program's own data type manager first,
        // then Ghidra's built-in primitives (int, uint, dword, qword, ulong,
        // byte, ...). Built-ins usually aren't materialized in the
        // program's own DTM until something references them, so scanning
        // only currentProgram.getDataTypeManager() misses most of the
        // ordinary C type names a user would type.
        DataType found = findDataTypeByName(dtm, trimmed, trimmed);
        if (found == null) {
            found = findDataTypeByName(BuiltInDataTypeManager.getDataTypeManager(), trimmed, trimmed);
        }
        if (found != null) return found.clone(dtm);

        // Retry under the canonical alias (uint32_t -> uint, u32 -> uint, etc.)
        String canonical = TYPE_NAME_ALIASES.get(trimmed);
        if (canonical != null) {
            found = findDataTypeByName(dtm, canonical, trimmed);
            if (found == null) {
                found = findDataTypeByName(BuiltInDataTypeManager.getDataTypeManager(), canonical, trimmed);
            }
        }
        return found != null ? found.clone(dtm) : null;
    }

    private DataType resolveArray(String expression, DataTypeManager dtm) {
        int firstDimension = expression.indexOf('[');
        if (firstDimension <= 0 || expression.substring(0, firstDimension).indexOf(']') >= 0) {
            throw invalidArray(expression, "expected a base type followed by [count]");
        }

        String dimensions = expression.substring(firstDimension);
        Matcher matcher = ARRAY_DIMENSION.matcher(dimensions);
        List<Integer> counts = new ArrayList<>();
        int end = 0;
        while (matcher.find()) {
            if (matcher.start() != end) break;
            int count;
            try {
                count = Integer.parseInt(matcher.group(1));
            } catch (NumberFormatException e) {
                throw invalidArray(expression, "array count must be between 1 and " + Integer.MAX_VALUE);
            }
            if (count <= 0) {
                throw invalidArray(expression, "array count must be positive");
            }
            counts.add(count);
            end = matcher.end();
        }
        if (end != dimensions.length() || counts.isEmpty()) {
            throw invalidArray(expression, "expected positive decimal array counts, such as byte[16]");
        }

        DataType element = resolveDataType(expression.substring(0, firstDimension));
        if (element == null) return null;
        // C dimensions are outermost first: byte[2][3] is two arrays of three
        // bytes. Construct from the final dimension inward to preserve shape.
        for (int i = counts.size() - 1; i >= 0; i--) {
            int elementLength = element.getAlignedLength();
            if (element.isZeroLength() || element.getLength() <= 0 || elementLength <= 0) {
                throw invalidArray(expression, "array element type must have a fixed positive size");
            }
            if ((long) elementLength * counts.get(i) > Integer.MAX_VALUE) {
                throw invalidArray(expression, "array byte length exceeds " + Integer.MAX_VALUE);
            }
            // These are detached objects: resolving a type expression never
            // registers a datatype or mutates the program database.
            element = new ArrayDataType(element, counts.get(i), -1, dtm);
        }
        return element;
    }

    private TypeResolutionException invalidArray(String expression, String reason) {
        JsonObject detail = new JsonObject();
        detail.addProperty("type_name", expression);
        return new TypeResolutionException("Invalid array type '" + expression + "': " + reason, detail);
    }

    private DataType findDataTypeByName(DataTypeManager mgr, String name, String requestedName) {
        Map<String, DataType> matches = new TreeMap<>();
        Iterator<DataType> iter = mgr.getAllDataTypes();
        while (iter.hasNext()) {
            DataType candidate = iter.next();
            if (candidate.getName().equals(name)) {
                matches.put(candidate.getPathName(), candidate);
            }
        }
        if (matches.size() > 1) {
            JsonArray candidates = new JsonArray();
            for (String path : matches.keySet()) candidates.add(path);
            JsonObject detail = new JsonObject();
            detail.addProperty("type_name", requestedName);
            detail.add("candidates", candidates);
            throw new TypeResolutionException("Ambiguous type name '" + requestedName
                + "'. Use a full path: " + String.join(", ", matches.keySet()), detail);
        }
        return matches.isEmpty() ? null : matches.values().iterator().next();
    }
}
