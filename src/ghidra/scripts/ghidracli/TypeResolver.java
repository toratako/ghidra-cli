package ghidracli;

import ghidra.program.model.data.BuiltInDataTypeManager;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.PointerDataType;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

final class TypeResolver {
    private final ProgramSession session;

    TypeResolver(ProgramSession session) {
        this.session = session;
    }

    private static final Map<String, String> TYPE_NAME_ALIASES = buildTypeNameAliases();

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
        if (name == null || name.isEmpty()) return null;
        String trimmed = name.trim();
        DataTypeManager dtm = session.program().getDataTypeManager();

        // Try by path first (e.g., "/int" or "/myCategory/myStruct")
        DataType dt = dtm.getDataType(trimmed);
        if (dt != null) return dt;

        // Handle pointer syntax: "int *" or "char **" -- peel one level and
        // recurse so aliasing/builtin fallback below also applies to the
        // pointee (e.g. "void *", "uint32_t *").
        if (trimmed.endsWith("*")) {
            String base = trimmed.substring(0, trimmed.lastIndexOf('*')).trim();
            DataType baseType = resolveDataType(base);
            return baseType != null ? new PointerDataType(baseType) : null;
        }

        // Scan by simple name: the program's own data type manager first,
        // then Ghidra's built-in primitives (int, uint, dword, qword, ulong,
        // byte, ...). Built-ins usually aren't materialized in the
        // program's own DTM until something references them, so scanning
        // only currentProgram.getDataTypeManager() misses most of the
        // ordinary C type names a user would type.
        DataType found = findDataTypeByName(dtm, trimmed);
        if (found == null) {
            found = findDataTypeByName(BuiltInDataTypeManager.getDataTypeManager(), trimmed);
        }
        if (found != null) return found;

        // Retry under the canonical alias (uint32_t -> uint, u32 -> uint, etc.)
        String canonical = TYPE_NAME_ALIASES.get(trimmed);
        if (canonical != null) {
            found = findDataTypeByName(dtm, canonical);
            if (found == null) {
                found = findDataTypeByName(BuiltInDataTypeManager.getDataTypeManager(), canonical);
            }
        }
        return found;
    }

    private DataType findDataTypeByName(DataTypeManager mgr, String name) {
        Iterator<DataType> iter = mgr.getAllDataTypes();
        while (iter.hasNext()) {
            DataType c = iter.next();
            if (c.getName().equals(name)) return c;
        }
        return null;
    }
}
