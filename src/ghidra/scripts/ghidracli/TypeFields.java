package ghidracli;

import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.Union;
import java.util.Objects;

/** Shared selection and receipts for struct and union field operations. */
final class TypeFields {
    private TypeFields() {}

    private static String selector(JsonObject args) {
        String selected = null;
        for (String key : new String[] { "offset", "ordinal", "field" }) {
            if (JsonProtocol.getArgString(args, key) == null) continue;
            if (selected != null)
                throw new IllegalArgumentException("Exactly one of offset, ordinal, or field is required");
            selected = key;
        }
        if (selected == null)
            throw new IllegalArgumentException("Exactly one of offset, ordinal, or field is required");
        return selected;
    }

    private static DataTypeComponent named(Composite type, JsonObject args) {
        String name = JsonProtocol.getArgString(args, "field");
        if (name.isBlank()) throw new IllegalArgumentException("Field name must not be empty");
        for (DataTypeComponent field : type.getComponents()) {
            if (name.equals(field.getFieldName())) return field;
        }
        throw new IllegalArgumentException("Field not found: " + name + " in " + type.getPathName());
    }

    static int structureOffset(Structure struct, JsonObject args) {
        switch (selector(args)) {
            case "field": return named(struct, args).getOffset();
            case "offset": return StructureFields.offset(args);
            default: throw new IllegalArgumentException("Struct fields require --offset or --field, not --ordinal");
        }
    }

    static DataTypeComponent structureDeletionTarget(Structure struct, JsonObject args) {
        // Named deletion also supports bit-fields and zero-length fields. An offset
        // cannot uniquely identify these, so it uses the guarded offset selector.
        if (selector(args).equals("field")) return named(struct, args);
        int offset = structureOffset(struct, args);
        DataTypeComponent field = StructureFields.target(struct, offset);
        if (field == null)
            throw new IllegalArgumentException("No defined field starts at offset " + offset);
        return field;
    }

    static int unionOrdinal(Union union, JsonObject args) {
        switch (selector(args)) {
            case "field": return named(union, args).getOrdinal();
            case "ordinal": return JsonProtocol.getNonnegativeIntArg(args, "ordinal", 0);
            default: throw new IllegalArgumentException("Union members require --ordinal or --field, not --offset");
        }
    }

    static JsonObject result(Composite type, int sizeBefore, int sizeAfter,
            JsonObject before, JsonObject after, String action) {
        boolean changed = !Objects.equals(before, after) || sizeBefore != sizeAfter;
        JsonObject result = new JsonObject();
        result.addProperty("status", changed ? action : "unchanged");
        result.addProperty("changed", changed);
        result.addProperty("name", type.getName());
        result.addProperty("path", type.getPathName());
        result.addProperty("kind", type instanceof Structure ? "struct" : "union");
        result.addProperty("size_before", sizeBefore);
        result.addProperty("size_after", sizeAfter);
        result.add("before", before == null ? JsonNull.INSTANCE : before);
        result.add("after", after == null ? JsonNull.INSTANCE : after);
        return result;
    }
}
