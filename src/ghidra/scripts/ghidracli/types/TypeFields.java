package ghidracli.types;

import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.Union;
import ghidracli.protocol.JsonProtocol;
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
        DataTypeComponent[] fields = type instanceof Structure
            ? ((Structure) type).getDefinedComponents() : type.getComponents();
        DataTypeComponent found = null;
        for (DataTypeComponent field : fields) {
            if (!name.equals(field.getFieldName())) continue;
            if (found != null)
                throw new IllegalArgumentException("Ambiguous field name '" + name
                    + "' in " + type.getPathName() + "; use --ordinal"
                    + (type instanceof Structure ? " or --offset" : ""));
            found = field;
        }
        if (found != null) return found;
        throw new IllegalArgumentException("Field not found: " + name + " in " + type.getPathName());
    }

    static final class StructureSelection {
        final int offset;
        final DataTypeComponent field;

        StructureSelection(int offset, DataTypeComponent field) {
            this.offset = offset;
            this.field = field;
        }
    }

    static StructureSelection structureSelection(Structure struct, JsonObject args) {
        String selector = selector(args);
        if (selector.equals("offset")) {
            int offset = StructureFields.offset(args);
            return new StructureSelection(offset, StructureFields.target(struct, offset));
        }
        DataTypeComponent field;
        if (selector.equals("field")) {
            field = named(struct, args);
        } else {
            int ordinal = JsonProtocol.getNonnegativeIntArg(args, "ordinal", 0);
            if (ordinal >= struct.getNumComponents())
                throw new IllegalArgumentException("Struct field ordinal is outside the structure: " + ordinal);
            field = struct.getComponent(ordinal);
        }
        return new StructureSelection(field.getOffset(),
            field.getDataType() == DataType.DEFAULT ? null : field);
    }

    static DataTypeComponent structureDeletionTarget(Structure struct, JsonObject args) {
        StructureSelection selected = structureSelection(struct, args);
        if (selected.field == null)
            throw new IllegalArgumentException("No defined field starts at offset " + selected.offset);
        return selected.field;
    }

    static int unionOrdinal(Union union, JsonObject args) {
        switch (selector(args)) {
            case "field": return named(union, args).getOrdinal();
            case "ordinal": return JsonProtocol.getNonnegativeIntArg(args, "ordinal", 0);
            default: throw new IllegalArgumentException("Union members require --ordinal or --field, not --offset");
        }
    }

    /** Count implicit filler and overlapping components without native int overflow. */
    static void verifyComponentCount(Structure struct) {
        if (struct.isPackingEnabled()) return;
        long count = 0;
        long end = 0;
        for (DataTypeComponent field : struct.getDefinedComponents()) {
            count += Math.max(0L, (long) field.getOffset() - end);
            if (field.getOrdinal() != count)
                throw new IllegalArgumentException("invalid component ordinal in " + struct.getPathName());
            count++;
            end = (long) field.getOffset() + field.getLength();
        }
        count += StructureFields.length(struct) - end;
        if (count < 0 || count > Integer.MAX_VALUE || struct.getNumComponents() != count)
            throw new IllegalArgumentException("structure component count exceeds its supported range in "
                + struct.getPathName());
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
