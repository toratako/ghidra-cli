package ghidracli.types;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.program.database.data.DataTypeUtilities;
import ghidra.program.model.data.BitFieldDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Structure;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidracli.protocol.JsonProtocol;
import java.util.Objects;

/** Validate field edits on a detached copy before changing the program database. */
final class StructureFields {
    private StructureFields() {}

    static int length(Structure struct) {
        return struct.isZeroLength() ? 0 : struct.getLength();
    }

    static int offset(JsonObject args) {
        String value = JsonProtocol.getArgString(args, "offset");
        if (value == null) throw new IllegalArgumentException("Offset is required");
        boolean hex = value.startsWith("0x") || value.startsWith("0X");
        String digits = hex ? value.substring(2) : value;
        if (!digits.matches(hex ? "[0-9a-fA-F]+" : "[0-9]+"))
            throw new IllegalArgumentException("Offset must be a nonnegative decimal or 0x hexadecimal integer");
        try { return Integer.parseInt(digits, hex ? 16 : 10); }
        catch (NumberFormatException e) { throw new IllegalArgumentException("Offset exceeds 2147483647"); }
    }

    static Integer size(JsonObject args) {
        if (args == null || !args.has("size") || args.get("size").isJsonNull()) return null;
        int size = JsonProtocol.getNonnegativeIntArg(args, "size", 0);
        if (size == 0) throw new IllegalArgumentException("Field size must be positive");
        return size;
    }

    static JsonObject describe(DataTypeComponent field) {
        if (field == null) return null;
        DataType type = field.getDataType();
        BitFieldDataType bitfield = type instanceof BitFieldDataType
            ? (BitFieldDataType) type : null;
        DataType baseType = bitfield == null ? null : bitfield.getBaseDataType();
        JsonObject result = new JsonObject();
        result.addProperty("ordinal", field.getOrdinal());
        result.addProperty("name", field.getFieldName());
        result.addProperty("display_name", field.getFieldName() != null
            ? field.getFieldName() : field.getDefaultFieldName());
        result.addProperty("type", type.getName());
        result.addProperty("type_path", type.getPathName());
        result.addProperty("offset", field.getOffset());
        result.addProperty("size", field.getLength());
        result.addProperty("comment", field.getComment());
        result.addProperty("is_bitfield", bitfield != null);
        // Native bit offsets are right shifts within the component's minimal byte storage.
        result.addProperty("bit_offset", bitfield == null ? null : bitfield.getBitOffset());
        result.addProperty("bit_size", bitfield == null ? null : bitfield.getBitSize());
        result.addProperty("base_type", baseType == null ? null : baseType.getName());
        result.addProperty("base_type_path", baseType == null ? null : baseType.getPathName());
        return result;
    }

    private static JsonProtocol.CommandException conflict(String message, DataTypeComponent field) {
        JsonObject detail = new JsonObject();
        detail.add("field", describe(field));
        return new JsonProtocol.CommandException(message, detail);
    }

    static DataTypeComponent target(Structure struct, int offset) {
        if (offset < 0) throw new IllegalArgumentException("Offset must be nonnegative");
        DataTypeComponent target = null;
        for (DataTypeComponent field : struct.getDefinedComponents()) {
            if (field.getOffset() == offset ||
                    (field.getOffset() < offset && offset <= field.getEndOffset())) {
                if (field.isBitFieldComponent() || field.getLength() == 0)
                    throw conflict("Bit-fields and zero-length fields are not supported by offset edits", field);
                if (field.getOffset() != offset)
                    throw conflict("Offset is inside a field; use its starting offset " + field.getOffset(), field);
                // Check every overlapping component: a later zero-length or
                // bit-field component can make the same byte offset ambiguous.
                target = field;
            }
        }
        return target;
    }

    static Plan set(Structure struct, TypeFields.StructureSelection selected, String name, DataType type,
            String comment, boolean commentSpecified, Integer sizeOverride) throws Exception {
        if (sizeOverride != null && type == null)
            throw new IllegalArgumentException("--size requires --type");
        int offset = selected.offset;
        DataTypeComponent old = selected.field;
        if (old != null && old.getLength() == 0)
            throw conflict("Zero-length fields are not supported by layout edits", old);
        if (name == null && type == null && !commentSpecified)
            throw new IllegalArgumentException("At least one of --name, --type, or --comment is required");
        if (old == null && type == null)
            throw new IllegalArgumentException("--type is required to create a field in undefined space");
        if (name != null) {
            SymbolUtilities.validateName(name);
            for (DataTypeComponent other : struct.getDefinedComponents()) {
                if (old != null && other.getOrdinal() == old.getOrdinal()) continue;
                if (name.equals(other.getFieldName()) || name.equals(other.getDefaultFieldName()))
                    throw conflict("Field name already exists: " + name, other);
            }
        }
        String effectiveName = name != null ? name : old == null ? null : old.getFieldName();
        String effectiveComment = commentSpecified ? (comment.isEmpty() ? null : comment)
            : old == null ? null : old.getComment();
        if (type != null && struct.isPackingEnabled())
            throw new IllegalArgumentException("Offset layout edits require a structure with packing disabled");

        int newSize = old == null ? 0 : old.getLength();
        if (type != null) {
            if (type instanceof BitFieldDataType)
                throw new IllegalArgumentException("Ordinary fields cannot be converted to bit-fields");
            type = type.clone(struct.getDataTypeManager());
            newSize = sizeOverride != null ? sizeOverride : type.getLength();
            if (newSize <= 0 || type.isZeroLength())
                throw new IllegalArgumentException("Field type must have a fixed positive size");
            long end = (long) offset + newSize;
            if (end > Integer.MAX_VALUE)
                throw new IllegalArgumentException("Field end exceeds the maximum structure size");
            DataTypeUtilities.checkAncestry(struct, type);
            JsonArray conflicts = new JsonArray();
            for (DataTypeComponent field : struct.getDefinedComponents()) {
                if (old != null && field.getOrdinal() == old.getOrdinal()) continue;
                if (field.getOffset() < end &&
                        (field.getLength() == 0 ? field.getOffset() >= offset : field.getEndOffset() >= offset))
                    conflicts.add(describe(field));
            }
            if (conflicts.size() != 0) {
                JsonObject detail = new JsonObject();
                detail.addProperty("offset", offset);
                detail.addProperty("size", newSize);
                detail.add("conflicts", conflicts);
                throw new JsonProtocol.CommandException("Field overlaps existing defined fields", detail);
            }
        }

        Structure staged = (Structure) struct.copy(struct.getDataTypeManager());
        if (type == null) {
            // Metadata changes are safe even in packed structures.
            DataTypeComponent field = staged.getComponent(old.getOrdinal());
            if (name != null) field.setFieldName(name);
            if (commentSpecified) staged.getComponent(old.getOrdinal()).setComment(effectiveComment);
        } else {
            int desiredLength = Math.max(length(struct), offset + newSize);
            if (desiredLength > length(staged)) staged.growStructure(desiredLength - length(staged));
            DataTypeComponent replacement = staged.replaceAtOffset(
                offset, type, newSize, effectiveName, effectiveComment);
            if (sizeOverride != null && replacement.getLength() != sizeOverride)
                throw new IllegalArgumentException("Ghidra cannot honor --size " + sizeOverride
                    + " for field type " + type.getName());
        }
        verifyOtherFields(struct, staged, old);
        DataTypeComponent after = type == null ? staged.getComponent(old.getOrdinal()) : target(staged, offset);
        if (after == null || (name != null && !name.equals(after.getFieldName())))
            throw new IllegalArgumentException("Ghidra did not preserve the requested field name or offset");
        if (length(staged) < length(struct))
            throw new IllegalArgumentException("Field replacement would shrink the structure");
        return new Plan(struct, staged, offset, old, after, type == null,
            old == null ? "created" : "updated");
    }

    static Plan clear(Structure struct, TypeFields.StructureSelection selected) {
        int offset = selected.offset;
        if (selected.field == null && (offset < 0 || offset >= length(struct)))
            throw new IllegalArgumentException("Offset is outside the structure");
        DataTypeComponent old = selected.field;
        if (old != null && old.getLength() == 0 && !old.isBitFieldComponent())
            throw conflict("Zero-length fields are not supported by layout edits", old);
        Structure staged = (Structure) struct.copy(struct.getDataTypeManager());
        if (old != null) {
            if (struct.isPackingEnabled())
                throw new IllegalArgumentException("Clearing a field requires a structure with packing disabled");
            staged.clearComponent(old.getOrdinal());
        }
        TypeFields.verifyComponentCount(staged);
        verifyOtherFields(struct, staged, old);
        if (length(staged) != length(struct))
            throw new IllegalArgumentException("Clearing a field would change the structure size");
        return new Plan(struct, staged, offset, old, null, false, "cleared");
    }

    static void verifyOtherFields(Structure original, Structure staged, DataTypeComponent old) {
        for (DataTypeComponent field : original.getDefinedComponents()) {
            if (old != null && field.getOrdinal() == old.getOrdinal()) continue;
            boolean found = false;
            for (DataTypeComponent candidate : staged.getDefinedComponents()) {
                if (field.getOffset() == candidate.getOffset() && field.getLength() == candidate.getLength()
                        && Objects.equals(field.getFieldName(), candidate.getFieldName())
                        && Objects.equals(field.getComment(), candidate.getComment())
                        && (!field.isBitFieldComponent() || candidate.isBitFieldComponent()
                            && ((BitFieldDataType) field.getDataType()).getBitOffset()
                                == ((BitFieldDataType) candidate.getDataType()).getBitOffset())
                        && field.getDataType().isEquivalent(candidate.getDataType())) {
                    found = true;
                    break;
                }
            }
            if (!found) throw conflict("Edit would change another field", field);
        }
    }

    static final class Plan {
        private final Structure staged;
        private final int offset;
        private final DataTypeComponent before;
        private final DataTypeComponent after;
        private final boolean metadataOnly;
        private final JsonObject result;
        private final boolean changed;

        Plan(Structure original, Structure staged, int offset,
                DataTypeComponent before, DataTypeComponent after, boolean metadataOnly, String action) {
            this.staged = staged;
            this.offset = offset;
            this.before = before;
            this.after = after;
            this.metadataOnly = metadataOnly;
            JsonObject previous = describe(before);
            JsonObject next = describe(after);
            changed = !Objects.equals(previous, next) || length(original) != length(staged);
            result = TypeFields.result(original, length(original), length(staged), previous, next, action);
        }

        JsonObject apply(Structure original) throws Exception {
            if (changed) {
                // Rebuilding the structure deletes every component's settings.
                // Apply only the validated edit so unrelated components retain
                // their records, settings, and inherited defaults.
                if (metadataOnly) {
                    before.setFieldName(after.getFieldName());
                    before.setComment(after.getComment());
                } else if (after == null) {
                    original.clearComponent(before.getOrdinal());
                    TypeFields.verifyComponentCount(original);
                    if (length(original) != length(staged))
                        throw new IllegalArgumentException("Clearing a field changed the structure size");
                    verifyOtherFields(staged, original, null);
                } else {
                    int growth = length(staged) - length(original);
                    if (growth > 0) original.growStructure(growth);
                    original.replaceAtOffset(offset, after.getDataType(), after.getLength(),
                        after.getFieldName(), after.getComment());
                }
            }
            return result;
        }
    }
}
