package ghidracli;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.docking.settings.Settings;
import ghidra.docking.settings.SettingsDefinition;
import ghidra.docking.settings.SettingsImpl;
import ghidra.program.model.data.BitFieldDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Structure;
import ghidra.program.model.symbol.SymbolUtilities;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import static ghidracli.JsonProtocol.*;
import static ghidracli.StructureFields.describe;
import static ghidracli.StructureFields.length;

/** Validated bit-field layouts and preservation of neighboring fields/settings. */
final class BitFields {
    private BitFields() {}

    static Integer bitSize(JsonObject args) {
        return getArgString(args, "bit_size") == null ? null : getNonnegativeIntArg(args, "bit_size", 0);
    }

    static JsonObject set(Structure struct, DataTypeComponent field, String name, DataType base,
            String comment, Integer size, Integer bitSize) throws Exception {
        if (size != null) throw new IllegalArgumentException("--size is not supported for bit-fields");
        if (name == null && base == null && comment == null && bitSize == null)
            throw new IllegalArgumentException("At least one of --name, --type, --comment, or --bit-size is required");
        validateName(struct, field, name);
        if (base == null && bitSize == null) {
            JsonObject before = describe(field);
            int beforeSize = length(struct);
            String expectedName = name == null ? field.getFieldName() : name;
            String expectedComment = comment == null ? field.getComment() : comment.isEmpty() ? null : comment;
            if (name != null) field.setFieldName(name);
            if (comment != null) field.setComment(expectedComment);
            verifyMetadata(field, expectedName, expectedComment);
            return TypeFields.result(struct, beforeSize, length(struct), before, describe(field), "updated");
        }
        BitFieldDataType bits = (BitFieldDataType) field.getDataType();
        if (bits.getBitSize() == 0)
            throw new IllegalArgumentException("Zero-width bit-fields do not support width or base type edits");
        return replace(struct, field, field.getOffset(), field.getLength(), bits.getBitOffset(),
            bitSize == null ? bits.getBitSize() : bitSize,
            base == null ? bits.getBaseDataType() : base,
            name == null ? field.getFieldName() : name,
            comment == null ? field.getComment() : comment);
    }

    private static void validateName(Structure struct, DataTypeComponent old, String name) throws Exception {
        if (name == null) return;
        if (name.isBlank()) throw new IllegalArgumentException("Field name must not be empty");
        SymbolUtilities.validateName(name);
        for (DataTypeComponent field : struct.getDefinedComponents()) {
            if (old != null && field.getOrdinal() == old.getOrdinal()) continue;
            if (name.equals(field.getFieldName()) || name.equals(field.getDefaultFieldName()))
                throw new IllegalArgumentException("Field name already exists: " + name);
        }
    }

    private static long startBit(int offset, int storage, int bitOffset, int width, boolean bigEndian) {
        return bigEndian ? 8L * (offset + (long) storage) - bitOffset - width : 8L * offset + bitOffset;
    }

    private static void validateRange(Structure struct, DataTypeComponent old, int offset,
            int storage, int bitOffset, int width, boolean bigEndian) {
        if (storage <= 0) throw new IllegalArgumentException("storage_size must be positive");
        if (width <= 0) throw new IllegalArgumentException("bit_size must be positive");
        if ((long) bitOffset + width > 8L * storage)
            throw new IllegalArgumentException("Bit-field does not fit within the storage byte range");
        // Native bit-offset ordering uses signed int arithmetic.
        if (8L * (offset + (long) storage) > Integer.MAX_VALUE)
            throw new IllegalArgumentException("Bit-field storage exceeds Ghidra's supported bit-offset range");
        long start = startBit(offset, storage, bitOffset, width, bigEndian);
        long end = start + width;
        JsonArray conflicts = new JsonArray();
        for (DataTypeComponent field : struct.getDefinedComponents()) {
            if (8L * (field.getOffset() + (long) Math.max(1, field.getLength())) > Integer.MAX_VALUE)
                throw new IllegalArgumentException("Existing field exceeds Ghidra's supported bit-offset range");
            if (old != null && field.getOrdinal() == old.getOrdinal()) continue;
            long otherStart = 8L * field.getOffset();
            long otherEnd = otherStart + 8L * field.getLength();
            if (field.isBitFieldComponent()) {
                BitFieldDataType bits = (BitFieldDataType) field.getDataType();
                if (bits.getBitSize() == 0) continue;
                otherStart = startBit(field.getOffset(), field.getLength(),
                    bits.getBitOffset(), bits.getBitSize(), bigEndian);
                otherEnd = otherStart + bits.getBitSize();
            }
            if (start < otherEnd && otherStart < end) conflicts.add(describe(field));
        }
        if (conflicts.size() != 0) {
            JsonObject detail = new JsonObject();
            detail.add("conflicts", conflicts);
            throw new CommandException("Bit-field overlaps existing defined fields", detail);
        }
    }

    static JsonObject replace(Structure struct, DataTypeComponent old, int offset,
            int storage, int bitOffset, int width, DataType base, String name, String comment) throws Exception {
        if (struct.isPackingEnabled())
            throw new IllegalArgumentException("Bit-field layout edits require a structure with packing disabled");
        validateName(struct, old, name);
        base = base.clone(struct.getDataTypeManager());
        BitFieldDataType.checkBaseDataType(base);
        if ((long) width > 8L * base.getLength())
            throw new IllegalArgumentException("Bit-field width exceeds the base type; clipping is not allowed");
        boolean bigEndian = struct.getDataTypeManager().getDataOrganization().isBigEndian();
        validateRange(struct, old, offset, storage, bitOffset, width, bigEndian);
        String effectiveComment = comment == null || comment.isEmpty() ? null : comment;
        Structure staged = (Structure) struct.copy(struct.getDataTypeManager());
        if (old != null) staged.clearComponent(old.getOrdinal());
        DataTypeComponent expected = staged.insertBitFieldAt(offset, storage, bitOffset,
            base, width, name, effectiveComment);
        TypeFields.verifyComponentCount(staged);
        verifyPlacement(expected, offset, storage, bitOffset, width, bigEndian);
        verifyMetadata(expected, name, effectiveComment);
        StructureFields.verifyOtherFields(struct, staged, old);
        int beforeSize = length(struct);
        int expectedLength = Math.max(beforeSize, offset + storage);
        if (length(staged) != expectedLength)
            throw new IllegalArgumentException("Bit-field insertion would move existing storage");
        JsonObject before = describe(old);
        if (Objects.equals(before, describe(expected)) && beforeSize == expectedLength)
            return TypeFields.result(struct, beforeSize, beforeSize, before, before, "unchanged");
        List<ComponentState> others = new ArrayList<>();
        for (DataTypeComponent field : struct.getDefinedComponents()) {
            if (old == null || old.getOrdinal() != field.getOrdinal()) others.add(new ComponentState(field));
        }
        Settings settings = old == null ? null : new SettingsImpl(old.getDefaultSettings());
        if (old != null) struct.clearComponent(old.getOrdinal());
        DataTypeComponent actual = struct.insertBitFieldAt(offset, storage, bitOffset,
            base, width, name, effectiveComment);
        TypeFields.verifyComponentCount(struct);
        if (settings != null) restoreSettings(actual, settings);
        if (!Objects.equals(describe(actual), describe(expected)) || length(struct) != expectedLength)
            throw new IllegalArgumentException("Ghidra did not preserve the requested bit-field layout");
        List<DataTypeComponent> remaining = new ArrayList<>();
        for (DataTypeComponent field : struct.getDefinedComponents()) {
            if (field.getOrdinal() != actual.getOrdinal()) remaining.add(field);
        }
        for (ComponentState state : others) state.removeMatch(remaining);
        if (!remaining.isEmpty()) throw new IllegalArgumentException("Bit-field edit changed another field");
        return TypeFields.result(struct, beforeSize, length(struct), before, describe(actual),
            old == null ? "created" : "updated");
    }

    private static void verifyPlacement(DataTypeComponent field, int offset, int storage,
            int bitOffset, int width, boolean bigEndian) {
        BitFieldDataType bits = (BitFieldDataType) field.getDataType();
        if (bits.getBitSize() != width || startBit(field.getOffset(), field.getLength(),
                bits.getBitOffset(), bits.getBitSize(), bigEndian)
                != startBit(offset, storage, bitOffset, width, bigEndian))
            throw new IllegalArgumentException("Ghidra did not preserve the requested bit location or width");
    }

    private static void verifyMetadata(DataTypeComponent field, String name, String comment) {
        if (!Objects.equals(field.getFieldName(), name) || !Objects.equals(field.getComment(), comment))
            throw new IllegalArgumentException("Ghidra did not preserve the requested field name or comment");
    }

    private static void restoreSettings(DataTypeComponent field, Settings source) {
        Settings target = field.getDefaultSettings();
        for (String key : source.getNames()) {
            for (SettingsDefinition definition : field.getDataType().getSettingsDefinitions()) {
                if (key.equals(definition.getStorageKey()) && target.isChangeAllowed(definition)) {
                    target.setValue(key, source.getValue(key));
                    break;
                }
            }
        }
    }

    private static final class ComponentState {
        private final JsonObject field;
        private final Settings settings;

        ComponentState(DataTypeComponent component) {
            field = withoutOrdinal(component);
            settings = new SettingsImpl(component.getDefaultSettings());
        }

        private static JsonObject withoutOrdinal(DataTypeComponent component) {
            JsonObject result = describe(component);
            result.remove("ordinal");
            // Unnamed display names embed the ordinal, which can change after insertion.
            result.remove("display_name");
            return result;
        }

        void removeMatch(List<DataTypeComponent> candidates) {
            for (int i = 0; i < candidates.size(); i++) {
                DataTypeComponent candidate = candidates.get(i);
                if (!field.equals(withoutOrdinal(candidate))) continue;
                for (String key : settings.getNames()) {
                    if (!Objects.equals(settings.getValue(key), candidate.getDefaultSettings().getValue(key)))
                        throw new IllegalArgumentException("Bit-field edit changed another field's settings");
                }
                candidates.remove(i);
                return;
            }
            throw new IllegalArgumentException("Bit-field edit changed another field");
        }
    }
}
