package ghidracli;

import com.google.gson.JsonObject;
import ghidra.docking.settings.Settings;
import ghidra.docking.settings.SettingsDefinition;
import ghidra.docking.settings.SettingsImpl;
import ghidra.program.database.data.DataTypeUtilities;
import ghidra.program.model.data.BitFieldDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Union;
import ghidra.program.model.symbol.SymbolUtilities;
import java.util.Objects;

import static ghidracli.StructureFields.describe;

/** Ordinal-based union edits validated before changing the program database. */
final class UnionFields {
    private UnionFields() {}

    static int length(Union union) {
        return union.isZeroLength() ? 0 : union.getLength();
    }

    private static DataTypeComponent target(Union union, int ordinal) {
        if (ordinal < 0 || ordinal >= union.getNumComponents())
            throw new IllegalArgumentException("Union member ordinal is outside the union: " + ordinal);
        DataTypeComponent field = union.getComponent(ordinal);
        return field;
    }

    private static void validateName(Union union, String name, int ordinal) throws Exception {
        if (name == null) return;
        if (name.isBlank()) throw new IllegalArgumentException("Field name must not be empty");
        SymbolUtilities.validateName(name);
        for (DataTypeComponent field : union.getComponents()) {
            if (field.getOrdinal() != ordinal && (name.equals(field.getFieldName())
                    || name.equals(field.getDefaultFieldName())))
                throw new IllegalArgumentException("Field name already exists: " + name);
        }
    }

    private static DataType fieldType(Union union, DataType type, Integer size) throws Exception {
        type = type.clone(union.getDataTypeManager());
        if (type instanceof BitFieldDataType)
            throw new IllegalArgumentException("Bit-field members are not supported by union field edits");
        if ((size == null ? type.getLength() : size) <= 0 || type.isZeroLength())
            throw new IllegalArgumentException("Field type must have a fixed positive size");
        DataTypeUtilities.checkAncestry(union, type);
        return type;
    }

    private static void verifyField(DataTypeComponent field, String name, Integer size) {
        if (!Objects.equals(name, field.getFieldName()))
            throw new IllegalArgumentException("Ghidra did not preserve the requested field name");
        if (size != null && field.getLength() != size)
            throw new IllegalArgumentException("Ghidra cannot honor --size " + size
                + " for field type " + field.getDataType().getName());
    }

    static JsonObject append(Union union, String name, DataType type, Integer size) throws Exception {
        validateName(union, name, -1);
        type = fieldType(union, type, size);
        Union staged = (Union) union.copy(union.getDataTypeManager());
        DataTypeComponent field = staged.add(type, size == null ? type.getLength() : size, name, null);
        verifyField(field, name, size);
        int beforeSize = length(union);
        DataTypeComponent added = union.add(type, field.getLength(), name, null);
        return TypeFields.result(union, beforeSize, length(union), null, describe(added), "appended");
    }

    static JsonObject set(Union union, int ordinal, String name, DataType type,
            String comment, Integer size) throws Exception {
        DataTypeComponent old = target(union, ordinal);
        if (old.isBitFieldComponent()) {
            if (size != null) throw new IllegalArgumentException("--size is not supported for bit-fields");
            if (type != null)
                throw new IllegalArgumentException("Bit-field layout edits require a structure with packing disabled");
        }
        if (size != null && type == null)
            throw new IllegalArgumentException("--size requires --type");
        if (name == null && type == null && comment == null)
            throw new IllegalArgumentException("At least one of --name, --type, or --comment is required");
        validateName(union, name, ordinal);
        String effectiveName = name == null ? old.getFieldName() : name;
        String effectiveComment = comment == null ? old.getComment() : comment.isEmpty() ? null : comment;
        JsonObject before = describe(old);
        int beforeSize = length(union);
        Union staged = (Union) union.copy(union.getDataTypeManager());
        if (type == null) {
            staged.getComponent(ordinal).setFieldName(effectiveName);
            staged.getComponent(ordinal).setComment(effectiveComment);
        } else {
            type = fieldType(union, type, size);
            staged.delete(ordinal);
            staged.insert(ordinal, type, size == null ? type.getLength() : size,
                effectiveName, effectiveComment);
        }
        verifyField(staged.getComponent(ordinal), effectiveName, size);
        if (before.equals(describe(staged.getComponent(ordinal))) && beforeSize == length(staged))
            return TypeFields.result(union, beforeSize, length(union), before, before, "unchanged");

        if (type == null) {
            union.getComponent(ordinal).setFieldName(effectiveName);
            union.getComponent(ordinal).setComment(effectiveComment);
        } else {
            // A live delete+insert sends parents a temporary union size, potentially
            // changing their layouts. Replace once, then restore component settings
            // removed by Ghidra's replacement. Omitted settings remain inherited.
            Settings[] settings = new Settings[union.getNumComponents()];
            for (int i = 0; i < settings.length; i++)
                settings[i] = new SettingsImpl(union.getComponent(i).getDefaultSettings());
            union.replaceWith(staged);
            for (int i = 0; i < settings.length; i++) {
                DataTypeComponent field = union.getComponent(i);
                Settings destination = field.getDefaultSettings();
                for (String key : settings[i].getNames()) {
                    if (i != ordinal || supportsSetting(field, key))
                        destination.setValue(key, settings[i].getValue(key));
                }
            }
        }
        return TypeFields.result(union, beforeSize, length(union), before, describe(union.getComponent(ordinal)), "updated");
    }

    private static boolean supportsSetting(DataTypeComponent field, String key) {
        for (SettingsDefinition definition : field.getDataType().getSettingsDefinitions()) {
            if (key.equals(definition.getStorageKey())
                    && field.getDefaultSettings().isChangeAllowed(definition)) return true;
        }
        return false;
    }

    static JsonObject delete(Union union, int ordinal) {
        JsonObject before = describe(target(union, ordinal));
        int beforeSize = length(union);
        union.delete(ordinal);
        return TypeFields.result(union, beforeSize, length(union), before, null, "deleted");
    }
}
