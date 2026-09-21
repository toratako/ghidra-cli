package ghidracli;

import com.google.gson.JsonNull;
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

    static int ordinal(JsonObject args) {
        if (JsonProtocol.getArgString(args, "ordinal") == null)
            throw new IllegalArgumentException("Union member ordinal is required; use --ordinal from type get");
        return JsonProtocol.getNonnegativeIntArg(args, "ordinal", 0);
    }

    private static DataTypeComponent target(Union union, int ordinal) {
        if (ordinal < 0 || ordinal >= union.getNumComponents())
            throw new IllegalArgumentException("Union member ordinal is outside the union: " + ordinal);
        DataTypeComponent field = union.getComponent(ordinal);
        if (field.isBitFieldComponent())
            throw new IllegalArgumentException("Bit-field members are not supported by union field edits");
        return field;
    }

    static int namedOrdinal(Union union, String name) {
        for (DataTypeComponent field : union.getComponents()) {
            if (name.equals(field.getFieldName())) return field.getOrdinal();
        }
        throw new IllegalArgumentException("Field not found: " + name + " in " + union.getPathName());
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

    static JsonObject add(Union union, String name, DataType type, Integer size) throws Exception {
        validateName(union, name, -1);
        type = fieldType(union, type, size);
        Union staged = (Union) union.copy(union.getDataTypeManager());
        DataTypeComponent field = staged.add(type, size == null ? type.getLength() : size, name, null);
        verifyField(field, name, size);
        int beforeSize = length(union);
        DataTypeComponent added = union.add(type, field.getLength(), name, null);
        return result(union, added.getOrdinal(), beforeSize, null, describe(added), "added");
    }

    static JsonObject set(Union union, int ordinal, String name, DataType type,
            String comment, Integer size) throws Exception {
        DataTypeComponent old = target(union, ordinal);
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
            return result(union, ordinal, beforeSize, before, before, "unchanged");

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
        return result(union, ordinal, beforeSize, before, describe(union.getComponent(ordinal)), "updated");
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
        return result(union, ordinal, beforeSize, before, null, "deleted");
    }

    private static JsonObject result(Union union, int ordinal, int beforeSize,
            JsonObject before, JsonObject after, String status) {
        JsonObject result = new JsonObject();
        result.addProperty("status", status);
        result.addProperty("changed", !status.equals("unchanged"));
        result.addProperty("union", union.getName());
        result.addProperty("path", union.getPathName());
        result.addProperty("ordinal", ordinal);
        result.addProperty("size_before", beforeSize);
        result.addProperty("size_after", length(union));
        result.add("before", before == null ? JsonNull.INSTANCE : before);
        result.add("after", after == null ? JsonNull.INSTANCE : after);
        return result;
    }
}
