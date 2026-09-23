package ghidracli.types;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.Union;
import ghidracli.protocol.JsonProtocol;
import java.util.ArrayList;
import java.util.List;

/** Read-only, unambiguous selection of one defined composite component. */
public final class TypeFieldTarget {
    private TypeFieldTarget() {}

    public static DataTypeComponent resolve(DataType target, JsonObject args) {
        if (!(target instanceof Structure) && !(target instanceof Union)) {
            throw new IllegalArgumentException("Type is not a struct or union: " + target.getPathName());
        }
        Composite type = (Composite) target;
        String selector = null;
        for (String key : new String[] { "field", "offset", "ordinal" }) {
            if (JsonProtocol.getArgString(args, key) == null) continue;
            if (selector != null) {
                throw new IllegalArgumentException("Exactly one of field, offset, or ordinal is required");
            }
            selector = key;
        }
        if (selector == null) {
            throw new IllegalArgumentException("Exactly one of field, offset, or ordinal is required");
        }
        if (selector.equals("offset") && type instanceof Union) {
            throw new IllegalArgumentException("Union members require --field or --ordinal");
        }
        String name = JsonProtocol.getArgString(args, "field");
        if (selector.equals("field") && name.isBlank()) {
            throw new IllegalArgumentException("Field name must not be empty");
        }
        int index = selector.equals("offset") ? StructureFields.offset(args)
            : selector.equals("ordinal") ? JsonProtocol.getNonnegativeIntArg(args, "ordinal", 0) : 0;
        DataTypeComponent[] components = type instanceof Structure structure
            ? structure.getDefinedComponents() : type.getComponents();
        List<DataTypeComponent> matches = new ArrayList<>();
        for (DataTypeComponent field : components) {
            boolean match = switch (selector) {
                case "field" -> name.equals(field.getFieldName());
                case "ordinal" -> index == field.getOrdinal();
                default -> field.getOffset() == index
                    || field.getOffset() < index && field.getEndOffset() >= index;
            };
            if (match) matches.add(field);
        }
        if (matches.size() > 1) {
            JsonArray candidates = new JsonArray();
            for (DataTypeComponent field : matches) candidates.add(StructureFields.describe(field));
            JsonObject detail = new JsonObject();
            detail.add("candidates", candidates);
            throw new JsonProtocol.CommandException("Ambiguous field " + selector + " in "
                + type.getPathName() + "; select a unique field name or ordinal", detail);
        }
        if (matches.isEmpty()) {
            throw new IllegalArgumentException("No defined field matches " + selector + " "
                + (selector.equals("field") ? name : index) + " in " + type.getPathName());
        }
        DataTypeComponent field = matches.get(0);
        if (selector.equals("offset") && field.getOffset() != index) {
            throw new IllegalArgumentException("Offset is inside a field; use its starting offset "
                + field.getOffset());
        }
        return field;
    }
}
