package ghidracli;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.Union;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import java.util.Iterator;
import static ghidracli.JsonProtocol.errorResult;
import static ghidracli.JsonProtocol.getArgBool;
import static ghidracli.JsonProtocol.getArgInt;
import static ghidracli.JsonProtocol.getArgString;

final class TypeCommands {
    private final ProgramSession session;
    private final TypeResolver typeResolver;

    TypeCommands(ProgramSession session, TypeResolver typeResolver) {
        this.session = session;
        this.typeResolver = typeResolver;
    }

    JsonObject handleTypeList(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");

        int limit = getArgInt(args, "limit", 0);
        String nameFilter = getArgString(args, "filter");
        DataTypeManager dtm = session.program().getDataTypeManager();
        JsonArray types = new JsonArray();

        Iterator<DataType> dtIter = dtm.getAllDataTypes();
        int count = 0;
        while (dtIter.hasNext()) {
            DataType dt = dtIter.next();
            if (limit > 0 && count >= limit) break;

            if (nameFilter != null && !dt.getName().toLowerCase().contains(nameFilter.toLowerCase())) {
                continue;
            }

            JsonObject typeData = new JsonObject();
            typeData.addProperty("name", dt.getName());
            typeData.addProperty("path", dt.getPathName());
            typeData.addProperty("category", dt.getCategoryPath().toString());
            typeData.addProperty("size", dt.getLength());
            String kind;
            if (dt instanceof Structure) kind = "struct";
            else if (dt instanceof Union) kind = "union";
            else if (dt instanceof ghidra.program.model.data.Enum) kind = "enum";
            else if (dt instanceof TypeDef) kind = "typedef";
            else if (dt instanceof FunctionDefinition) kind = "functiondef";
            else if (dt instanceof Pointer) kind = "pointer";
            else if (dt instanceof Array) kind = "array";
            else kind = "other";
            typeData.addProperty("kind", kind);
            types.add(typeData);
            count++;
        }

        JsonObject result = new JsonObject();
        result.add("types", types);
        result.addProperty("count", types.size());
        return result;
    }

    JsonObject handleTypeGet(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");

        String typeName = getArgString(args, "name");
        if (typeName == null) return errorResult("Type name required");

        DataType dataType = typeResolver.resolveDataType(typeName);
        if (dataType == null) {
            return errorResult("Type not found: " + typeName);
        }

        JsonObject typeInfo = new JsonObject();
        typeInfo.addProperty("name", dataType.getName());
        typeInfo.addProperty("path", dataType.getPathName());
        typeInfo.addProperty("category", dataType.getCategoryPath().toString());
        typeInfo.addProperty("size", dataType.getLength());
        typeInfo.addProperty("description", dataType.getDescription());

        if (dataType instanceof Structure) {
            typeInfo.addProperty("kind", "struct");
            Structure struct = (Structure) dataType;
            JsonArray components = new JsonArray();
            for (DataTypeComponent comp : struct.getComponents()) {
                JsonObject compObj = new JsonObject();
                compObj.addProperty("name", comp.getFieldName());
                compObj.addProperty("type", comp.getDataType().getName());
                compObj.addProperty("offset", comp.getOffset());
                compObj.addProperty("size", comp.getLength());
                components.add(compObj);
            }
            typeInfo.add("components", components);
        } else if (dataType instanceof Union) {
            typeInfo.addProperty("kind", "union");
            Union union = (Union) dataType;
            JsonArray components = new JsonArray();
            for (DataTypeComponent comp : union.getComponents()) {
                JsonObject compObj = new JsonObject();
                compObj.addProperty("name", comp.getFieldName());
                compObj.addProperty("type", comp.getDataType().getName());
                compObj.addProperty("offset", comp.getOffset());
                compObj.addProperty("size", comp.getLength());
                components.add(compObj);
            }
            typeInfo.add("components", components);
        } else if (dataType instanceof ghidra.program.model.data.Enum) {
            typeInfo.addProperty("kind", "enum");
            ghidra.program.model.data.Enum enumType = (ghidra.program.model.data.Enum) dataType;
            JsonArray members = new JsonArray();
            for (String name : enumType.getNames()) {
                JsonObject member = new JsonObject();
                member.addProperty("name", name);
                member.addProperty("value", enumType.getValue(name));
                members.add(member);
            }
            typeInfo.add("members", members);
        } else if (dataType instanceof TypeDef) {
            typeInfo.addProperty("kind", "typedef");
            TypeDef td = (TypeDef) dataType;
            typeInfo.addProperty("base_type", td.getDataType().getName());
            typeInfo.addProperty("base_type_path", td.getDataType().getPathName());
        } else if (dataType instanceof FunctionDefinition) {
            typeInfo.addProperty("kind", "functiondef");
        } else if (dataType instanceof Pointer) {
            typeInfo.addProperty("kind", "pointer");
        } else if (dataType instanceof Array) {
            typeInfo.addProperty("kind", "array");
        } else {
            typeInfo.addProperty("kind", "other");
        }

        return typeInfo;
    }

    JsonObject handleTypeCreate(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");

        String typeName = getArgString(args, "definition");
        if (typeName == null) typeName = getArgString(args, "name");
        if (typeName == null) return errorResult("Type name required");

        // This only ever creates an empty struct named `typeName` -- it does
        // NOT parse a C-style struct body. Reject anything that isn't a bare
        // identifier instead of silently creating a type literally named
        // after the whole (unparsed) string, e.g. `struct Foo {}` -- that
        // used to succeed and leave a garbage type behind with no error.
        if (!typeName.matches("[A-Za-z_][A-Za-z0-9_]*")) {
            return errorResult("Invalid type name: '" + typeName + "'. `type create` takes a "
                + "bare identifier and always creates an empty struct; build fields afterward "
                + "with `type add-field`. It does not parse a C-style struct definition.");
        }

        try {
            DataTypeManager dtm = session.program().getDataTypeManager();
            ProgramTransaction transaction = session.transaction("Create type");
            try {
                StructureDataType newStruct = new StructureDataType(typeName, 0);
                dtm.addDataType(newStruct, null);
                transaction.end(true);
            } catch (Exception e) {
                transaction.end(true);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "created");
            result.addProperty("name", typeName);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to create type: " + e.getMessage());
        }
    }

    JsonObject handleTypeApply(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");

        String addressStr = getArgString(args, "address");
        String typeName = getArgString(args, "type_name");
        boolean force = getArgBool(args, "force", false);
        if (addressStr == null || typeName == null) {
            return errorResult("Address and type_name required");
        }

        try {
            Address addr = session.program().getAddressFactory().getAddress(addressStr);
            if (addr == null) return errorResult("Invalid address: " + addressStr);

            DataType dataType = typeResolver.resolveDataType(typeName);
            if (dataType == null) {
                return errorResult("Type not found: " + typeName);
            }

            // Captured before the clear below (which can silently remove the Function
            // object along with its code) so a `--force` that lands on a function's own
            // entry -- rather than an actual conflicting data unit -- is still reported.
            ghidra.program.model.listing.Function forcedFunctionEntry = force
                ? session.program().getFunctionManager().getFunctionAt(addr)
                : null;

            Listing listing = session.program().getListing();
            ProgramTransaction transaction = session.transaction("Apply type");
            try {
                if (force) {
                    int len = dataType.getLength();
                    Address clearEnd = len > 0 ? addr.add(len - 1) : addr;
                    listing.clearCodeUnits(addr, clearEnd, false);
                }
                listing.createData(addr, dataType);
                transaction.end(true);
            } catch (ghidra.program.model.util.CodeUnitInsertionException e) {
                transaction.end(true);
    /** Surface the conflicting code unit's own type/length/range instead of just "Conflicting data exists". */
                return typeApplyConflictError(addr, typeName, e);
            } catch (Exception e) {
                transaction.end(true);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "applied");
            result.addProperty("address", addressStr);
            result.addProperty("type", typeName);
            if (force) {
                result.addProperty("cleared_conflicting", true);
                // `--force` means force: clearing a function's own entry point (as opposed
                // to an actual conflicting data unit) "succeeds" the same way, but silently
                // -- `function get` still reports the function's old name/size afterward,
                // and only a later `function disasm` failing with "No instruction at
                // address" exposes the corruption. Flag it here instead.
                if (forcedFunctionEntry != null) {
                    result.addProperty("is_function_entry", true);
                    result.addProperty("warning", "Cleared the entry point of function '"
                        + forcedFunctionEntry.getName() + "' (code, not a conflicting data "
                        + "unit) and replaced it with " + typeName
                        + " data -- the function's code is gone, not just its conflicting bytes.");
                }
            }
            return result;
        } catch (Exception e) {
            return errorResult("Failed to apply type: " + e.getMessage());
        }
    }

    private JsonObject typeApplyConflictError(Address addr, String typeName, Exception cause) {
        Listing listing = session.program().getListing();
        CodeUnit cu = listing.getCodeUnitContaining(addr);

        JsonObject detail = new JsonObject();
        String description = "unknown";
        if (cu != null) {
            detail.addProperty("conflicting_start", cu.getMinAddress().toString());
            detail.addProperty("conflicting_end", cu.getMaxAddress().toString());
            detail.addProperty("conflicting_length", cu.getLength());
            if (cu instanceof Instruction) {
                detail.addProperty("conflicting_kind", "instruction");
                detail.addProperty("conflicting_mnemonic", ((Instruction) cu).getMnemonicString());
                description = "an instruction (" + ((Instruction) cu).getMnemonicString() + ")";
            } else if (cu instanceof Data) {
                Data d = (Data) cu;
                detail.addProperty("conflicting_kind", "data");
                detail.addProperty("conflicting_type", d.getDataType().getName());
                detail.addProperty("conflicting_defined", d.isDefined());
                description = (d.isDefined() ? "defined data of type " + d.getDataType().getName()
                    : "undefined data") + " spanning " + cu.getMinAddress() + "-" + cu.getMaxAddress();
            }
        }

        JsonObject err = errorResult("Conflicting data exists at " + addr + " for type " + typeName
            + ": conflicts with " + description + ". Use --force to clear the conflicting range first.");
        err.add("detail", detail);
        return err;
    }

    JsonObject handleTypeDelete(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");
        String typeName = getArgString(args, "name");
        if (typeName == null || typeName.isEmpty()) return errorResult("Type name required");

        try {
            DataType dataType = typeResolver.resolveDataType(typeName);
            if (dataType == null) return errorResult("Type not found: " + typeName);

            String fullPath = dataType.getPathName();
            DataTypeManager dtm = session.program().getDataTypeManager();
            ProgramTransaction transaction = session.transaction("Delete type");
            try {
                boolean removed = dtm.remove(dataType, session.monitor());
                transaction.end(true);
                if (!removed) {
                    return errorResult("Failed to remove type: " + typeName + " (may be in use or built-in)");
                }
            } catch (Exception e) {
                transaction.end(true);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "deleted");
            result.addProperty("name", typeName);
            result.addProperty("path", fullPath);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to delete type: " + e.getMessage());
        }
    }

    JsonObject handleTypeRename(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");
        String oldName = getArgString(args, "old_name");
        String newName = getArgString(args, "new_name");
        if (oldName == null || oldName.isEmpty()) return errorResult("Old type name required");
        if (newName == null || newName.isEmpty()) return errorResult("New type name required");

        try {
            DataType dataType = typeResolver.resolveDataType(oldName);
            if (dataType == null) return errorResult("Type not found: " + oldName);

            ProgramTransaction transaction = session.transaction("Rename type");
            try {
                dataType.setName(newName);
                transaction.end(true);
            } catch (Exception e) {
                transaction.end(true);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "renamed");
            result.addProperty("old_name", oldName);
            result.addProperty("new_name", newName);
            result.addProperty("path", dataType.getPathName());
            return result;
        } catch (Exception e) {
            return errorResult("Failed to rename type: " + e.getMessage());
        }
    }

    JsonObject handleTypeCreateEnum(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");
        String name = getArgString(args, "name");
        String valuesStr = getArgString(args, "values");
        int size = getArgInt(args, "size", 4);
        if (name == null || valuesStr == null) return errorResult("name and values required");

        if (size != 1 && size != 2 && size != 4 && size != 8)
            return errorResult("Enum size must be 1, 2, 4, or 8");

        try {
            DataTypeManager dtm = session.program().getDataTypeManager();
            ProgramTransaction transaction = session.transaction("Create enum");
            try {
                EnumDataType enumDt = new EnumDataType(name, size);
                String[] pairs = valuesStr.split(",");
                for (String pair : pairs) {
                    String[] kv = pair.trim().split("=", 2);
                    if (kv.length != 2)
                        throw new IllegalArgumentException("Invalid KEY=VALUE pair: " + pair.trim());
                    String key = kv[0].trim();
                    long value = Long.decode(kv[1].trim());
                    enumDt.add(key, value);
                }
                dtm.addDataType(enumDt, null);
                transaction.end(true);
            } catch (Exception e) {
                transaction.end(true);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "created");
            result.addProperty("name", name);
            result.addProperty("kind", "enum");
            result.addProperty("size", size);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to create enum: " + e.getMessage());
        }
    }

    JsonObject handleTypeTypedef(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");
        String name = getArgString(args, "name");
        String baseTypeName = getArgString(args, "base_type");
        if (name == null || baseTypeName == null) return errorResult("name and base_type required");

        try {
            DataType baseType = typeResolver.resolveDataType(baseTypeName);
            if (baseType == null) return errorResult("Base type not found: " + baseTypeName);

            DataTypeManager dtm = session.program().getDataTypeManager();
            ProgramTransaction transaction = session.transaction("Create typedef");
            try {
                TypedefDataType td = new TypedefDataType(name, baseType);
                dtm.addDataType(td, null);
                transaction.end(true);
            } catch (Exception e) {
                transaction.end(true);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "created");
            result.addProperty("name", name);
            result.addProperty("kind", "typedef");
            result.addProperty("base_type", baseTypeName);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to create typedef: " + e.getMessage());
        }
    }

    JsonObject handleTypeAddField(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");
        String typeName = getArgString(args, "type_name");
        String fieldName = getArgString(args, "field_name");
        String fieldTypeName = getArgString(args, "field_type");
        if (typeName == null || fieldName == null || fieldTypeName == null)
            return errorResult("type_name, field_name, and field_type required");

        try {
            DataType structType = typeResolver.resolveDataType(typeName);
            if (structType == null) return errorResult("Type not found: " + typeName);
            if (!(structType instanceof Structure))
                return errorResult("Type is not a struct: " + typeName);

            DataType fieldDataType = typeResolver.resolveDataType(fieldTypeName);
            if (fieldDataType == null) return errorResult("Field type not found: " + fieldTypeName);

            Structure struct = (Structure) structType;
            ProgramTransaction transaction = session.transaction("Add field to struct");
            try {
                int offset = getArgInt(args, "offset", -1);
                if (offset >= 0) {
                    // replaceAtOffset() places the field at that exact byte offset,
                    // never shifting components that sit elsewhere -- insertAtOffset()
                    // instead shifts every later field by the new field's size, which
                    // silently corrupts a struct being built (or patched) offset-by-offset
                    // out of order. Unlike insertAtOffset(), replaceAtOffset() does not
                    // grow the structure itself, so grow it first when the field falls
                    // past the current end (the common case: fields added in ascending
                    // offset order into a struct that's only as big as its last field).
                    int fieldSize = getArgInt(args, "size", fieldDataType.getLength());
                    // A brand-new struct (StructureDataType(name, 0)) has zero real
                    // components but getLength() still reports 1 (Ghidra's minimum
                    // displayable data type length) rather than the true internal 0 --
                    // growing off that reported length silently comes up 1 byte short
                    // for the first field. Use 0 as the starting length until a
                    // component actually exists, when getLength() is accurate.
                    int currentLength = struct.getNumComponents() == 0 ? 0 : struct.getLength();
                    int needed = (offset + fieldSize) - currentLength;
                    if (needed > 0) {
                        struct.growStructure(needed);
                    }
                    struct.replaceAtOffset(offset, fieldDataType, fieldSize, fieldName, null);
                } else {
                    struct.add(fieldDataType, fieldName, null);
                }
                transaction.end(true);
            } catch (Exception e) {
                transaction.end(true);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "field_added");
            result.addProperty("struct", typeName);
            result.addProperty("field", fieldName);
            result.addProperty("field_type", fieldTypeName);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to add field: " + e.getMessage());
        }
    }

    JsonObject handleTypeDelField(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");
        String typeName = getArgString(args, "type_name");
        String fieldName = getArgString(args, "field_name");
        if (typeName == null || fieldName == null)
            return errorResult("type_name and field_name required");

        try {
            DataType structType = typeResolver.resolveDataType(typeName);
            if (structType == null) return errorResult("Type not found: " + typeName);
            if (!(structType instanceof Structure))
                return errorResult("Type is not a struct: " + typeName);

            Structure struct = (Structure) structType;
            int ordinal = -1;
            for (DataTypeComponent comp : struct.getComponents()) {
                if (fieldName.equals(comp.getFieldName())) {
                    ordinal = comp.getOrdinal();
                    break;
                }
            }
            if (ordinal < 0)
                return errorResult("Field not found: " + fieldName + " in " + typeName);

            ProgramTransaction transaction = session.transaction("Delete field from struct");
            try {
                struct.delete(ordinal);
                transaction.end(true);
            } catch (Exception e) {
                transaction.end(true);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "field_deleted");
            result.addProperty("struct", typeName);
            result.addProperty("field", fieldName);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to delete field: " + e.getMessage());
        }
    }
}
