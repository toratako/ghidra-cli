package ghidracli;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.program.model.address.Address;
import ghidra.program.database.data.DataTypeUtilities;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.BitFieldDataType;
import ghidra.program.model.data.Dynamic;
import ghidra.program.model.data.FactoryDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.mem.MemoryBufferImpl;
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

    JsonObject handleTypeList(JsonObject args) throws ghidra.util.exception.CancelledException {
        if (session.program() == null) return errorResult("No program loaded");

        ListQuery query = new ListQuery(session, args);
        DataTypeManager dtm = session.program().getDataTypeManager();
        JsonArray types = new JsonArray();

        Iterator<DataType> dtIter = dtm.getAllDataTypes();
        while (dtIter.hasNext()) {
            if (query.isFull()) break;
            DataType dt = dtIter.next();

            if (!query.include(dt.getName())) {
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
            query.record();
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
            typeInfo.addProperty("packing_enabled", struct.isPackingEnabled());
            JsonArray components = new JsonArray();
            for (DataTypeComponent comp : struct.getComponents()) {
                components.add(StructureFields.describe(comp));
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
        if (typeName == null) return errorResult("Type name required");

        // This only ever creates an empty struct named `typeName` -- it does
        // NOT parse a C-style struct body. Reject anything that isn't a bare
        // identifier instead of silently creating a type literally named
        // after the whole (unparsed) string, e.g. `struct Foo {}` -- that
        // used to succeed and leave a garbage type behind with no error.
        if (!typeName.matches("[A-Za-z_][A-Za-z0-9_]*")) {
            return errorResult("Invalid type name: '" + typeName + "'. `type create struct` takes a "
                + "bare identifier and always creates an empty struct; build fields afterward "
                + "with `type add-field`. It does not parse a C-style struct definition.");
        }

        try {
            DataTypeManager dtm = session.program().getDataTypeManager();
            StructureDataType newStruct = new StructureDataType(typeName, 0);
            DataType registered = dtm.addDataType(newStruct, null);

            JsonObject result = new JsonObject();
            result.addProperty("status", "created");
            result.addProperty("name", registered.getName());
            result.addProperty("path", registered.getPathName());
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
            Address addr = AddressCodec.parse(session.program().getAddressFactory(), addressStr);
            if (addr == null) return errorResult("Invalid address: " + addressStr);

            DataType dataType = typeResolver.resolveDataType(typeName);
            if (dataType == null) {
                return errorResult("Type not found: " + typeName);
            }

            // Mirror listing applicability and sizing before any destructive clear.
            if (dataType instanceof FactoryDataType) {
                dataType = ((FactoryDataType) dataType).getDataType(
                    new MemoryBufferImpl(session.program().getMemory(), addr));
                if (dataType == null) return errorResult("Failed to resolve data type: " + typeName);
                dataType = dataType.clone(session.program().getDataTypeManager());
            }
            if (dataType instanceof BitFieldDataType)
                return errorResult("Bitfields not supported for Data");
            DataType baseType = dataType instanceof TypeDef
                ? ((TypeDef) dataType).getBaseDataType() : dataType;
            if (baseType instanceof FunctionDefinition)
                dataType = new PointerDataType(dataType, session.program().getDataTypeManager());
            int length = dataType instanceof Dynamic
                ? ((Dynamic) dataType).getLength(new MemoryBufferImpl(session.program().getMemory(), addr), -1)
                : dataType.getLength();
            if (length <= 0 || dataType.isZeroLength())
                return errorResult("Type must have a positive applicable data length: " + typeName);
            Address clearEnd = addr.addNoWrap(length - 1);
            if (!session.program().getMemory().contains(addr, clearEnd))
                return errorResult("Type range extends outside program memory: "
                    + AddressCodec.format(addr) + "-" + AddressCodec.format(clearEnd));

            // Captured before the clear below (which can silently remove the Function
            // object along with its code) so a `--force` that lands on a function's own
            // entry -- rather than an actual conflicting data unit -- is still reported.
            ghidra.program.model.listing.Function forcedFunctionEntry = force
                ? session.program().getFunctionManager().getFunctionAt(addr)
                : null;

            Listing listing = session.program().getListing();
            try {
                if (force) {
                    listing.clearCodeUnits(addr, clearEnd, false);
                }
                listing.createData(addr, dataType, length);
            } catch (ghidra.program.model.util.CodeUnitInsertionException e) {
                // Surface the conflicting code unit's own type/length/range.
                return typeApplyConflictError(addr, typeName, e);
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "applied");
            result.addProperty("address", AddressCodec.format(addr));
            result.addProperty("type", typeName);
            if (force) {
                result.addProperty("cleared_conflicting", true);
                // `--force` means force: clearing a function's own entry point (as opposed
                // to an actual conflicting data unit) "succeeds" the same way, but silently
                // -- `function get` still reports the function's old name/size afterward,
                // and only a later `function disassemble` failing with "No instruction at
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
            return errorResult("Failed to apply type: " + e.getMessage(), e);
        }
    }

    private JsonObject typeApplyConflictError(Address addr, String typeName, Exception cause) {
        Listing listing = session.program().getListing();
        CodeUnit cu = listing.getCodeUnitContaining(addr);

        JsonObject detail = new JsonObject();
        String description = "unknown";
        if (cu != null) {
            detail.addProperty("conflicting_start", AddressCodec.format(cu.getMinAddress()));
            detail.addProperty("conflicting_end", AddressCodec.format(cu.getMaxAddress()));
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
                    : "undefined data") + " spanning " + AddressCodec.format(cu.getMinAddress())
                    + "-" + AddressCodec.format(cu.getMaxAddress());
            }
        }

        JsonObject err = errorResult("Conflicting data exists at " + AddressCodec.format(addr) + " for type " + typeName
            + ": conflicts with " + description + ". Use --force to clear the conflicting range first.");
        err.add("detail", detail);
        return err;
    }

    JsonObject handleTypeDelete(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");
        String typeName = getArgString(args, "name");
        if (typeName == null || typeName.isEmpty()) return errorResult("Type name required");

        try {
            DataType dataType = typeResolver.resolveRegisteredDataType(typeName);
            if (dataType == null) return errorResult("Type not found: " + typeName);

            String fullPath = dataType.getPathName();
            DataTypeManager dtm = session.program().getDataTypeManager();
            boolean removed = dtm.remove(dataType, session.monitor());
            if (!removed) {
                return errorResult("Failed to remove type: " + typeName + " (may be in use or built-in)");
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "deleted");
            result.addProperty("name", typeName);
            result.addProperty("path", fullPath);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to delete type: " + e.getMessage(), e);
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

            dataType.setName(newName);
            if (!newName.equals(dataType.getName()))
                throw new IllegalArgumentException("Type cannot be renamed: " + oldName);

            JsonObject result = new JsonObject();
            result.addProperty("status", "renamed");
            result.addProperty("old_name", oldName);
            result.addProperty("new_name", newName);
            result.addProperty("path", dataType.getPathName());
            return result;
        } catch (Exception e) {
            return errorResult("Failed to rename type: " + e.getMessage(), e);
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
            DataType registered = dtm.addDataType(enumDt, null);

            JsonObject result = new JsonObject();
            result.addProperty("status", "created");
            result.addProperty("name", registered.getName());
            result.addProperty("path", registered.getPathName());
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
            TypedefDataType td = new TypedefDataType(name, baseType);
            DataType registered = dtm.addDataType(td, null);

            JsonObject result = new JsonObject();
            result.addProperty("status", "created");
            result.addProperty("name", registered.getName());
            result.addProperty("path", registered.getPathName());
            result.addProperty("kind", "typedef");
            result.addProperty("base_type", baseTypeName);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to create typedef: " + e.getMessage(), e);
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
            DataTypeUtilities.checkAncestry(struct, fieldDataType);
            Structure staged = (Structure) struct.copy(struct.getDataTypeManager());
            Integer size = StructureFields.size(args);
            if (size != null) {
                if ((long) StructureFields.length(struct) + size > Integer.MAX_VALUE)
                    return errorResult("Field size must fit within the structure");
                DataTypeComponent added = staged.add(fieldDataType, size, fieldName, null);
                if (added.getLength() != size)
                    return errorResult("Ghidra cannot honor --size " + size + " for field type " + fieldTypeName);
            } else {
                staged.add(fieldDataType, fieldName, null);
            }
            // Preserve existing components and their per-field default settings.
            if (size != null) struct.add(fieldDataType, size, fieldName, null);
            else struct.add(fieldDataType, fieldName, null);

            JsonObject result = new JsonObject();
            result.addProperty("status", "field_added");
            result.addProperty("struct", typeName);
            result.addProperty("field", fieldName);
            result.addProperty("field_type", fieldTypeName);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to add field: " + e.getMessage(), e);
        }
    }

    private Structure findStructure(JsonObject args) {
        String name = getArgString(args, "type_name");
        if (name == null || name.isBlank()) throw new IllegalArgumentException("Structure name required");
        DataType type = typeResolver.resolveDataType(name);
        if (type == null) throw new IllegalArgumentException("Type not found: " + name);
        if (!(type instanceof Structure)) throw new IllegalArgumentException("Type is not a struct: " + name);
        return (Structure) type;
    }

    JsonObject handleTypeSetField(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");
        try {
            Structure struct = findStructure(args);
            String typeName = getArgString(args, "field_type");
            DataType type = typeName == null ? null : typeResolver.resolveDataType(typeName);
            if (typeName != null && type == null) return errorResult("Field type not found: " + typeName);
            String comment = getArgString(args, "comment");
            return StructureFields.set(struct, StructureFields.offset(args),
                getArgString(args, "field_name"), type, comment, comment != null,
                StructureFields.size(args)).apply(struct);
        } catch (Exception e) {
            return errorResult("Failed to set field: " + e.getMessage(), e);
        }
    }

    JsonObject handleTypeClearField(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");
        try {
            Structure struct = findStructure(args);
            return StructureFields.clear(struct, StructureFields.offset(args)).apply(struct);
        } catch (Exception e) {
            return errorResult("Failed to clear field: " + e.getMessage(), e);
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

            struct.delete(ordinal);

            JsonObject result = new JsonObject();
            result.addProperty("status", "field_deleted");
            result.addProperty("struct", typeName);
            result.addProperty("field", fieldName);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to delete field: " + e.getMessage(), e);
        }
    }
}
