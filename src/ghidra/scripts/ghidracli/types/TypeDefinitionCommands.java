package ghidracli.types;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.docking.settings.Settings;
import ghidra.program.model.data.BitFieldDataType;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.SourceArchive;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Union;
import ghidracli.session.ProgramSession;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Objects;

import static ghidracli.protocol.JsonProtocol.errorResult;
import static ghidracli.protocol.JsonProtocol.getArgString;

public final class TypeDefinitionCommands {
    private final ProgramSession session;
    private final TypeResolver typeResolver;

    public TypeDefinitionCommands(ProgramSession session, TypeResolver typeResolver) {
        this.session = session;
        this.typeResolver = typeResolver;
    }

    public JsonObject handleClone(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");
        try {
            DataType source = editableType(getArgString(args, "type_name"));
            String name = getArgString(args, "new_name");
            if (name == null || name.isBlank() || name.indexOf('/') >= 0)
                throw new IllegalArgumentException("New type name must be a non-empty simple name");
            DataTypeManager dtm = session.program().getDataTypeManager();
            String category = getArgString(args, "category");
            CategoryPath path = category == null ? source.getCategoryPath() : categoryPath(category);
            requireCategory(dtm, path);
            requireVacant(dtm, path, name);

            // copy, unlike clone, assigns a new identity and drops source-archive
            // association. Using the same manager keeps all dependencies shared,
            // including pointers back to the original definition.
            DataType copy = source.copy(dtm);
            copy.setName(name);
            copy.setCategoryPath(path);
            DataType registered = dtm.addDataType(copy, null);
            if (!registered.getName().equals(name) || !registered.getCategoryPath().equals(path)
                    || registered == source || registered.getUniversalID() == null
                    || Objects.equals(registered.getUniversalID(), source.getUniversalID()))
                throw new IllegalArgumentException("Ghidra could not create an independent type at the requested path");
            SourceArchive archive = registered.getSourceArchive();
            if (archive != null && !Objects.equals(archive.getSourceArchiveID(), dtm.getUniversalID())
                    && !Objects.equals(archive.getSourceArchiveID(), DataTypeManager.LOCAL_ARCHIVE_UNIVERSAL_ID))
                throw new IllegalArgumentException("Cloned type retained an external source archive");

            // Native copy/resolve omit presentation settings. Restore only values
            // explicitly stored on this definition; inherited defaults remain shared.
            copySettings(source.getDefaultSettings(), registered.getDefaultSettings());
            if (source instanceof Composite) {
                preserveComponents((Composite) source, (Composite) registered);
            }
            JsonObject result = typeResult(registered, "cloned", true);
            result.addProperty("source_path", source.getPathName());
            return result;
        } catch (Exception e) {
            return errorResult("Failed to clone type: " + e.getMessage(), e);
        }
    }

    public JsonObject handleMove(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");
        try {
            DataType type = editableType(getArgString(args, "type_name"));
            CategoryPath destination = categoryPath(getArgString(args, "category"));
            DataTypeManager dtm = session.program().getDataTypeManager();
            requireCategory(dtm, destination);
            String oldPath = type.getPathName();
            boolean changed = !destination.equals(type.getCategoryPath());
            if (changed) {
                requireVacant(dtm, destination, type.getName());
                type.setCategoryPath(destination);
                if (!destination.equals(type.getCategoryPath()))
                    throw new IllegalArgumentException("Type cannot be moved: " + oldPath);
            }
            JsonObject result = typeResult(type, changed ? "moved" : "unchanged", changed);
            result.addProperty("old_path", oldPath);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to move type: " + e.getMessage(), e);
        }
    }

    public JsonObject handleCategoryList(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");
        try {
            CategoryPath path = categoryPath(getArgString(args, "path"));
            Category category = requireCategory(session.program().getDataTypeManager(), path);
            Category[] children = category.getCategories();
            Arrays.sort(children, Comparator.comparing(Category::getName));
            JsonArray rows = new JsonArray();
            for (Category child : children) {
                session.monitor().checkCancelled();
                JsonObject row = new JsonObject();
                row.addProperty("name", child.getName());
                row.addProperty("path", child.getCategoryPath().getPath());
                row.addProperty("type_count", child.getDataTypes().length);
                rows.add(row);
            }
            JsonObject result = new JsonObject();
            result.addProperty("path", path.getPath());
            result.add("categories", rows);
            result.addProperty("count", rows.size());
            return result;
        } catch (Exception e) {
            return errorResult("Failed to list type categories: " + e.getMessage(), e);
        }
    }

    public JsonObject handleCategoryCreate(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");
        try {
            CategoryPath path = categoryPath(getArgString(args, "path"));
            DataTypeManager dtm = session.program().getDataTypeManager();
            boolean changed = dtm.getCategory(path) == null;
            if (changed) dtm.createCategory(path);
            return categoryResult(path, changed ? "created" : "unchanged", changed);
        } catch (Exception e) {
            return errorResult("Failed to create type category: " + e.getMessage(), e);
        }
    }

    public JsonObject handleCategoryDelete(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");
        try {
            CategoryPath path = categoryPath(getArgString(args, "path"));
            if (path.isRoot()) throw new IllegalArgumentException("Root category cannot be deleted");
            Category category = requireCategory(session.program().getDataTypeManager(), path);
            if (category.getDataTypes().length != 0 || category.getCategories().length != 0)
                throw new IllegalArgumentException("Category is not empty: " + path);
            if (!category.getParent().removeEmptyCategory(category.getName(), session.monitor()))
                throw new IllegalArgumentException("Ghidra could not delete category: " + path);
            return categoryResult(path, "deleted", true);
        } catch (Exception e) {
            return errorResult("Failed to delete type category: " + e.getMessage(), e);
        }
    }

    private DataType editableType(String name) {
        if (name == null || name.isBlank()) throw new IllegalArgumentException("Type name required");
        DataType type = typeResolver.resolveRegisteredDataType(name);
        if (type == null) throw new IllegalArgumentException("Registered type not found: " + name);
        if (!(type instanceof Structure) && !(type instanceof Union)
                && !(type instanceof ghidra.program.model.data.Enum)
                && !(type instanceof FunctionDefinition) && !(type instanceof TypeDef))
            throw new IllegalArgumentException("Type is not an editable named definition: " + name);
        if (type instanceof TypeDef && ((TypeDef) type).isAutoNamed())
            throw new IllegalArgumentException("Auto-named typedef is not an editable named definition: " + name);
        return type;
    }

    private static CategoryPath categoryPath(String value) {
        if (value == null || !value.startsWith("/") || value.chars().anyMatch(Character::isISOControl))
            throw new IllegalArgumentException("Category path must be an absolute canonical path");
        CategoryPath path = new CategoryPath(value);
        if (!path.getPath().equals(value))
            throw new IllegalArgumentException("Category path must be canonical: " + value);
        for (CategoryPath part = path; !part.isRoot(); part = part.getParent()) {
            if (part.getName().isBlank() || part.getName().equals(".") || part.getName().equals(".."))
                throw new IllegalArgumentException("Category path must contain non-empty named components: " + value);
        }
        return path;
    }

    private static Category requireCategory(DataTypeManager dtm, CategoryPath path) {
        Category category = dtm.getCategory(path);
        if (category == null) throw new IllegalArgumentException("Category not found: " + path);
        return category;
    }

    private static void requireVacant(DataTypeManager dtm, CategoryPath path, String name) {
        DataType existing = dtm.getDataType(path, name);
        if (existing != null) throw new IllegalArgumentException("Type already exists: " + existing.getPathName());
    }

    private static void copySettings(Settings source, Settings destination) {
        for (String key : source.getNames()) {
            Object value = source.getValue(key);
            destination.setValue(key, value);
            if (!Objects.equals(value, destination.getValue(key)))
                throw new IllegalArgumentException("Ghidra could not preserve setting: " + key);
        }
    }

    private static void preserveComponents(Composite source, Composite destination) {
        if (source.getLength() != destination.getLength() || source.isZeroLength() != destination.isZeroLength()
                || source.getPackingType() != destination.getPackingType()
                || source.getExplicitPackingValue() != destination.getExplicitPackingValue()
                || source.getAlignmentType() != destination.getAlignmentType()
                || source.getExplicitMinimumAlignment() != destination.getExplicitMinimumAlignment())
            throw new IllegalArgumentException("Ghidra could not preserve the composite layout");
        DataTypeComponent[] original = source.getDefinedComponents();
        DataTypeComponent[] copied = destination.getDefinedComponents();
        if (original.length != copied.length)
            throw new IllegalArgumentException("Ghidra could not preserve the composite components");
        for (int i = 0; i < original.length; i++) {
            DataTypeComponent before = original[i];
            DataTypeComponent after = copied[i];
            if (before.getOrdinal() != after.getOrdinal() || before.getOffset() != after.getOffset()
                    || before.getLength() != after.getLength()
                    || !Objects.equals(before.getFieldName(), after.getFieldName())
                    || !Objects.equals(before.getComment(), after.getComment())
                    || !sameDependency(before.getDataType(), after.getDataType()))
                throw new IllegalArgumentException("Ghidra could not preserve component " + before.getOrdinal());
            copySettings(before.getDefaultSettings(), after.getDefaultSettings());
        }
    }

    private static boolean sameDependency(DataType before, DataType after) {
        if (before == after) return true;
        if (!(before instanceof BitFieldDataType) || !(after instanceof BitFieldDataType)) return false;
        BitFieldDataType original = (BitFieldDataType) before;
        BitFieldDataType copied = (BitFieldDataType) after;
        return original.getBaseDataType() == copied.getBaseDataType()
            && original.getDeclaredBitSize() == copied.getDeclaredBitSize()
            && original.getBitSize() == copied.getBitSize()
            && original.getBitOffset() == copied.getBitOffset();
    }

    private static JsonObject typeResult(DataType type, String status, boolean changed) {
        JsonObject result = categoryResult(type.getCategoryPath(), status, changed);
        result.addProperty("name", type.getName());
        result.addProperty("path", type.getPathName());
        return result;
    }

    private static JsonObject categoryResult(CategoryPath path, String status, boolean changed) {
        JsonObject result = new JsonObject();
        result.addProperty("status", status);
        result.addProperty("path", path.getPath());
        result.addProperty("changed", changed);
        return result;
    }
}
