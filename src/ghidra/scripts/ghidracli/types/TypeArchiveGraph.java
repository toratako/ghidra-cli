package ghidracli.types;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.docking.settings.Settings;
import ghidra.docking.settings.SettingsDefinition;
import ghidra.program.model.data.*;
import ghidra.util.task.TaskMonitor;
import java.util.*;

/** Dependency closure and checks independent of Ghidra's resolve equivalence cache. */
final class TypeArchiveGraph {
    private final SortedMap<String, DataType> types = new TreeMap<>();
    private final Map<String, JsonObject> layouts = new HashMap<>();
    private final Set<String> roots = new TreeSet<>();

    TypeArchiveGraph(Collection<DataType> selected, TaskMonitor monitor) throws Exception {
        Set<DataType> visited = Collections.newSetFromMap(new IdentityHashMap<>());
        Deque<DataType> pending = new ArrayDeque<>(selected);
        for (DataType type : selected) roots.add(type.getPathName());
        while (!pending.isEmpty()) {
            monitor.checkCancelled();
            DataType type = pending.removeFirst();
            if (!visited.add(type)) continue;
            if (type instanceof MissingBuiltInDataType || type instanceof BadDataType)
                throw new IllegalArgumentException("Unavailable data type in archive graph: " + type.getPathName());
            // Bitfields are component values rather than registered definitions.
            // Their individual bit offsets are captured on each component below.
            if (!(type instanceof BitFieldDataType)) {
                types.put(type.getPathName(), type);
                layouts.put(type.getPathName(), layout(type));
            }
            pending.addAll(children(type));
        }
    }

    static boolean selectable(DataType type) {
        return type instanceof Composite || type instanceof ghidra.program.model.data.Enum
            || type instanceof FunctionDefinition
            || type instanceof TypeDef && !((TypeDef) type).isAutoNamed();
    }

    static List<DataType> candidates(DataTypeManager manager, TaskMonitor monitor) throws Exception {
        List<DataType> result = new ArrayList<>();
        Iterator<DataType> iterator = manager.getAllDataTypes();
        while (iterator.hasNext()) {
            monitor.checkCancelled();
            DataType type = iterator.next();
            if (selectable(type)) result.add(type);
        }
        result.sort(Comparator.comparing(DataType::getPathName));
        return result;
    }

    /** Resolve only after checking *all* dependencies, including built-ins. */
    JsonObject transfer(DataTypeManager destination, TaskMonitor monitor) throws Exception {
        Map<String, DataType> reusable = preflight(destination, monitor);
        Map<String, JsonObject> before = new HashMap<>();
        reusable.forEach((path, type) -> before.put(path, describe(type)));
        DataTypeConflictHandler strict = new DataTypeConflictHandler() {
            private void checked(DataType source, DataType existing) {
                // Never call isEquivalent from this callback: Ghidra's in-progress
                // equivalence cache may say true for a pair it has not compared.
                if (reusable.get(source.getPathName()) != existing)
                    throw conflict(source, existing, "resolve conflict");
            }
            @Override
            public ConflictResult resolveConflict(DataType source, DataType existing) {
                checked(source, existing);
                return ConflictResult.USE_EXISTING;
            }
            @Override
            public boolean shouldUpdate(DataType source, DataType existing) {
                checked(source, existing);
                return false;
            }
            @Override
            public DataTypeConflictHandler getSubsequentHandler() { return this; }
        };
        List<DataType> selected = new ArrayList<>();
        for (String path : roots) selected.add(types.get(path));
        // One native resolve cache covers shared dependencies and recursive roots.
        destination.addDataTypes(selected, strict, monitor);
        List<DataType> resolvedRoots = resolveRoots(destination);
        TypeArchiveGraph copied = new TypeArchiveGraph(resolvedRoots, monitor);
        for (String path : types.keySet()) {
            monitor.checkCancelled();
            DataType target = copied.types.get(path);
            if (target != null) preserveSettings(types.get(path), target);
        }
        TypeArchiveGraph resolved = verify(resolvedRoots, monitor);
        JsonArray rows = new JsonArray();
        JsonArray dependencies = new JsonArray();
        for (Map.Entry<String, DataType> entry : types.entrySet()) {
            monitor.checkCancelled();
            String path = entry.getKey();
            // Report named definitions. Wrappers and built-ins still participate
            // in conflict/layout verification, but are not independent edits.
            if (!selectable(entry.getValue())) continue;
            JsonObject row = describe(resolved.types.get(path));
            row.addProperty("role", roots.contains(path) ? "root" : "dependency");
            JsonObject previous = before.get(path);
            boolean associated = previous != null && (!Objects.equals(previous.get("universal_id"), row.get("universal_id"))
                || !Objects.equals(previous.get("source_archive"), row.get("source_archive")));
            row.addProperty("status", previous == null ? "created" : associated ? "associated" : "reused");
            row.add("source_type", describe(entry.getValue()));
            rows.add(row);
            if (!roots.contains(path)) dependencies.add(path);
        }
        JsonObject result = new JsonObject();
        JsonArray rootRows = new JsonArray();
        roots.forEach(rootRows::add);
        result.add("roots", rootRows);
        result.add("dependencies", dependencies);
        result.add("types", rows);
        result.addProperty("count", rows.size());
        return result;
    }

    void verify(DataTypeManager destination, TaskMonitor monitor) throws Exception {
        verify(resolveRoots(destination), monitor);
    }

    private List<DataType> resolveRoots(DataTypeManager destination) {
        List<DataType> selected = new ArrayList<>();
        for (String path : roots) {
            DataType type = destination.getDataType(path);
            if (type == null) throw new IllegalArgumentException("Archive definition missing: " + path);
            selected.add(type);
        }
        return selected;
    }

    private TypeArchiveGraph verify(Collection<DataType> selected, TaskMonitor monitor) throws Exception {
        TypeArchiveGraph actual = new TypeArchiveGraph(selected, monitor);
        if (!types.keySet().equals(actual.types.keySet()))
            throw new IllegalArgumentException("Resolved type dependency paths differ from the source graph");
        for (String path : types.keySet()) {
            monitor.checkCancelled();
            DataType before = types.get(path);
            DataType after = actual.types.get(path);
            if (!layouts.get(path).equals(actual.layouts.get(path)) || !before.isEquivalent(after))
                throw new IllegalArgumentException("Type layout or definition changed while resolving " + path);
            requireSettings(before, after);
            SourceArchive sourceArchive = before.getSourceArchive();
            if (before.getUniversalID() != null && sourceArchive != null && sourceArchive.getArchiveType() == ArchiveType.FILE
                    && (!Objects.equals(before.getUniversalID(), after.getUniversalID())
                        || after.getSourceArchive() == null
                        || !Objects.equals(sourceArchive.getSourceArchiveID(), after.getSourceArchive().getSourceArchiveID())))
                throw new IllegalArgumentException("Source archive identity changed while resolving " + path);
        }
        return actual;
    }

    private Map<String, DataType> preflight(DataTypeManager destination, TaskMonitor monitor) throws Exception {
        Map<String, DataType> reusable = new HashMap<>();
        for (DataType source : types.values()) {
            monitor.checkCancelled();
            DataType atPath = destination.getDataType(source.getPathName());
            if (atPath != null) {
                requireEquivalent(source, atPath);
                SourceArchive incomingArchive = source.getSourceArchive();
                SourceArchive existingArchive = atPath.getSourceArchive();
                if (source.getUniversalID() != null && incomingArchive != null && existingArchive != null
                        && incomingArchive.getArchiveType() == ArchiveType.FILE
                        && existingArchive.getArchiveType() == ArchiveType.FILE
                        && (!Objects.equals(incomingArchive.getSourceArchiveID(), existingArchive.getSourceArchiveID())
                            || !Objects.equals(source.getUniversalID(), atPath.getUniversalID())))
                    throw conflict(source, atPath, "different source archives");
                reusable.put(source.getPathName(), atPath);
            }
            if (source instanceof FunctionDefinition) {
                FunctionDefinition function = (FunctionDefinition) source;
                if (!function.hasUnknownCallingConventionName()) {
                    var targetConvention = destination.getCallingConvention(function.getCallingConventionName());
                    var sourceConvention = function.getCallingConvention();
                    if (targetConvention == null || sourceConvention != null
                            && !sourceConvention.isEquivalent(targetConvention))
                        throw new IllegalArgumentException("Function calling convention is incompatible: " + source.getPathName());
                }
            }
            SourceArchive origin = source.getSourceArchive();
            if (origin != null && source.getUniversalID() != null) {
                DataType byIdentity = destination.getDataType(origin, source.getUniversalID());
                if (byIdentity != null) {
                    requireEquivalent(source, byIdentity);
                    if (!source.getPathName().equals(byIdentity.getPathName()))
                        throw conflict(source, byIdentity, "source identity occurs at a different path");
                    reusable.put(source.getPathName(), byIdentity);
                }
            }
        }
        return reusable;
    }

    private static void requireEquivalent(DataType source, DataType existing) {
        if (!layout(source).equals(layout(existing)) || !source.isEquivalent(existing))
            throw conflict(source, existing, "non-equivalent definition");
        requireSettings(source, existing);
    }

    private static void requireSettings(DataType source, DataType target) {
        sameSettings(source, source.getDefaultSettings(), target.getDefaultSettings());
        if (source instanceof Composite && target instanceof Composite) {
            DataTypeComponent[] before = ((Composite) source).getDefinedComponents();
            DataTypeComponent[] after = ((Composite) target).getDefinedComponents();
            if (before.length != after.length) throw conflict(source, target, "different component settings");
            for (int i = 0; i < before.length; i++)
                sameSettings(before[i].getDataType(), before[i].getDefaultSettings(), after[i].getDefaultSettings());
        }
    }

    private static void sameSettings(DataType type, Settings source, Settings target) {
        for (SettingsDefinition definition : type.getSettingsDefinitions()) {
            if (!definition.hasSameValue(source, target))
                throw new IllegalArgumentException("Type settings conflict at " + type.getPathName()
                    + ": " + definition.getName());
        }
    }

    private static void preserveSettings(DataType source, DataType target) {
        copySettings(source.getDefaultSettings(), target.getDefaultSettings());
        if (source instanceof Composite && target instanceof Composite) {
            DataTypeComponent[] before = ((Composite) source).getDefinedComponents();
            DataTypeComponent[] after = ((Composite) target).getDefinedComponents();
            if (before.length != after.length) return; // Full layout check reports the mismatch.
            for (int i = 0; i < before.length; i++)
                copySettings(before[i].getDefaultSettings(), after[i].getDefaultSettings());
        }
    }

    private static void copySettings(Settings source, Settings destination) {
        for (String key : source.getNames()) {
            Object value = source.getValue(key);
            if (!Objects.equals(value, destination.getValue(key))) destination.setValue(key, value);
        }
    }

    private static IllegalArgumentException conflict(DataType source, DataType existing, String reason) {
        return new IllegalArgumentException("Type conflict at " + source.getPathName() + ": " + reason
            + " (existing " + existing.getPathName() + ")");
    }

    private static List<DataType> children(DataType type) {
        List<DataType> result = new ArrayList<>();
        if (type instanceof Composite) {
            for (DataTypeComponent component : ((Composite) type).getDefinedComponents())
                result.add(component.getDataType());
        } else if (type instanceof TypeDef) result.add(((TypeDef) type).getDataType());
        else if (type instanceof Array) result.add(((Array) type).getDataType());
        else if (type instanceof Pointer) {
            DataType pointed = ((Pointer) type).getDataType();
            if (pointed != null) result.add(pointed);
        } else if (type instanceof BitFieldDataType) result.add(((BitFieldDataType) type).getBaseDataType());
        else if (type instanceof FunctionDefinition) {
            FunctionDefinition function = (FunctionDefinition) type;
            result.add(function.getReturnType());
            for (ParameterDefinition argument : function.getArguments()) result.add(argument.getDataType());
        }
        return result;
    }

    static JsonObject describe(DataType type) {
        JsonObject result = new JsonObject();
        result.addProperty("name", type.getName());
        result.addProperty("path", type.getPathName());
        result.addProperty("category", type.getCategoryPath().getPath());
        result.addProperty("kind", kind(type));
        result.addProperty("size", type.getLength());
        result.addProperty("universal_id", type.getUniversalID() == null ? null : type.getUniversalID().toString());
        SourceArchive source = type.getSourceArchive();
        JsonObject archive = null;
        if (source != null) {
            archive = new JsonObject();
            archive.addProperty("id", source.getSourceArchiveID() == null ? null : source.getSourceArchiveID().toString());
            archive.addProperty("name", source.getName());
            archive.addProperty("kind", source.getArchiveType().name().toLowerCase(Locale.ROOT));
        }
        result.add("source_archive", archive);
        return result;
    }

    private static String kind(DataType type) {
        if (type instanceof Structure) return "struct";
        if (type instanceof Union) return "union";
        if (type instanceof ghidra.program.model.data.Enum) return "enum";
        if (type instanceof TypeDef) return "typedef";
        if (type instanceof FunctionDefinition) return "functiondef";
        if (type instanceof Pointer) return "pointer";
        if (type instanceof Array) return "array";
        if (type instanceof BitFieldDataType) return "bitfield";
        return "other";
    }

    private static JsonObject reference(DataType type) {
        JsonObject result = new JsonObject();
        if (type == null) return result;
        result.addProperty("path", type.getPathName());
        result.addProperty("size", type.getLength());
        if (type instanceof BitFieldDataType) {
            BitFieldDataType bitfield = (BitFieldDataType) type;
            result.addProperty("base", bitfield.getBaseDataType().getPathName());
            result.addProperty("declared_bits", bitfield.getDeclaredBitSize());
            result.addProperty("bits", bitfield.getBitSize());
            result.addProperty("bit_offset", bitfield.getBitOffset());
            result.addProperty("storage_size", bitfield.getStorageSize());
        }
        return result;
    }

    private static JsonObject layout(DataType type) {
        JsonObject result = reference(type);
        result.addProperty("kind", kind(type));
        result.addProperty("alignment", type.getAlignment());
        result.addProperty("zero_length", type.isZeroLength());
        if (type instanceof AbstractIntegerDataType)
            result.addProperty("signed", ((AbstractIntegerDataType) type).isSigned());
        if (type instanceof Pointer)
            result.addProperty("pointer_shift", type.getDataOrganization().getPointerShift());
        if (type.getLength() > 1 && (type instanceof AbstractIntegerDataType
                || type instanceof AbstractFloatDataType || type instanceof Pointer
                || type instanceof ghidra.program.model.data.Enum
                || type instanceof WideCharDataType || type instanceof WideChar16DataType
                || type instanceof WideChar32DataType)) {
            int endian = EndianSettingsDefinition.DEF.getChoice(type.getDefaultSettings());
            result.addProperty("big_endian", endian == EndianSettingsDefinition.DEFAULT
                ? type.getDataOrganization().isBigEndian() : endian == EndianSettingsDefinition.BIG);
        }
        if (type instanceof Composite) {
            Composite composite = (Composite) type;
            result.addProperty("packing", composite.getPackingType().name());
            result.addProperty("pack_value", composite.getExplicitPackingValue());
            result.addProperty("alignment_type", composite.getAlignmentType().name());
            result.addProperty("minimum_alignment", composite.getExplicitMinimumAlignment());
            JsonArray components = new JsonArray();
            for (DataTypeComponent component : composite.getDefinedComponents()) {
                JsonObject row = reference(component.getDataType());
                row.addProperty("ordinal", component.getOrdinal());
                row.addProperty("offset", component.getOffset());
                row.addProperty("length", component.getLength());
                row.addProperty("name", component.getFieldName());
                row.addProperty("comment", component.getComment());
                components.add(row);
            }
            result.add("components", components);
        } else if (type instanceof TypeDef) result.add("base", reference(((TypeDef) type).getDataType()));
        else if (type instanceof Pointer) result.add("base", reference(((Pointer) type).getDataType()));
        else if (type instanceof Array) {
            Array array = (Array) type;
            result.add("base", reference(array.getDataType()));
            result.addProperty("count", array.getNumElements());
            result.addProperty("element_length", array.getElementLength());
        } else if (type instanceof FunctionDefinition) {
            FunctionDefinition function = (FunctionDefinition) type;
            result.add("return", reference(function.getReturnType()));
            result.addProperty("calling_convention", function.getCallingConventionName());
            result.addProperty("varargs", function.hasVarArgs());
            result.addProperty("noreturn", function.hasNoReturn());
            JsonArray arguments = new JsonArray();
            for (ParameterDefinition argument : function.getArguments()) {
                JsonObject row = reference(argument.getDataType());
                row.addProperty("name", argument.getName());
                arguments.add(row);
            }
            result.add("arguments", arguments);
        } else if (type instanceof ghidra.program.model.data.Enum) {
            ghidra.program.model.data.Enum enumeration = (ghidra.program.model.data.Enum) type;
            JsonObject members = new JsonObject();
            for (String name : enumeration.getNames()) members.addProperty(name, enumeration.getValue(name));
            result.add("members", members);
        }
        return result;
    }
}
