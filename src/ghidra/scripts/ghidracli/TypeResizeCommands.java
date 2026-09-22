package ghidracli;

import com.google.gson.JsonObject;
import ghidra.docking.settings.Settings;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.AlignmentType;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.PackingType;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/** Resize with native propagation, accepting only complete, preserved definitions. */
final class TypeResizeCommands {
    private final ProgramSession session;
    private final TypeResolver resolver;

    TypeResizeCommands(ProgramSession session, TypeResolver resolver) {
        this.session = session;
        this.resolver = resolver;
    }

    JsonObject handleResize(JsonObject args) throws Exception {
        if (session.program() == null) return JsonProtocol.errorResult("No program loaded");
        String name = JsonProtocol.getArgString(args, "type_name");
        if (name == null || name.isBlank())
            throw new IllegalArgumentException("Type name required");
        if (!args.has("size") || args.get("size").isJsonNull())
            throw new IllegalArgumentException("size is required");
        int size = JsonProtocol.getNonnegativeIntArg(args, "size", 0);
        DataType type = resolver.resolveRegisteredDataType(name);
        if (type == null) throw new IllegalArgumentException("Type not found: " + name);
        if (!(type instanceof Structure) || ((Structure) type).isPackingEnabled())
            throw new IllegalArgumentException("Resize requires a registered structure with packing disabled");
        Structure structure = (Structure) type;
        int previous = StructureFields.length(structure);
        if (previous != size) {
            for (DataTypeComponent field : structure.getDefinedComponents()) {
                session.monitor().checkCancelled();
                // Defined components include explicit undefined types and zero-length
                // boundaries. Only implicit undefined filler may be removed.
                if ((long) field.getOffset() + field.getLength() > size)
                    throw new IllegalArgumentException("Resize would remove or truncate field at offset "
                        + field.getOffset() + " in " + structure.getPathName());
            }
            Map<DataType, Definition> affected = captureDefinitions(structure);
            List<Application> applications = captureApplications(affected);
            structure.setLength(size);
            if (StructureFields.length(structure) != size)
                throw new IllegalArgumentException("Ghidra did not retain the requested structure size");
            for (Definition definition : affected.values()) {
                session.monitor().checkCancelled();
                definition.verify(affected, definition.type == structure, session.monitor());
            }
            for (Application application : applications) {
                session.monitor().checkCancelled();
                application.verify(session.program().getListing(), session.monitor());
            }
        }
        JsonObject result = new JsonObject();
        result.addProperty("status", previous == size ? "unchanged" : "resized");
        result.addProperty("changed", previous != size);
        result.addProperty("name", structure.getName());
        result.addProperty("path", structure.getPathName());
        result.addProperty("size_before", previous);
        result.addProperty("size_after", size);
        return result;
    }

    private Map<DataType, Definition> captureDefinitions(Structure target) throws Exception {
        Map<DataType, Definition> affected = new LinkedHashMap<>();
        ArrayDeque<DataType> pending = new ArrayDeque<>();
        pending.add(target);
        while (!pending.isEmpty()) {
            session.monitor().checkCancelled();
            DataType type = pending.removeFirst();
            if (affected.containsKey(type)) continue;
            affected.put(type, new Definition(type, session.monitor()));
            // These are the database parent relationships used by native size
            // notifications, not the partial public type-usage search. Pointers
            // and function signatures do not propagate pointee/value sizes.
            for (DataType parent : type.getParents()) {
                if (parent instanceof Composite || parent instanceof Array || parent instanceof TypeDef)
                    pending.addLast(parent);
            }
        }
        return affected;
    }

    private List<Application> captureApplications(Map<DataType, Definition> affected) throws Exception {
        Listing listing = session.program().getListing();
        List<Application> applications = new ArrayList<>();
        // Scan every defined root, including typedef and nested array applications.
        // The public type-usage search does not enumerate these exhaustively.
        DataIterator data = listing.getDefinedData(true);
        while (data.hasNext()) {
            session.monitor().checkCancelled();
            Data item = data.next();
            if (affected.containsKey(item.getDataType()))
                applications.add(new Application(item, listing, session.monitor()));
        }
        return applications;
    }

    private static Map<String, Object> settings(Settings settings) {
        Map<String, Object> result = new HashMap<>();
        for (String name : settings.getNames()) result.put(name, settings.getValue(name));
        return result;
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new IllegalArgumentException("Unsafe resize: " + message);
    }

    private static Map<List<Integer>, Map<String, Object>> appliedSettings(Data data, TaskMonitor monitor)
            throws CancelledException {
        Map<List<Integer>, Map<String, Object>> result = new HashMap<>();
        appliedSettings(data, new ArrayList<>(), result, monitor);
        return result;
    }

    private static void appliedSettings(Data data, List<Integer> path,
            Map<List<Integer>, Map<String, Object>> result, TaskMonitor monitor) throws CancelledException {
        monitor.checkCancelled();
        require(data != null, "incomplete applied component");
        Map<String, Object> values = settings(data);
        if (!values.isEmpty()) result.put(new ArrayList<>(path), values);
        DataType base = data.getBaseDataType();
        if (base instanceof Composite) {
            DataTypeComponent[] fields = ((Composite) base).getDefinedComponents();
            for (int i = 0; i < fields.length; i++) {
                // Defined-field indices survive filler ordinal changes. Array
                // indices likewise retain element identity across stride changes.
                path.add(i);
                appliedSettings(data.getComponent(fields[i].getOrdinal()), path, result, monitor);
                path.remove(path.size() - 1);
            }
        } else if (base instanceof Array) {
            for (int i = 0; i < ((Array) base).getNumElements(); i++) {
                path.add(i);
                appliedSettings(data.getComponent(i), path, result, monitor);
                path.remove(path.size() - 1);
            }
        }
    }

    private static final class Field {
        final DataType type;
        final String name;
        final String comment;
        final int ordinal;
        final int offset;
        final int length;
        final Map<String, Object> settings;

        Field(DataTypeComponent field) {
            type = field.getDataType();
            name = field.getFieldName();
            comment = field.getComment();
            ordinal = field.getOrdinal();
            offset = field.getOffset();
            length = field.getLength();
            settings = settings(field.getDefaultSettings());
        }

        void verify(DataTypeComponent field, Composite parent,
                Map<DataType, Definition> affected, boolean target) {
            String location = parent.getPathName() + " field " + ordinal;
            require(type.equals(field.getDataType()) && Objects.equals(name, field.getFieldName())
                    && Objects.equals(comment, field.getComment())
                    && settings.equals(settings(field.getDefaultSettings())),
                "field definition or settings changed in " + location);
            if (target || !parent.isPackingEnabled())
                require(offset == field.getOffset(), "field moved in " + location);
            if (target) require(ordinal == field.getOrdinal(), "field ordinal changed in " + location);
            if (!target && affected.containsKey(type)) {
                int expected = DataTypeComponent.usesZeroLengthComponent(type) ? 0
                    : parent.isPackingEnabled() ? type.getAlignedLength() : type.getLength();
                require(expected >= 0 && field.getLength() == expected,
                    "incomplete embedded type in " + location);
            } else {
                require(length == field.getLength(), "field length changed in " + location);
            }
            require((long) field.getOffset() + field.getLength()
                    <= (parent.isZeroLength() ? 0 : parent.getLength()),
                "field extends beyond " + location);
        }
    }

    private static final class Definition {
        final DataType type;
        final String path;
        final String description;
        final Map<String, Object> settings;
        final List<Field> fields = new ArrayList<>();
        final int packing;
        final int alignment;
        final PackingType packingType;
        final AlignmentType alignmentType;
        final DataType base;
        final int count;

        Definition(DataType type, TaskMonitor monitor) throws CancelledException {
            this.type = type;
            path = type.getPathName();
            description = type.getDescription();
            settings = settings(type.getDefaultSettings());
            if (type instanceof Composite) {
                Composite composite = (Composite) type;
                packingType = composite.getPackingType();
                alignmentType = composite.getAlignmentType();
                packing = composite.hasExplicitPackingValue() ? composite.getExplicitPackingValue() : 0;
                alignment = composite.hasExplicitMinimumAlignment() ? composite.getExplicitMinimumAlignment() : 0;
                for (DataTypeComponent field : composite.getDefinedComponents()) {
                    monitor.checkCancelled();
                    fields.add(new Field(field));
                }
            } else {
                packing = alignment = 0;
                packingType = null;
                alignmentType = null;
            }
            base = type instanceof Array ? ((Array) type).getDataType()
                : type instanceof TypeDef ? ((TypeDef) type).getDataType() : null;
            count = type instanceof Array ? ((Array) type).getNumElements() : 0;
        }

        void verify(Map<DataType, Definition> affected, boolean target, TaskMonitor monitor)
                throws CancelledException {
            require(!type.isDeleted() && path.equals(type.getPathName())
                    && Objects.equals(description, type.getDescription())
                    && settings.equals(settings(type.getDefaultSettings())),
                "type definition or settings changed in " + path);
            if (type instanceof Composite) {
                Composite composite = (Composite) type;
                require(packingType == composite.getPackingType() && alignmentType == composite.getAlignmentType()
                        && (!composite.hasExplicitPackingValue() || packing == composite.getExplicitPackingValue())
                        && (!composite.hasExplicitMinimumAlignment() || alignment == composite.getExplicitMinimumAlignment()),
                    "packing changed in " + path);
                DataTypeComponent[] after = composite.getDefinedComponents();
                require(after.length == fields.size(), "defined fields were lost in " + path);
                for (int i = 0; i < after.length; i++) {
                    monitor.checkCancelled();
                    fields.get(i).verify(after[i], composite, affected, target);
                }
                if (composite instanceof Structure)
                    TypeFields.verifyComponentCount((Structure) composite);
            } else if (type instanceof Array) {
                Array array = (Array) type;
                long length = (long) count * array.getElementLength();
                require(base.equals(array.getDataType()) && count == array.getNumElements()
                        && array.getElementLength() == base.getAlignedLength()
                        && array.getElementLength() > 0 && length <= Integer.MAX_VALUE
                        && (count == 0 ? array.isZeroLength() : array.getLength() == length),
                    "incomplete array in " + path);
            } else if (type instanceof TypeDef) {
                require(base.equals(((TypeDef) type).getDataType()) && type.getLength() == base.getLength(),
                    "incomplete typedef in " + path);
            }
        }
    }

    private static final class Application {
        final Address address;
        final DataType type;
        final Map<List<Integer>, Map<String, Object>> settings;
        final Address neighbor;
        final DataType neighborType;
        final int neighborInstructionLength;

        Application(Data data, Listing listing, TaskMonitor monitor) throws CancelledException {
            address = data.getMinAddress();
            type = data.getDataType();
            // Instance settings are keyed by address in Ghidra. A packed parent
            // or an array can move components without relocating those settings.
            // Keep only explicit values, then verify their component association.
            settings = appliedSettings(data, monitor);
            Data nextData = listing.getDefinedDataAfter(address);
            Instruction nextInstruction = listing.getInstructionAfter(address);
            CodeUnit next = nextData;
            if (nextInstruction != null && (next == null
                    || nextInstruction.getMinAddress().compareTo(next.getMinAddress()) < 0))
                next = nextInstruction;
            neighbor = next == null ? null : next.getMinAddress();
            neighborType = next instanceof Data ? ((Data) next).getDataType() : null;
            neighborInstructionLength = next instanceof Instruction ? next.getLength() : 0;
        }

        void verify(Listing listing, TaskMonitor monitor) throws CancelledException {
            Data after = listing.getDefinedDataAt(address);
            String location = AddressCodec.format(address);
            require(after != null && type.equals(after.getDataType()),
                "applied data was lost at " + location);
            require(!type.isZeroLength() && type.getLength() > 0 && after.getLength() == type.getLength(),
                "incomplete applied data at " + location);
            require(settings.equals(appliedSettings(after, monitor)),
                "applied component settings changed at " + location);
            if (neighbor != null) {
                CodeUnit next = listing.getCodeUnitAt(neighbor);
                require(neighborType != null
                        ? next instanceof Data && neighborType.equals(((Data) next).getDataType())
                        : next instanceof Instruction && next.getLength() == neighborInstructionLength,
                    "following code unit was lost at " + AddressCodec.format(neighbor));
            }
        }
    }
}
