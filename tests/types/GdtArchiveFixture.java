import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import java.io.File;
import java.util.Objects;

public class GdtArchiveFixture extends GhidraScript {
    private static final CategoryPath CATEGORY = new CategoryPath("/Gdt");
    private static final String[] NAMES = {
        "Root", "Node", "Link", "Payload", "Choice", "Alias", "Callback", "Mode"
    };

    @Override
    public void run() throws Exception {
        String mode = getScriptArgs()[0];
        File file = new File(getScriptArgs()[1]);
        if (mode.equals("packed-cache-state")) {
            String configured = System.getProperty("pdb.cache.dir");
            File cache = configured == null
                ? new File(ghidra.framework.Application.getUserCacheDirectory(), "packed-db-cache")
                : new File(configured);
            var entries = new com.google.gson.JsonArray();
            if (cache.exists()) {
                try (var paths = java.nio.file.Files.list(cache.toPath())) {
                    paths.filter(java.nio.file.Files::isDirectory)
                        .map(path -> path.getFileName().toString())
                        .filter(name -> name.startsWith("pdb"))
                        .sorted().forEach(entries::add);
                }
            }
            println(entries.toString());
            return;
        }
        if (mode.equals("local")) {
            populate(currentProgram.getDataTypeManager());
            return;
        }
        if (mode.equals("semantic-setting")) {
            var payload = (Structure) currentProgram.getDataTypeManager().getDataType("/Gdt/Payload");
            ghidra.program.model.data.EndianSettingsDefinition.DEF.setChoice(
                payload.getComponentAt(0).getDefaultSettings(),
                ghidra.program.model.data.EndianSettingsDefinition.BIG);
            return;
        }
        if (mode.equals("conflict")) {
            var dtm = currentProgram.getDataTypeManager();
            var payload = new StructureDataType(CATEGORY, "Payload", 8, dtm);
            payload.replaceAtOffset(0, QWordDataType.dataType, 8, "incompatible", null);
            dtm.addDataType(payload, null);
            return;
        }
        if (mode.equals("create") || mode.equals("create-char")) {
            var archive = FileDataTypeManager.createFileArchive(file,
                currentProgram.getLanguageID(), currentProgram.getCompilerSpec().getCompilerSpecID());
            try {
                int tx = archive.startTransaction("GDT fixture");
                try {
                    if (mode.equals("create-char")) {
                        var holder = new StructureDataType(CATEGORY, "Character", 0, archive);
                        holder.add(new CharDataType(archive), "value", null);
                        archive.addDataType(holder, null);
                    } else populate(archive);
                }
                finally { archive.endTransaction(tx, true); }
                archive.save();
            } finally { archive.close(); }
            return;
        }
        var archive = FileDataTypeManager.openFileArchive(file, mode.equals("diverge"));
        try {
            if (mode.equals("diverge")) {
                int tx = archive.startTransaction("Change definition without changing origin identity");
                try {
                    var payload = (Structure) archive.getDataType("/Gdt/Payload");
                    var id = payload.getUniversalID();
                    payload.replaceAtOffset(0, FloatDataType.dataType, 4, "divergent", null);
                    check(id.equals(payload.getUniversalID()), "Fixture changed the type identity");
                } finally { archive.endTransaction(tx, true); }
                archive.save();
                return;
            }
            boolean importing = mode.equals("check-import");
            check(importing || mode.equals("check-export"), "Unknown fixture mode " + mode);
            DataTypeManager source = importing ? archive : currentProgram.getDataTypeManager();
            DataTypeManager destination = importing ? currentProgram.getDataTypeManager() : archive;
            for (String name : NAMES) {
                DataType before = source.getDataType("/Gdt/" + name);
                DataType after = destination.getDataType("/Gdt/" + name);
                check(before != null && after != null, "Missing closure member: " + name);
                check(before.isEquivalent(after), "Definition changed: " + name);
                check(before.getLength() == after.getLength(), "Layout changed: " + name);
                if (importing || before.getSourceArchive().getArchiveType() == ArchiveType.FILE) {
                    check(before.getUniversalID().equals(after.getUniversalID()), "UID changed: " + name);
                    check(before.getSourceArchive().getSourceArchiveID().equals(
                        after.getSourceArchive().getSourceArchiveID()), "Source identity changed: " + name);
                } else {
                    check(!before.getUniversalID().equals(after.getUniversalID()),
                        "Local exported definition retained a Program UID: " + name);
                    check(after.getSourceArchive().getSourceArchiveID().equals(archive.getUniversalID()),
                        "Local exported definition is not owned by the new archive: " + name);
                }
                checkSettings(before.getDefaultSettings(), after.getDefaultSettings(), name);
                if (before instanceof Composite a && after instanceof Composite b) {
                    var oldFields = a.getDefinedComponents();
                    var newFields = b.getDefinedComponents();
                    check(oldFields.length == newFields.length, "Component count: " + name);
                    for (int i = 0; i < oldFields.length; ++i) {
                        var oldField = oldFields[i];
                        var newField = newFields[i];
                        check(oldField.getOffset() == newField.getOffset()
                            && oldField.getLength() == newField.getLength()
                            && Objects.equals(oldField.getFieldName(), newField.getFieldName())
                            && Objects.equals(oldField.getComment(), newField.getComment()),
                            "Component changed: " + name + "[" + i + "]");
                        checkSettings(oldField.getDefaultSettings(), newField.getDefaultSettings(), name);
                    }
                }
            }
            checkGraph(destination);
            if (!importing) {
                check(archive.getDataType("/Other/Unselected") == null,
                    "Unselected unrelated definition was exported");
            }
        } finally { archive.close(); }
    }

    private void populate(DataTypeManager dtm) throws Exception {
        var payload = (Structure) dtm.addDataType(
            new StructureDataType(CATEGORY, "Payload", 4, dtm), null);
        payload.replaceAtOffset(0, DWordDataType.dataType, 4, "value", "shared value");
        var node = (Structure) dtm.addDataType(
            new StructureDataType(CATEGORY, "Node", 24, dtm), null);
        var link = (Structure) dtm.addDataType(
            new StructureDataType(CATEGORY, "Link", 16, dtm), null);
        node.setDescription("mutually recursive node");
        node.replaceAtOffset(0, payload, 4, "payload", "shared definition");
        node.insertBitFieldAt(4, 1, 0, UnsignedIntegerDataType.dataType, 3, "flags", "three bits");
        node.replaceAtOffset(8, new PointerDataType(link, dtm), 8, "next", null);
        node.replaceAtOffset(16, new PointerDataType(node, dtm), 8, "self", null);
        link.replaceAtOffset(0, new PointerDataType(node, dtm), 8, "node", null);
        link.replaceAtOffset(8, payload, 4, "payload", null);
        var union = new UnionDataType(CATEGORY, "Choice", dtm);
        union.setExplicitPackingValue(2);
        union.add(payload, "payload", "shared union member");
        union.add(QWordDataType.dataType, "wide", null);
        var choice = dtm.addDataType(union, null);
        var alias = dtm.addDataType(new TypedefDataType(CATEGORY, "Alias",
            new ArrayDataType(payload, 2, payload.getLength(), dtm), dtm), null);
        var callback = new FunctionDefinitionDataType(CATEGORY, "Callback", dtm);
        callback.setReturnType(DWordDataType.dataType);
        callback.setArguments(new ParameterDefinitionImpl("node", new PointerDataType(node, dtm), "node"));
        callback.setCallingConvention("__cdecl");
        callback.setVarArgs(true);
        var function = dtm.addDataType(callback, null);
        var mode = new EnumDataType(CATEGORY, "Mode", 1, dtm);
        mode.add("IDLE", 0, "idle mode");
        mode.add("ACTIVE", 3, "active mode");
        mode.add("ACTIVE_ALIAS", 3, "same value");
        var savedMode = dtm.addDataType(mode, null);
        var root = new StructureDataType(CATEGORY, "Root", 48, dtm);
        root.replaceAtOffset(0, new PointerDataType(node, dtm), 8, "head", "graph root");
        root.replaceAtOffset(8, payload, 4, "first", null);
        root.replaceAtOffset(12, payload, 4, "second", null);
        root.replaceAtOffset(16, choice, 8, "choice", null);
        root.replaceAtOffset(24, new PointerDataType(function, dtm), 8, "callback", null);
        root.replaceAtOffset(32, alias, 8, "values", null);
        root.replaceAtOffset(40, savedMode, 1, "mode", null);
        dtm.addDataType(root, null);
        dtm.addDataType(new StructureDataType(new CategoryPath("/Other"), "Unselected", 3, dtm), null);
    }

    private void checkGraph(DataTypeManager dtm) {
        var root = (Structure) dtm.getDataType("/Gdt/Root");
        var payload = dtm.getDataType("/Gdt/Payload");
        var node = (Structure) dtm.getDataType("/Gdt/Node");
        var link = (Structure) dtm.getDataType("/Gdt/Link");
        check(((Pointer) root.getComponentAt(0).getDataType()).getDataType() == node,
            "Root pointer does not refer to the registered node");
        check(root.getComponentAt(8).getDataType() == payload
            && root.getComponentAt(12).getDataType() == payload
            && node.getComponentAt(0).getDataType() == payload
            && link.getComponentAt(8).getDataType() == payload, "Shared dependency was duplicated");
        check(((Pointer) node.getComponentAt(8).getDataType()).getDataType() == link
            && ((Pointer) node.getComponentAt(16).getDataType()).getDataType() == node
            && ((Pointer) link.getComponentAt(0).getDataType()).getDataType() == node,
            "Recursive references lost registered identity");
        var alias = (TypeDef) dtm.getDataType("/Gdt/Alias");
        check(((Array) alias.getDataType()).getDataType() == payload, "Array dependency was duplicated");
    }

    private static void checkSettings(ghidra.docking.settings.Settings before,
            ghidra.docking.settings.Settings after, String name) {
        for (String key : before.getNames()) {
            check(Objects.equals(before.getValue(key), after.getValue(key)), "Setting changed: " + name + " " + key);
        }
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new IllegalStateException(message);
    }
}
