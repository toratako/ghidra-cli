use super::{create_type_edit_program, harness, type_command, TEST_PROGRAM};
use serde_json::{json, Value};
use serial_test::serial;

fn command(program: &str, args: &[&str]) -> Value {
    let result = type_command(program, args);
    result.assert_success();
    result.data()
}

fn definition(program: &str, name: &str) -> Value {
    command(program, &["get", name])
}

fn run_script(program: &str, source: &str, args: &[String]) {
    let client = harness().client().unwrap();
    client.open_program(program).unwrap();
    client.script_run_source(source, args, &[], false).unwrap();
}

fn reopen(program: &str) {
    let client = harness().client().unwrap();
    client.program_close().unwrap();
    client.open_program(program).unwrap();
}

#[test]
#[serial]
fn clone_composites_preserves_saved_layout_settings_and_shared_external_dependencies() {
    require_ghidra!();
    let program = create_type_edit_program("x86:LE:64:default");
    let archive_dir = tempfile::tempdir().unwrap();
    let archive_path = archive_dir.path().join("Recovered.gdt");
    run_script(
        &program,
        r#"
import ghidra.app.script.GhidraScript;
import ghidra.docking.settings.FormatSettingsDefinition;
import ghidra.program.model.data.*;
import java.io.File;
public class CreateCloneDefinitions extends GhidraScript {
    public void run() throws Exception {
        var archive = FileDataTypeManager.createFileArchive(new File(getScriptArgs()[0]),
            currentProgram.getLanguageID(), currentProgram.getCompilerSpec().getCompilerSpecID());
        try {
            int tx = archive.startTransaction("Fixture definitions");
            try {
                var path = new CategoryPath("/Source");
                var payload = (Structure) archive.addDataType(new StructureDataType(path, "Payload", 4, archive), null);
                payload.replaceAtOffset(0, DWordDataType.dataType, 4, "value", "shared payload");
                var node = (Structure) archive.addDataType(new StructureDataType(path, "Node", 24, archive), null);
                node.setDescription("recovered node");
                node.replaceAtOffset(0, payload, 4, "payload", "shared definition");
                node.replaceAtOffset(8, new PointerDataType(node, archive), 8, "next", "original self reference");
                node.insertBitFieldAt(16, 1, 0, UnsignedIntegerDataType.dataType, 3, "mode", "mode bits");
                node.insertBitFieldAt(16, 1, 3, UnsignedIntegerDataType.dataType, 2, null, "unnamed bits");
                node.replaceAtOffset(20, DWordDataType.dataType, 4, "tail", "tail comment");
                for (boolean packed : new boolean[] { false, true }) {
                    String name = packed ? "PackedUnion" : "Union";
                    var union = new UnionDataType(path, name, archive);
                    union.setDescription("union description");
                    if (packed) {
                        union.setExplicitPackingValue(2);
                        union.setExplicitMinimumAlignment(16);
                    }
                    union.add(payload, "payload", "shared union dependency");
                    union.add(QWordDataType.dataType, null, "unnamed member");
                    union.addBitField(UnsignedIntegerDataType.dataType, 3, "flags", "union bits");
                    archive.addDataType(union, null);
                }
                var packed = new StructureDataType(path, "Packed", 0, archive);
                packed.setDescription("packed description");
                packed.setExplicitPackingValue(2);
                packed.setExplicitMinimumAlignment(16);
                packed.add(ByteDataType.dataType, "tag", "tag comment");
                packed.add(payload, "payload", "shared packed dependency");
                packed.addBitField(UnsignedIntegerDataType.dataType, 3, "flags", "packed bits");
                archive.addDataType(packed, null);
            } finally { archive.endTransaction(tx, true); }
            archive.save();
            var dtm = currentProgram.getDataTypeManager();
            for (String name : new String[] { "Node", "Packed", "Union", "PackedUnion" }) {
                var registered = (Composite) dtm.addDataType(archive.getDataType("/Source/" + name), null);
                for (var field : registered.getDefinedComponents()) {
                    if (field.getDataType().getSettingsDefinitions().length == 0) continue;
                    FormatSettingsDefinition.DEF.setChoice(field.getDefaultSettings(), FormatSettingsDefinition.DECIMAL);
                    EndianSettingsDefinition.DEF.setChoice(field.getDefaultSettings(), EndianSettingsDefinition.BIG);
                }
            }
        } finally { archive.close(); }
    }
}
"#,
        &[archive_path.to_string_lossy().into_owned()],
    );
    let payload_before = definition(&program, "/Source/Payload");
    assert_eq!(payload_before["source_archive"]["kind"], "file");
    command(&program, &["category", "create", "/Draft"]);
    let names = ["Node", "Packed", "Union", "PackedUnion"];
    let originals: Vec<_> = names
        .iter()
        .map(|name| definition(&program, &format!("/Source/{name}")))
        .collect();
    for (name, original) in names.iter().zip(&originals) {
        let cloned = command(
            &program,
            &[
                "clone",
                &format!("/Source/{name}"),
                &format!("{name}Copy"),
                "--category",
                "/Draft",
            ],
        );
        assert_eq!(cloned["source_path"], format!("/Source/{name}"));
        assert_eq!(cloned["path"], format!("/Draft/{name}Copy"));
        assert_eq!(cloned["status"], "cloned");
        let copied = definition(&program, &format!("/Draft/{name}Copy"));
        assert_ne!(copied["universal_id"], original["universal_id"]);
        assert!(copied["universal_id"].is_string());
        assert_eq!(copied["source_archive"]["kind"], "program");
        assert_ne!(
            copied["source_archive"]["id"],
            original["source_archive"]["id"]
        );
        for key in ["size", "description", "packing_enabled", "components"] {
            assert_eq!(copied[key], original[key], "{name}: {key}");
        }
        assert_eq!(definition(&program, &format!("/Source/{name}")), *original);
    }
    assert_eq!(definition(&program, "/Source/Payload"), payload_before);
    reopen(&program);
    for (name, original) in names.iter().zip(&originals) {
        assert_eq!(definition(&program, &format!("/Source/{name}")), *original);
    }
    run_script(
        &program,
        r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import java.util.Arrays;
import java.util.Objects;
public class CheckSavedClonedDefinitions extends GhidraScript {
    public void run() throws Exception {
        var dtm = currentProgram.getDataTypeManager();
        for (String name : new String[] { "Node", "Packed", "Union", "PackedUnion" }) {
            var original = (Composite) dtm.getDataType("/Source/" + name);
            var copy = (Composite) dtm.getDataType("/Draft/" + name + "Copy");
            if (original.getUniversalID().equals(copy.getUniversalID())
                    || original.getSourceArchive().getArchiveType() != ArchiveType.FILE
                    || copy.getSourceArchive().getArchiveType() != ArchiveType.PROGRAM)
                throw new IllegalStateException("Identity or source archive was not preserved");
            if (original.getPackingType() != copy.getPackingType()
                    || original.getExplicitPackingValue() != copy.getExplicitPackingValue()
                    || original.getAlignmentType() != copy.getAlignmentType()
                    || original.getExplicitMinimumAlignment() != copy.getExplicitMinimumAlignment())
                throw new IllegalStateException("Packing or alignment changed");
            var fields = original.getDefinedComponents();
            var copied = copy.getDefinedComponents();
            for (int i = 0; i < fields.length; i++) {
                var a = fields[i].getDefaultSettings();
                var b = copied[i].getDefaultSettings();
                if (!Arrays.equals(a.getNames(), b.getNames()))
                    throw new IllegalStateException("Explicit component settings changed");
                for (String key : a.getNames()) {
                    if (!Objects.equals(a.getValue(key), b.getValue(key)))
                        throw new IllegalStateException("Component setting not saved: " + key);
                }
                var oldType = fields[i].getDataType();
                var newType = copied[i].getDataType();
                if (oldType instanceof BitFieldDataType) {
                    oldType = ((BitFieldDataType) oldType).getBaseDataType();
                    newType = ((BitFieldDataType) newType).getBaseDataType();
                }
                if (oldType != newType) throw new IllegalStateException("Dependency was copied");
            }
        }
        var original = (Structure) dtm.getDataType("/Source/Node");
        var copy = (Structure) dtm.getDataType("/Draft/NodeCopy");
        if (((Pointer) copy.getComponentAt(8).getDataType()).getDataType() != original)
            throw new IllegalStateException("Self reference was redirected to the clone");
        var payload = (Structure) dtm.getDataType("/Source/Payload");
        payload.getComponentAt(0).setFieldName("shared_edit");
        if (((Structure) original.getComponentAt(0).getDataType()).getComponentAt(0).getFieldName()
                .equals("shared_edit") == false
                || ((Structure) copy.getComponentAt(0).getDataType()).getComponentAt(0).getFieldName()
                .equals("shared_edit") == false)
            throw new IllegalStateException("Dependency edits were not shared");
        copy.getComponentAt(20).setFieldName("independent_edit");
        if (!original.getComponentAt(20).getFieldName().equals("tail"))
            throw new IllegalStateException("Clone edit modified source definition");
    }
}
"#,
        &[],
    );
    reopen(&program);
    assert_eq!(
        definition(&program, "/Source/Payload")["components"][0]["name"],
        "shared_edit"
    );
    assert_eq!(
        definition(&program, "/Source/Node")["components"],
        originals[0]["components"]
    );
    harness()
        .client()
        .unwrap()
        .open_program(TEST_PROGRAM)
        .unwrap();
}

#[test]
#[serial]
fn clone_enum_typedef_and_function_preserves_definition_settings_and_default_category() {
    require_ghidra!();
    let program = create_type_edit_program("x86:LE:64:default");
    run_script(
        &program,
        r#"
import ghidra.app.script.GhidraScript;
import ghidra.docking.settings.FormatSettingsDefinition;
import ghidra.program.model.data.*;
public class CreateOtherCloneDefinitions extends GhidraScript {
    public void run() throws Exception {
        var dtm = currentProgram.getDataTypeManager();
        var path = new CategoryPath("/Types");
        var values = new EnumDataType(path, "Values", 4, dtm);
        values.setDescription("enum description");
        values.add("FIRST", 1, "first comment");
        values.add("ALIAS", 1, "alias comment");
        var savedEnum = dtm.addDataType(values, null);
        FormatSettingsDefinition.DEF.setChoice(savedEnum.getDefaultSettings(), FormatSettingsDefinition.DECIMAL);
        var alias = new TypedefDataType(path, "Alias", savedEnum, dtm);
        var savedAlias = dtm.addDataType(alias, null);
        FormatSettingsDefinition.DEF.setChoice(savedAlias.getDefaultSettings(), FormatSettingsDefinition.BINARY);
        var ptr = new PointerTypedef("Relative", savedEnum, 8, dtm, 12L);
        var savedPointer = dtm.addDataType(ptr, null);
        savedPointer.setCategoryPath(path);
        FormatSettingsDefinition.DEF.setChoice(savedPointer.getDefaultSettings(), FormatSettingsDefinition.DECIMAL);
        var function = new FunctionDefinitionDataType(path, "Callback", dtm);
        function.setComment("callback comment");
        function.setReturnType(savedAlias);
        function.setArguments(new ParameterDefinitionImpl("arg", savedPointer, "argument comment"));
        function.setVarArgs(true);
        function.setNoReturn(true);
        function.setCallingConvention("__cdecl");
        dtm.addDataType(function, null);
    }
}
"#,
        &[],
    );
    let names = ["Values", "Alias", "Relative", "Callback"];
    let originals: Vec<_> = names
        .iter()
        .map(|name| definition(&program, &format!("/Types/{name}")))
        .collect();
    for name in names {
        let receipt = command(
            &program,
            &["clone", &format!("/Types/{name}"), &format!("{name}Copy")],
        );
        assert_eq!(receipt["path"], format!("/Types/{name}Copy"));
    }
    reopen(&program);
    run_script(
        &program,
        r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import java.util.Objects;
public class CheckOtherClonedDefinitions extends GhidraScript {
    public void run() throws Exception {
        var dtm = currentProgram.getDataTypeManager();
        for (String name : new String[] { "Values", "Alias", "Relative", "Callback" }) {
            var source = dtm.getDataType("/Types/" + name);
            var copy = dtm.getDataType("/Types/" + name + "Copy");
            if (source.getUniversalID().equals(copy.getUniversalID()))
                throw new IllegalStateException("Clone identity matches source");
            for (String key : source.getDefaultSettings().getNames()) {
                if (!Objects.equals(source.getDefaultSettings().getValue(key), copy.getDefaultSettings().getValue(key)))
                    throw new IllegalStateException("Default setting lost: " + name + " " + key);
            }
            if (source instanceof TypeDef && ((TypeDef) source).getDataType() != ((TypeDef) copy).getDataType())
                throw new IllegalStateException("Typedef dependency changed");
        }
        var sourceEnum = (ghidra.program.model.data.Enum) dtm.getDataType("/Types/Values");
        var enumCopy = (ghidra.program.model.data.Enum) dtm.getDataType("/Types/ValuesCopy");
        for (String name : sourceEnum.getNames()) {
            if (sourceEnum.getValue(name) != enumCopy.getValue(name)
                    || !Objects.equals(sourceEnum.getComment(name), enumCopy.getComment(name)))
                throw new IllegalStateException("Enum member changed");
        }
        var original = (FunctionDefinition) dtm.getDataType("/Types/Callback");
        var copy = (FunctionDefinition) dtm.getDataType("/Types/CallbackCopy");
        if (original.getReturnType() != copy.getReturnType() || !copy.hasVarArgs() || !copy.hasNoReturn()
                || !Objects.equals(original.getComment(), copy.getComment())
                || !Objects.equals(original.getCallingConventionName(), copy.getCallingConventionName()))
            throw new IllegalStateException("Function properties changed");
        var originalArg = original.getArguments()[0];
        var copiedArg = copy.getArguments()[0];
        if (originalArg.getDataType() != copiedArg.getDataType()
                || !Objects.equals(originalArg.getName(), copiedArg.getName())
                || !Objects.equals(originalArg.getComment(), copiedArg.getComment()))
            throw new IllegalStateException("Function argument changed");
    }
}
"#,
        &[],
    );
    for (name, original) in names.iter().zip(&originals) {
        assert_eq!(definition(&program, &format!("/Types/{name}")), *original);
    }
    harness()
        .client()
        .unwrap()
        .open_program(TEST_PROGRAM)
        .unwrap();
}

#[test]
#[serial]
fn categories_and_move_preserve_identity_references_and_reject_destructive_collisions() {
    require_ghidra!();
    let program = create_type_edit_program("x86:LE:64:default");
    command(&program, &["category", "create", "/Draft/Empty"]);
    assert_eq!(
        command(&program, &["category", "create", "/Draft/Empty"])["changed"],
        false
    );
    assert_eq!(
        command(&program, &["category", "create", "/"])["changed"],
        false
    );
    command(&program, &["category", "create", "/Final"]);
    command(
        &program,
        &[
            "import-c",
            "struct Item { int value; };",
            "--category",
            "/Draft",
        ],
    );
    command(
        &program,
        &[
            "import-c",
            "struct Item { char existing; };",
            "--category",
            "/Final",
        ],
    );
    let children = type_command(&program, &["category", "list", "/Draft"]);
    children.assert_success();
    assert_eq!(
        children.data::<Value>(),
        json!([{"name": "Empty", "path": "/Draft/Empty", "type_count": 0}])
    );
    assert_eq!(children.json::<Value>()["meta"]["path"], "/Draft");
    let categories = command(&program, &["category", "list", "/"]);
    for name in ["Draft", "Final"] {
        let category = categories
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["name"] == name)
            .unwrap();
        assert_eq!(category["type_count"], 1);
    }
    assert!(command(&program, &["category", "list", "/Draft/Empty"])
        .as_array()
        .unwrap()
        .is_empty());
    command(
        &program,
        &["create", "typedef", "ItemAlias", "/Draft/Item *"],
    );
    let alias = definition(&program, "/ItemAlias");
    let pointer_path = alias["base_type_path"].as_str().unwrap();
    type_command(&program, &["move", pointer_path, "/Final"])
        .assert_failure()
        .assert_stderr_contains("editable named definition");
    assert_eq!(definition(&program, "/ItemAlias"), alias);
    let source = definition(&program, "/Draft/Item");
    let collision = definition(&program, "/Final/Item");
    let clone_collision = type_command(
        &program,
        &["clone", "/Draft/Item", "Item", "--category", "/Final"],
    );
    clone_collision
        .assert_failure()
        .assert_stderr_contains("already exists");
    assert_eq!(
        serde_json::from_str::<Value>(&clone_collision.stderr).unwrap()["detail"]["rolled_back"],
        true
    );
    type_command(&program, &["move", "/Draft/Item", "/Final"])
        .assert_failure()
        .assert_stderr_contains("already exists");
    type_command(
        &program,
        &[
            "clone",
            "/Draft/Item",
            "MissingCopy",
            "--category",
            "/Missing",
        ],
    )
    .assert_failure()
    .assert_stderr_contains("Category not found");
    type_command(&program, &["move", "/Draft/Item", "/Missing"])
        .assert_failure()
        .assert_stderr_contains("Category not found");
    for path in ["/", "/Draft", "/Final"] {
        type_command(&program, &["category", "delete", path]).assert_failure();
    }
    for path in ["Relative", "/Bad/../Target", "/Bad//Target", "/Bad/"] {
        type_command(&program, &["category", "create", path]).assert_failure();
    }
    reopen(&program);
    assert_eq!(definition(&program, "/Draft/Item"), source);
    assert_eq!(definition(&program, "/Final/Item"), collision);
    let unchanged = command(&program, &["move", "/Draft/Item", "/Draft"]);
    assert_eq!(unchanged["changed"], false);
    assert_eq!(unchanged["old_path"], "/Draft/Item");
    command(&program, &["rename", "/Draft/Item", "MovedItem"]);
    assert_eq!(
        definition(&program, "/Draft/MovedItem")["universal_id"],
        source["universal_id"]
    );
    let moved = command(&program, &["move", "/Draft/MovedItem", "/Final"]);
    assert_eq!(moved["old_path"], "/Draft/MovedItem");
    assert_eq!(moved["path"], "/Final/MovedItem");
    assert_eq!(moved["changed"], true);
    command(&program, &["category", "delete", "/Draft/Empty"]);
    reopen(&program);
    let after = definition(&program, "/Final/MovedItem");
    assert_eq!(after["universal_id"], source["universal_id"]);
    assert_eq!(after["source_archive"], source["source_archive"]);
    let primitive = definition(&program, "int");
    assert!(primitive["universal_id"].is_null());
    assert_eq!(primitive["source_archive"]["kind"], "built_in");
    type_command(&program, &["get", "/Draft/Item"]).assert_failure();
    run_script(
        &program,
        r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
public class CheckMovedTypeReferences extends GhidraScript {
    public void run() throws Exception {
        var dtm = currentProgram.getDataTypeManager();
        var alias = (TypeDef) dtm.getDataType("/ItemAlias");
        var moved = dtm.getDataType("/Final/MovedItem");
        if (((Pointer) alias.getDataType()).getDataType() != moved)
            throw new IllegalStateException("Moving type changed references");
        if (dtm.getCategory(new CategoryPath("/Draft/Empty")) != null
                || dtm.getCategory(new CategoryPath("/Missing")) != null
                || dtm.getCategory(new CategoryPath("/Bad")) != null)
            throw new IllegalStateException("Rejected category mutation persisted");
    }
}
"#,
        &[],
    );
    harness()
        .client()
        .unwrap()
        .open_program(TEST_PROGRAM)
        .unwrap();
}
