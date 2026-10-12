//! Union members share an offset and are edited by ordinal without losing settings.

use super::common::helpers::GhidraResult;
use super::{assert_field_receipt, create_type_edit_program, harness, type_command, TEST_PROGRAM};
use serde_json::{json, Value};
use serial_test::serial;

fn success(result: GhidraResult) -> Value {
    result.assert_success();
    result.data::<Value>()
}

fn definition(program: &str, name: &str) -> Value {
    success(type_command(program, &["get", name]))
}

fn set(program: &str, name: &str, ordinal: &str, attributes: &[&str]) -> GhidraResult {
    let mut args = vec!["field", "set", name, "--ordinal", ordinal];
    args.extend_from_slice(attributes);
    type_command(program, &args)
}

#[test]
#[serial]
fn union_edits_reject_packed_alignment_size_overflow_without_saving_a_corrupt_layout() {
    require_ghidra!();
    let program = create_type_edit_program("x86:LE:32:default");
    let client = harness().client().unwrap();
    super::common::with_temporary_program(&client, &program, TEST_PROGRAM, || {
        client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
public class CreatePackedUnionOverflow extends GhidraScript {
    public void run() throws Exception {
        var dtm = currentProgram.getDataTypeManager();
        for (String name : new String[] { "PackedUnionAppend", "PackedUnionSet" }) {
            var union = new UnionDataType(CategoryPath.ROOT, name, dtm);
            union.setPackingEnabled(true);
            union.add(new ArrayDataType(ByteDataType.dataType, Integer.MAX_VALUE, -1, dtm), "bytes", "keep");
            if (name.equals("PackedUnionSet")) union.add(ByteDataType.dataType, "tag", "keep tag");
            var saved = dtm.addDataType(union, null);
            if (saved.getLength() != Integer.MAX_VALUE)
                throw new IllegalStateException("Fixture must fill the supported union size");
        }
    }
}
"#,
            &[],
            &[],
            false,
        )
        .unwrap();
        for (name, command) in [
            (
                "PackedUnionAppend",
                vec![
                    "field",
                    "append",
                    "PackedUnionAppend",
                    "--name",
                    "word",
                    "--type",
                    "word",
                ],
            ),
            (
                "PackedUnionSet",
                vec![
                    "field",
                    "set",
                    "PackedUnionSet",
                    "--field",
                    "tag",
                    "--type",
                    "word",
                ],
            ),
        ] {
            let before = definition(&program, name);
            let failed = type_command(&program, &command);
            failed
                .assert_failure()
                .assert_stderr_contains("Composite size exceeds its supported range");
            let error: Value = serde_json::from_str(&failed.stderr).unwrap();
            assert_eq!(error["detail"]["rolled_back"], true, "{error}");
            client.program_close().unwrap();
            assert_eq!(definition(&program, name), before);
        }
    });
}

#[test]
#[serial]
fn union_creation_member_edits_and_deletions_persist() {
    require_ghidra!();
    let program = create_type_edit_program("x86:LE:64:default");
    let created = success(type_command(&program, &["create", "union", "Payload"]));
    assert_eq!(created["kind"], "union");
    assert_eq!(created["path"], "/Payload");
    assert_eq!(definition(&program, "Payload")["size"], 0);
    let added = success(type_command(
        &program,
        &[
            "field", "append", "Payload", "--name", "integer", "--type", "uint32_t",
        ],
    ));
    assert_field_receipt(&added, "union", "Payload", "appended");
    assert_eq!(added["after"]["ordinal"], 0);
    assert_eq!(added["size_before"], 0);
    assert_eq!(added["size_after"], 4);
    success(type_command(
        &program,
        &[
            "field", "append", "Payload", "--name", "bytes", "--type", "byte[16]",
        ],
    ));
    let before = definition(&program, "Payload");
    assert_eq!(before["size"], 16);
    for (ordinal, field) in before["components"].as_array().unwrap().iter().enumerate() {
        assert_eq!(field["offset"], 0);
        assert_eq!(field["ordinal"], ordinal);
    }
    let edited = success(set(
        &program,
        "Payload",
        "1",
        &[
            "--type",
            "Payload *",
            "--name",
            "next",
            "--comment",
            "linked payload",
        ],
    ));
    assert_field_receipt(&edited, "union", "Payload", "updated");
    assert_eq!(edited["before"], before["components"][1]);
    assert_eq!(edited["after"]["type_path"], "/Payload *");
    assert_eq!(edited["after"]["size"], 8);
    assert_eq!(edited["size_before"], 16);
    assert_eq!(edited["size_after"], 8);
    let saved = definition(&program, "Payload");
    assert_eq!(saved["components"][0], before["components"][0]);
    assert_eq!(saved["components"][1]["name"], "next");
    assert_eq!(saved["components"][1]["comment"], "linked payload");
    let unchanged = success(type_command(
        &program,
        &[
            "field",
            "set",
            "Payload",
            "--field",
            "next",
            "--comment",
            "linked payload",
        ],
    ));
    assert_field_receipt(&unchanged, "union", "Payload", "unchanged");
    assert_eq!(unchanged["status"], "unchanged");
    assert_eq!(unchanged["changed"], false);
    harness().client().unwrap().program_close().unwrap();
    assert_eq!(definition(&program, "Payload"), saved);
    let cleared = success(type_command(
        &program,
        &[
            "field",
            "set",
            "Payload",
            "--field",
            "next",
            "--comment",
            "",
        ],
    ));
    assert!(cleared["after"]["comment"].is_null());
    assert_eq!(cleared["after"]["name"], "next");

    let deleted = success(type_command(
        &program,
        &["field", "delete", "Payload", "--field", "integer"],
    ));
    assert_field_receipt(&deleted, "union", "Payload", "deleted");
    assert_eq!(deleted["before"]["ordinal"], 0);
    assert!(deleted["after"].is_null());
    assert_eq!(
        definition(&program, "Payload")["components"][0]["name"],
        "next"
    );
    let emptied = success(type_command(
        &program,
        &["field", "delete", "Payload", "--ordinal", "0"],
    ));
    assert_field_receipt(&emptied, "union", "Payload", "deleted");
    assert_eq!(emptied["size_after"], 0);
    harness().client().unwrap().program_close().unwrap();
    let empty = definition(&program, "Payload");
    assert_eq!(empty["size"], 0);
    assert!(empty["components"].as_array().unwrap().is_empty());
    harness()
        .client()
        .unwrap()
        .open_program(TEST_PROGRAM)
        .unwrap();
}

#[test]
#[serial]
fn union_alignment_changes_reject_incomplete_applied_parents_even_when_size_is_unchanged() {
    require_ghidra!();
    let program = create_type_edit_program("x86:LE:64:default");
    let client = harness().client().unwrap();
    client.open_program(&program).unwrap();
    client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
public class CreateUnionAlignmentCases extends GhidraScript {
    public void run() throws Exception {
        var dtm = currentProgram.getDataTypeManager();
        int address = 0x1000;
        for (String name : new String[] { "AlignAppend", "AlignSet" }) {
            var union = new UnionDataType(CategoryPath.ROOT, name, dtm);
            union.setPackingEnabled(true);
            union.add(new ArrayDataType(ByteDataType.dataType, 8, -1, dtm), "raw", null);
            var saved = dtm.addDataType(union, null);
            var holder = new StructureDataType(name + "Holder", 0, dtm);
            holder.setPackingEnabled(true);
            holder.add(ByteDataType.dataType, "prefix", null);
            holder.add(saved, "payload", null);
            holder.add(ByteDataType.dataType, "tail", null);
            var parent = dtm.addDataType(holder, null);
            if (parent.getLength() != 10 || saved.getAlignment() != 1)
                throw new IllegalStateException("Unexpected initial union alignment");
            currentProgram.getMemory().createInitializedBlock(name, toAddr(address),
                10, (byte) 0, monitor, false);
            currentProgram.getListing().createData(toAddr(address), parent);
            address += 0x100;
        }
    }
}
"#,
            &[],
            &[],
            false,
        )
        .unwrap();
    for (name, action, selector, operand) in [
        ("AlignAppend", "append", "--name", "wide"),
        ("AlignSet", "set", "--field", "raw"),
    ] {
        let before = definition(&program, name);
        let parent_name = format!("{name}Holder");
        let parent = definition(&program, &parent_name);
        let failed = type_command(
            &program,
            &["field", action, name, selector, operand, "--type", "qword"],
        );
        failed
            .assert_failure()
            .assert_stderr_contains("Unsafe resize");
        let error: Value = serde_json::from_str(&failed.stderr).unwrap();
        assert_eq!(error["detail"]["rolled_back"], true, "{error}");
        client.program_close().unwrap();
        assert_eq!(definition(&program, name), before);
        assert_eq!(definition(&program, &parent_name), parent);
    }
    client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
public class CheckUnionAlignmentRollback extends GhidraScript {
    public void run() throws Exception {
        for (int address : new int[] { 0x1000, 0x1100 }) {
            var data = currentProgram.getListing().getDefinedDataAt(toAddr(address));
            if (data == null || data.getLength() != 10 || data.getDataType().getLength() != 10)
                throw new IllegalStateException("Union alignment left incomplete applied data");
        }
    }
}
"#,
            &[],
            &[],
            false,
        )
        .unwrap();
    client.open_program(TEST_PROGRAM).unwrap();
}

#[test]
#[serial]
fn field_deletion_preserves_remaining_applied_settings_or_rolls_back() {
    require_ghidra!();
    let program = create_type_edit_program("x86:LE:64:default");
    let client = harness().client().unwrap();
    client.open_program(&program).unwrap();
    client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
import ghidra.docking.settings.FormatSettingsDefinition;
import ghidra.program.model.data.*;
public class CreateFieldDeletionSettingsCases extends GhidraScript {
    public void run() throws Exception {
        var dtm = currentProgram.getDataTypeManager();
        int address = 0x1000;
        for (boolean keepSettings : new boolean[] { true, false }) {
            String suffix = keepSettings ? "Guarded" : "Free";
            var union = new UnionDataType(CategoryPath.ROOT, "DeleteUnion" + suffix, dtm);
            union.add(QWordDataType.dataType, "wide", null);
            union.add(DWordDataType.dataType, "narrow", null);
            var savedUnion = dtm.addDataType(union, null);
            var holder = new StructureDataType("DeleteHolder" + suffix, 0, dtm);
            holder.setPackingEnabled(true);
            holder.add(savedUnion, "payload", null);
            holder.add(ByteDataType.dataType, "tail", null);
            var packed = new StructureDataType("DeleteStruct" + suffix, 0, dtm);
            packed.setPackingEnabled(true);
            packed.add(QWordDataType.dataType, "wide", null);
            packed.add(DWordDataType.dataType, "tail", null);
            for (var type : new StructureDataType[] { holder, packed }) {
                currentProgram.getMemory().createInitializedBlock(type.getName(), toAddr(address),
                    32, (byte) 0, monitor, false);
                var data = currentProgram.getListing().createData(toAddr(address), dtm.addDataType(type, null));
                if (keepSettings)
                    FormatSettingsDefinition.DEF.setChoice(data.getComponent(1), FormatSettingsDefinition.BINARY);
                address += 0x100;
            }
        }
    }
}
"#,
            &[],
            &[],
            false,
        )
        .unwrap();
    for name in ["DeleteUnionGuarded", "DeleteStructGuarded"] {
        let before = definition(&program, name);
        let holder = definition(&program, "DeleteHolderGuarded");
        let failed = type_command(&program, &["field", "delete", name, "--field", "wide"]);
        failed
            .assert_failure()
            .assert_stderr_contains("applied component settings changed");
        let error: Value = serde_json::from_str(&failed.stderr).unwrap();
        assert_eq!(error["detail"]["rolled_back"], true, "{error}");
        client.program_close().unwrap();
        assert_eq!(definition(&program, name), before);
        assert_eq!(definition(&program, "DeleteHolderGuarded"), holder);
    }
    for name in ["DeleteUnionFree", "DeleteStructFree"] {
        success(type_command(
            &program,
            &["field", "delete", name, "--field", "wide"],
        ));
        assert_eq!(definition(&program, name)["size"], 4);
    }
    client.program_close().unwrap();
    client.open_program(&program).unwrap();
    client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
import ghidra.docking.settings.FormatSettingsDefinition;
public class CheckFieldDeletionSettingsCases extends GhidraScript {
    public void run() throws Exception {
        var listing = currentProgram.getListing();
        for (int address : new int[] { 0x1000, 0x1100 }) {
            var data = listing.getDefinedDataAt(toAddr(address));
            if (FormatSettingsDefinition.DEF.getChoice(data.getComponent(1)) != FormatSettingsDefinition.BINARY)
                throw new IllegalStateException("Deletion lost a retained component's settings");
        }
        if (listing.getDefinedDataAt(toAddr(0x1200)).getLength() != 5
                || listing.getDefinedDataAt(toAddr(0x1300)).getLength() != 4)
            throw new IllegalStateException("Safe deletion failed to propagate complete data");
    }
}
"#,
            &[],
            &[],
            false,
        )
        .unwrap();
    client.open_program(TEST_PROGRAM).unwrap();
}

#[test]
#[serial]
fn union_growth_rejects_truncated_parent_embedding() {
    require_ghidra!();
    let program = create_type_edit_program("x86:LE:64:default");
    let client = harness().client().unwrap();
    client.open_program(&program).unwrap();
    client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
public class CreateUnionGrowthConflict extends GhidraScript {
    public void run() throws Exception {
        var dtm = currentProgram.getDataTypeManager();
        var member = new UnionDataType(CategoryPath.ROOT, "GrowingUnion", dtm);
        member.add(DWordDataType.dataType, "value", null);
        var saved = dtm.addDataType(member, null);
        var parent = new StructureDataType(CategoryPath.ROOT, "UnionParent", 8, dtm);
        parent.replaceAtOffset(0, saved, 4, "member", null);
        parent.replaceAtOffset(4, DWordDataType.dataType, 4, "tail", null);
        dtm.addDataType(parent, null);
    }
}
"#,
            &[],
            &[],
            false,
        )
        .unwrap();
    let member = definition(&program, "GrowingUnion");
    let parent = definition(&program, "UnionParent");
    for args in [
        vec![
            "field",
            "append",
            "GrowingUnion",
            "--name",
            "wide",
            "--type",
            "qword",
        ],
        vec![
            "field",
            "set",
            "GrowingUnion",
            "--ordinal",
            "0",
            "--type",
            "qword",
        ],
    ] {
        let failed = type_command(&program, &args);
        failed.assert_failure();
        let error: Value = serde_json::from_str(&failed.stderr).unwrap();
        assert_eq!(error["detail"]["rolled_back"], true, "{error}");
        assert_eq!(definition(&program, "GrowingUnion"), member);
        assert_eq!(definition(&program, "UnionParent"), parent);
    }
    client.program_close().unwrap();
    assert_eq!(definition(&program, "GrowingUnion"), member);
    assert_eq!(definition(&program, "UnionParent"), parent);
    client.open_program(TEST_PROGRAM).unwrap();
}

#[test]
#[serial]
fn union_edits_validate_targets_names_ancestry_and_sizes_before_mutation() {
    require_ghidra!();
    let program = create_type_edit_program("x86:LE:32:default");
    success(type_command(
        &program,
        &[
            "import-c",
            "--code",
            "union Payload { unsigned int tag; char raw[8]; }; struct Holder { int field; };",
            "--category",
            "/Recovered",
        ],
    ));
    let name = "/Recovered/Payload";
    let before = definition(&program, name);
    for (args, message) in [
        (
            vec!["field", "set", name, "--offset", "0", "--name", "wrong"],
            "require --ordinal",
        ),
        (
            vec!["field", "set", name, "--ordinal", "2", "--type", "byte"],
            "outside the union",
        ),
        (
            vec![
                "field",
                "set",
                name,
                "--ordinal",
                "0",
                "--name",
                "raw",
                "--type",
                "byte",
            ],
            "already exists",
        ),
        (
            vec![
                "field",
                "set",
                name,
                "--ordinal",
                "0",
                "--name",
                "renamed",
                "--type",
                name,
            ],
            "within it",
        ),
        (
            vec![
                "field",
                "set",
                name,
                "--ordinal",
                "0",
                "--type",
                "byte",
                "--size",
                "8",
            ],
            "cannot honor --size",
        ),
        (
            vec!["field", "append", name, "--name", "tag", "--type", "byte"],
            "already exists",
        ),
        (
            vec![
                "field", "append", name, "--name", "invalid", "--type", "void",
            ],
            "fixed positive size",
        ),
        (
            vec![
                "field", "append", name, "--name", "invalid", "--type", "byte", "--size", "0",
            ],
            "must be positive",
        ),
        (
            vec!["field", "delete", name, "--field", "absent"],
            "Field not found",
        ),
        (
            vec!["field", "set", name, "--field", "absent", "--type", "byte"],
            "Field not found",
        ),
        (
            vec!["field", "clear", name, "--field", "tag"],
            "not a struct",
        ),
    ] {
        let result = type_command(&program, &args);
        result.assert_failure().assert_stderr_contains(message);
        let error: Value = serde_json::from_str(&result.stderr).unwrap();
        assert_eq!(error["detail"]["rolled_back"], true, "{error}");
        assert_eq!(definition(&program, name), before);
    }
    let holder = definition(&program, "/Recovered/Holder");
    let client = harness().client().unwrap();
    for (command, args, message) in [
        (
            "type_field_set",
            json!({"type_name": name, "ordinal": 0, "offset": 0, "field_name": "wrong"}),
            "Exactly one",
        ),
        (
            "type_field_set",
            json!({"type_name": name, "ordinal": 0.5, "field_name": "wrong"}),
            "ordinal must be an integer",
        ),
        (
            "type_field_delete",
            json!({"type_name": name, "ordinal": 4294967296_u64}),
            "ordinal must be an integer",
        ),
        (
            "type_field_delete",
            json!({"type_name": name, "ordinal": 1, "field": "tag"}),
            "Exactly one",
        ),
        (
            "type_field_set",
            json!({"type_name": name, "ordinal": 0, "size": 2, "field_name": "wrong"}),
            "--size requires --type",
        ),
    ] {
        let error = client.send_command(command, Some(args)).unwrap_err();
        assert!(error.to_string().contains(message), "{error:#}");
        assert_eq!(definition(&program, name), before);
    }
    client.program_close().unwrap();
    assert_eq!(definition(&program, name), before);
    assert_eq!(definition(&program, "/Recovered/Holder"), holder);

    let text = success(set(
        &program,
        name,
        "1",
        &["--type", "string", "--size", "12"],
    ));
    assert_eq!(text["after"]["size"], 12);
    assert_eq!(text["after"]["name"], "raw");
    let pointer = success(type_command(
        &program,
        &[
            "field", "append", name, "--name", "pointer", "--type", "void *",
        ],
    ));
    assert_eq!(pointer["after"]["size"], 4);
    client.open_program(TEST_PROGRAM).unwrap();
}

fn assert_saved_settings(program: &str, union_name: &str, names: &[&str]) {
    let client = harness().client().unwrap();
    client.open_program(program).unwrap();
    let mut args = vec![union_name.to_owned()];
    args.extend(names.iter().map(|name| (*name).to_owned()));
    client.script_run_source(r#"
import ghidra.app.script.GhidraScript;
import ghidra.docking.settings.FormatSettingsDefinition;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
public class CheckSavedUnionSettings extends GhidraScript {
    public void run() throws Exception {
        Object consumer = new Object();
        Program saved = (Program) currentProgram.getDomainFile()
            .getReadOnlyDomainObject(consumer, DomainFile.DEFAULT_VERSION, monitor);
        try {
            String[] args = getScriptArgs();
            var union = (Union) saved.getDataTypeManager().getDataType("/" + args[0]);
            boolean packed = args[0].equals("Packed");
            if (union.isPackingEnabled() != packed || !union.getDescription().equals("recovered layout"))
                throw new IllegalStateException("Union layout metadata changed");
            if (packed && (union.getExplicitPackingValue() != 2
                    || union.getExplicitMinimumAlignment() != 16 || union.getAlignment() != 16))
                throw new IllegalStateException("Packing or minimum alignment changed");
            for (int i = 1; i < args.length; i++) {
                DataTypeComponent field = null;
                for (var candidate : union.getComponents())
                    if (args[i].equals(candidate.getFieldName())) field = candidate;
                if (field == null) throw new IllegalStateException("Missing member " + args[i]);
                if (FormatSettingsDefinition.DEF.getChoice(field.getDefaultSettings())
                        != FormatSettingsDefinition.DECIMAL
                        || EndianSettingsDefinition.DEF.getChoice(field.getDefaultSettings())
                        != EndianSettingsDefinition.BIG)
                    throw new IllegalStateException("Member settings changed: " + args[i]);
            }
            var holder = (Structure) saved.getDataTypeManager().getDataType("/" + args[0] + "Holder");
            var tail = holder.getComponentAt(16);
            if (!tail.getFieldName().equals("tail") || tail.getLength() != 4
                    || holder.getComponentAt(0).getDataType() != union
                    || FormatSettingsDefinition.DEF.getChoice(tail.getDefaultSettings())
                        != FormatSettingsDefinition.BINARY)
                throw new IllegalStateException("Parent field or its settings changed");
        } finally { saved.release(consumer); }
    }
}
"#, &args, &[], false).unwrap();
}

#[test]
#[serial]
fn union_edits_preserve_unnamed_members_packing_parent_layout_and_saved_settings() {
    require_ghidra!();
    let program = create_type_edit_program("x86:LE:64:default");
    let client = harness().client().unwrap();
    client.open_program(&program).unwrap();
    client.script_run_source(r#"
import ghidra.app.script.GhidraScript;
import ghidra.docking.settings.FormatSettingsDefinition;
import ghidra.program.model.data.*;
public class CreateUnionSettings extends GhidraScript {
    public void run() throws Exception {
        var dtm = currentProgram.getDataTypeManager();
        for (boolean packed : new boolean[] { false, true }) {
            String name = packed ? "Packed" : "Unpacked";
            var union = new UnionDataType(CategoryPath.ROOT, name, dtm);
            union.setDescription("recovered layout");
            if (packed) {
                union.setExplicitPackingValue(2);
                union.setExplicitMinimumAlignment(16);
            }
            union.add(QWordDataType.dataType, "wide", "wide comment");
            union.add(DWordDataType.dataType, null, "unnamed comment");
            var registered = (Union) dtm.addDataType(union, null);
            for (var field : registered.getComponents()) {
                FormatSettingsDefinition.DEF.setChoice(field.getDefaultSettings(), FormatSettingsDefinition.DECIMAL);
                EndianSettingsDefinition.DEF.setChoice(field.getDefaultSettings(), EndianSettingsDefinition.BIG);
            }
            var holder = new StructureDataType(CategoryPath.ROOT, name + "Holder", 24, dtm);
            holder.replaceAtOffset(0, registered, registered.getLength(), "payload", "union field");
            holder.replaceAtOffset(16, DWordDataType.dataType, 4, "tail", "tail comment");
            var saved = (Structure) dtm.addDataType(holder, null);
            FormatSettingsDefinition.DEF.setChoice(saved.getComponentAt(16).getDefaultSettings(), FormatSettingsDefinition.BINARY);
        }
    }
}
"#, &[], &[], false).unwrap();
    for name in ["Unpacked", "Packed"] {
        let initial = definition(&program, name);
        assert!(initial["components"][1]["name"].is_null());
        assert!(!initial["components"][1]["display_name"]
            .as_str()
            .unwrap()
            .is_empty());
        type_command(
            &program,
            &[
                "field",
                "delete",
                name,
                "--field",
                initial["components"][1]["display_name"].as_str().unwrap(),
            ],
        )
        .assert_failure()
        .assert_stderr_contains("Field not found");
        assert_eq!(definition(&program, name), initial);
        let holder = definition(&program, &format!("{name}Holder"));
        let renamed = success(set(&program, name, "1", &["--name", "narrow"]));
        assert_eq!(renamed["after"]["comment"], "unnamed comment");
        assert_saved_settings(&program, name, &["wide", "narrow"]);
        success(set(&program, name, "1", &["--comment", "updated comment"]));
        assert_saved_settings(&program, name, &["wide", "narrow"]);
        let replaced = success(set(&program, name, "0", &["--type", "unsigned long long"]));
        assert_eq!(replaced["status"], "updated");
        assert_eq!(replaced["after"]["comment"], "wide comment");
        assert_eq!(replaced["after"]["size"], 8);
        assert_eq!(definition(&program, &format!("{name}Holder")), holder);
        assert_saved_settings(&program, name, &["wide", "narrow"]);
        success(type_command(
            &program,
            &["field", "append", name, "--name", "extra", "--type", "byte"],
        ));
        assert_saved_settings(&program, name, &["wide", "narrow"]);
        success(type_command(
            &program,
            &["field", "delete", name, "--ordinal", "0"],
        ));
        assert_eq!(
            definition(&program, name)["components"][0]["name"],
            "narrow"
        );
        assert_saved_settings(&program, name, &["narrow"]);
        client.program_close().unwrap();
        assert_saved_settings(&program, name, &["narrow"]);
    }
    client.open_program(TEST_PROGRAM).unwrap();
}

#[test]
#[serial]
fn union_bitfield_metadata_and_deletion_preserve_other_members() {
    require_ghidra!();
    let program = create_type_edit_program("x86:LE:64:default");
    success(type_command(
        &program,
        &[
            "import-c",
            "--code",
            "union Flags { unsigned int bits:3; unsigned int raw; };",
        ],
    ));
    let before = definition(&program, "Flags");
    let edited = success(set(
        &program,
        "Flags",
        "0",
        &["--name", "renamed", "--comment", "flags"],
    ));
    assert_eq!(edited["before"], before["components"][0]);
    assert_eq!(edited["after"]["is_bitfield"], true);
    assert_eq!(edited["after"]["bit_size"], 3);
    set(&program, "Flags", "0", &["--bit-size", "4"])
        .assert_failure()
        .assert_stderr_contains("packing disabled");
    set(&program, "Flags", "0", &["--type", "uint16_t"])
        .assert_failure()
        .assert_stderr_contains("packing disabled");
    success(set(
        &program,
        "Flags",
        "1",
        &["--name", "value", "--type", "uint16_t"],
    ));
    let after = definition(&program, "Flags");
    assert_eq!(after["components"][0], edited["after"]);
    harness().client().unwrap().program_close().unwrap();
    assert_eq!(definition(&program, "Flags"), after);
    let deleted = success(type_command(
        &program,
        &["field", "delete", "Flags", "--field", "renamed"],
    ));
    assert_eq!(deleted["before"], edited["after"]);
    let remaining = definition(&program, "Flags");
    assert_eq!(remaining["components"].as_array().unwrap().len(), 1);
    assert_eq!(remaining["components"][0]["name"], "value");
    assert_eq!(remaining["components"][0]["size"], 2);
    harness()
        .client()
        .unwrap()
        .open_program(TEST_PROGRAM)
        .unwrap();
}
