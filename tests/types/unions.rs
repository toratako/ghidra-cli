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
fn union_edits_validate_targets_names_ancestry_and_sizes_before_mutation() {
    require_ghidra!();
    let program = create_type_edit_program("x86:LE:32:default");
    success(type_command(
        &program,
        &[
            "import-c",
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
