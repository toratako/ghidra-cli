//! Offset field edits preserve recovered layouts and reject destructive guesses.

use super::common::helpers::GhidraResult;
use super::{assert_field_receipt, ghidra, harness, test_project, unique_suffix, TEST_PROGRAM};
use serde_json::{json, Value};
use serial_test::serial;

fn command(args: &[&str]) -> GhidraResult {
    ghidra(harness())
        .arg("type")
        .args(args.iter().copied())
        .with_project(test_project(), TEST_PROGRAM)
        .arg("--json")
        .run()
}

fn success(result: GhidraResult) -> Value {
    result.assert_success();
    let value: Value = result.json();
    value
        .as_array()
        .map(|items| &items[0])
        .unwrap_or(&value)
        .clone()
}

fn definition(name: &str) -> Value {
    success(command(&["get", name]))
}

fn create_struct() -> String {
    let name = format!("FieldEditing_{}", unique_suffix());
    command(&["create", "struct", &name]).assert_success();
    name
}

fn set(name: &str, offset: &str, attributes: &[&str]) -> GhidraResult {
    let mut args = vec!["field", "set", name, "--offset", offset];
    args.extend_from_slice(attributes);
    command(&args)
}

fn clear(name: &str, offset: &str) -> GhidraResult {
    command(&["field", "clear", name, "--offset", offset])
}

fn field<'a>(definition: &'a Value, name: &str) -> &'a Value {
    definition["components"]
        .as_array()
        .unwrap()
        .iter()
        .find(|component| component["name"].as_str() == Some(name))
        .unwrap_or_else(|| panic!("Missing field {name}: {definition}"))
}

fn rejected_unchanged(name: &str, before: &Value, result: GhidraResult, message: &str) -> Value {
    result.assert_failure();
    let error: Value = serde_json::from_str(&result.stderr).unwrap();
    assert!(
        error["message"].as_str().unwrap().contains(message),
        "Expected {message}: {error}"
    );
    assert!(
        error["detail"].get("partial_changes_saved").is_none(),
        "{error}"
    );
    assert_eq!(definition(name), *before);
    error
}

fn assert_saved_field_settings(name: &str, offsets: &[&str]) {
    let mut args = vec![name.to_owned()];
    args.extend(offsets.iter().map(|offset| (*offset).to_owned()));
    harness().client().unwrap().script_run_source(r#"
import ghidra.app.script.GhidraScript;
import ghidra.docking.settings.FormatSettingsDefinition;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.data.EndianSettingsDefinition;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Program;
public class CheckSavedFieldSettings extends GhidraScript {
    public void run() throws Exception {
        Object consumer = new Object();
        Program saved = (Program) currentProgram.getDomainFile()
            .getReadOnlyDomainObject(consumer, DomainFile.DEFAULT_VERSION, monitor);
        try {
            String[] args = getScriptArgs();
            var structure = (Structure) saved.getDataTypeManager().getDataType("/" + args[0]);
            for (int i = 1; i < args.length; i++) {
                var settings = structure.getComponentAt(Integer.parseInt(args[i])).getDefaultSettings();
                if (FormatSettingsDefinition.DEF.getChoice(settings) != FormatSettingsDefinition.DECIMAL)
                    throw new IllegalStateException("Lost field format at " + args[i]);
                if (EndianSettingsDefinition.DEF.getChoice(settings) != EndianSettingsDefinition.BIG)
                    throw new IllegalStateException("Lost field byte order at " + args[i]);
            }
        } finally {
            saved.release(consumer);
        }
    }
}
"#, &args, &[], false).unwrap();
}

#[test]
#[serial]
fn field_edits_preserve_saved_component_settings() {
    require_ghidra!();
    let prefix = format!("Settings_{}", unique_suffix());
    harness().client().unwrap().script_run_source(r#"
import ghidra.app.script.GhidraScript;
import ghidra.docking.settings.FormatSettingsDefinition;
import ghidra.program.model.data.*;
public class CreateFieldSettings extends GhidraScript {
    public void run() throws Exception {
        var dtm = currentProgram.getDataTypeManager();
        for (boolean packed : new boolean[] { false, true }) {
            String name = getScriptArgs()[0] + (packed ? "Packed" : "Unpacked");
            var structure = new StructureDataType(CategoryPath.ROOT, name, packed ? 0 : 24, dtm);
            if (packed) {
                structure.setPackingEnabled(true);
                structure.add(DWordDataType.dataType, "head", null);
                structure.add(DWordDataType.dataType, "tail", null);
            } else {
                structure.replaceAtOffset(0, DWordDataType.dataType, 4, "head", null);
                structure.replaceAtOffset(16, DWordDataType.dataType, 4, "tail", null);
            }
            var saved = (Structure) dtm.addDataType(structure, null);
            for (var component : saved.getDefinedComponents()) {
                FormatSettingsDefinition.DEF.setChoice(component.getDefaultSettings(), FormatSettingsDefinition.DECIMAL);
                EndianSettingsDefinition.DEF.setChoice(component.getDefaultSettings(), EndianSettingsDefinition.BIG);
            }
        }
    }
}
"#, std::slice::from_ref(&prefix), &[], false).unwrap();

    for (suffix, tail) in [("Packed", "4"), ("Unpacked", "16")] {
        let name = format!("{prefix}{suffix}");
        assert_saved_field_settings(&name, &["0", tail]);
        success(set(&name, "0", &["--comment", "new comment"]));
        assert_saved_field_settings(&name, &["0", tail]);
        success(set(&name, "0", &["--name", "renamed"]));
        assert_saved_field_settings(&name, &["0", tail]);
        let before = definition(&name);
        let appended = success(command(&[
            "field", "append", &name, "--name", "extra", "--type", "byte",
        ]));
        assert_field_receipt(&appended, "struct", &name, "appended");
        assert_eq!(appended["size_before"], before["size"]);
        assert!(appended["before"].is_null());
        let after = definition(&name);
        assert_eq!(appended["after"], *field(&after, "extra"));
        assert_eq!(appended["size_after"], after["size"]);
        assert_eq!(after["packing_enabled"], before["packing_enabled"]);
        assert_saved_field_settings(&name, &["0", tail]);
        success(command(&["field", "delete", &name, "--field", "extra"]));
        assert_eq!(definition(&name), before);
        assert_saved_field_settings(&name, &["0", tail]);
    }
    let name = format!("{prefix}Unpacked");
    success(set(
        &name,
        "8",
        &["--name", "inserted", "--type", "uint32_t"],
    ));
    assert_saved_field_settings(&name, &["0", "16"]);
    success(set(&name, "8", &["--type", "byte[6]"]));
    assert_saved_field_settings(&name, &["0", "16"]);
    success(clear(&name, "0"));
    assert_saved_field_settings(&name, &["16"]);
    success(set(&name, "24", &["--type", "byte[8]"]));
    assert_saved_field_settings(&name, &["16"]);
    harness().client().unwrap().program_close().unwrap();
    harness()
        .client()
        .unwrap()
        .open_program(TEST_PROGRAM)
        .unwrap();
    assert_saved_field_settings(&name, &["16"]);
}

#[test]
#[serial]
fn set_field_preserves_attributes_and_offsets_while_shrinking_and_growing() {
    require_ghidra!();
    let name = create_struct();
    let created = success(set(
        &name,
        "0x10",
        &[
            "--name",
            "payload",
            "--type",
            "byte[8]",
            "--comment",
            "original",
        ],
    ));
    assert_eq!(created["status"], "created");
    assert_eq!(created["changed"], true);
    assert_eq!(created["name"], name);
    assert_eq!(created["path"], format!("/{name}"));
    assert_eq!(created["after"]["offset"], 16);
    assert_eq!(created["size_before"], 0);
    assert_eq!(created["size_after"], 24);
    assert!(created["before"].is_null());
    assert_eq!(created["after"]["name"], "payload");
    assert_eq!(created["after"]["display_name"], "payload");
    assert_eq!(created["after"]["type_path"], "/byte[8]");
    assert_eq!(created["after"]["comment"], "original");
    success(set(
        &name,
        "0x20",
        &[
            "--name",
            "tail",
            "--type",
            "byte[4]",
            "--comment",
            "tail comment",
        ],
    ));

    let metadata = success(set(&name, "16", &["--comment", "recovered payload"]));
    assert_eq!(metadata["status"], "updated");
    assert_eq!(metadata["before"], created["after"]);
    assert_eq!(metadata["after"]["name"], "payload");
    assert_eq!(metadata["after"]["type"], "byte[8]");
    assert_eq!(metadata["after"]["comment"], "recovered payload");
    let renamed = success(set(&name, "16", &["--name", "data"]));
    assert_eq!(renamed["after"]["name"], "data");
    assert_eq!(renamed["after"]["type"], "byte[8]");
    assert_eq!(renamed["after"]["comment"], "recovered payload");
    let same = success(set(&name, "16", &["--name", "data"]));
    assert_eq!(same["status"], "unchanged");
    assert_eq!(same["changed"], false);
    assert_eq!(same["before"], same["after"]);

    let shrunk = success(set(&name, "16", &["--type", "byte[4]"]));
    assert_eq!(shrunk["after"]["size"], 4);
    assert_eq!(shrunk["after"]["name"], "data");
    assert_eq!(shrunk["after"]["comment"], "recovered payload");
    assert_eq!(shrunk["size_before"], 36);
    assert_eq!(shrunk["size_after"], 36);
    let after_shrink = definition(&name);
    assert_eq!(field(&after_shrink, "tail")["offset"], 32);
    let cleared_tail = after_shrink["components"]
        .as_array()
        .unwrap()
        .iter()
        .find(|component| component["offset"] == 20)
        .expect("Shrinking should leave an undefined component at the old tail");
    assert!(cleared_tail["name"].is_null());
    assert_eq!(cleared_tail["size"], 1);

    let grown = success(set(&name, "16", &["--type", "byte[12]"]));
    assert_eq!(grown["after"]["size"], 12);
    assert_eq!(grown["size_after"], 36);
    let extended = success(set(&name, "32", &["--type", "byte[8]"]));
    assert_eq!(extended["size_before"], 36);
    assert_eq!(extended["size_after"], 40);
    assert_eq!(extended["after"]["name"], "tail");
    assert_eq!(extended["after"]["comment"], "tail comment");

    let anonymous = success(set(&name, "0", &["--type", "uint32_t"]));
    assert_eq!(anonymous["status"], "created");
    assert_eq!(anonymous["after"].get("name"), Some(&Value::Null));
    assert!(!anonymous["after"]["display_name"]
        .as_str()
        .unwrap()
        .is_empty());
    assert_eq!(anonymous["after"]["type_path"], "/dword");
    assert_eq!(anonymous["after"]["size"], 4);
    let comment_cleared = success(set(&name, "16", &["--comment", ""]));
    assert_eq!(comment_cleared["after"].get("comment"), Some(&Value::Null));
    assert_eq!(comment_cleared["after"]["name"], "data");
    assert_eq!(comment_cleared["after"]["type"], "byte[12]");

    let saved = definition(&name);
    assert_eq!(saved["size"], 40);
    assert_eq!(field(&saved, "data")["offset"], 16);
    assert_eq!(field(&saved, "data")["type_path"], "/byte[12]");
    assert_eq!(field(&saved, "tail")["offset"], 32);
    assert_eq!(field(&saved, "tail")["comment"], "tail comment");
    harness().client().unwrap().program_close().unwrap();
    assert_eq!(definition(&name), saved);
}

#[test]
#[serial]
fn validation_rejects_interior_overlap_collision_and_invalid_sizes_without_changes() {
    require_ghidra!();
    let name = create_struct();
    for (offset, field_name) in [("4", "first"), ("12", "second")] {
        success(set(
            &name,
            offset,
            &[
                "--name",
                field_name,
                "--type",
                "byte[4]",
                "--comment",
                "keep",
            ],
        ));
    }
    let before = definition(&name);
    let interior = rejected_unchanged(
        &name,
        &before,
        set(&name, "6", &["--name", "changed"]),
        "inside a field",
    );
    assert_eq!(interior["detail"]["field"]["name"], "first");
    assert_eq!(interior["detail"]["field"]["offset"], 4);
    rejected_unchanged(&name, &before, clear(&name, "6"), "inside a field");

    let overlap = rejected_unchanged(
        &name,
        &before,
        set(
            &name,
            "4",
            &["--type", "byte[12]", "--comment", "must not change"],
        ),
        "overlaps",
    );
    assert_eq!(overlap["detail"]["conflicts"][0]["name"], "second");
    assert_eq!(overlap["detail"]["conflicts"][0]["offset"], 12);
    rejected_unchanged(
        &name,
        &before,
        set(&name, "0", &["--type", "byte[8]"]),
        "overlaps",
    );
    let collision = rejected_unchanged(
        &name,
        &before,
        set(
            &name,
            "4",
            &["--name", "second", "--comment", "must not change"],
        ),
        "already exists",
    );
    assert_eq!(collision["detail"]["field"]["name"], "second");
    rejected_unchanged(
        &name,
        &before,
        set(
            &name,
            "4",
            &["--type", "void", "--comment", "must not change"],
        ),
        "fixed positive size",
    );
    rejected_unchanged(
        &name,
        &before,
        set(&name, "4", &["--type", &name]),
        "within it",
    );
    rejected_unchanged(
        &name,
        &before,
        set(&name, "2147483647", &["--type", "byte"]),
        "maximum structure size",
    );
    rejected_unchanged(
        &name,
        &before,
        set(&name, "0", &["--comment", "missing type"]),
        "--type is required",
    );
    rejected_unchanged(&name, &before, clear(&name, "16"), "outside the structure");
    set(&name, "4", &[]).assert_failure();
    assert_eq!(definition(&name), before);

    // Direct bridge callers must receive the same no-attribute validation.
    let client = harness().client().unwrap();
    assert!(client
        .send_command(
            "type_field_set",
            Some(json!({"type_name": name, "offset": 4}))
        )
        .is_err());
    assert_eq!(definition(&name), before);

    // A self pointer is valid even though embedding the structure is not.
    let linked = success(set(
        &name,
        "16",
        &["--name", "next", "--type", &format!("{name} *")],
    ));
    assert_eq!(linked["after"]["name"], "next");
    assert_eq!(linked["after"]["offset"], 16);
}

#[test]
#[serial]
fn offset_field_size_is_honored_or_rejected_before_changing_the_structure() {
    require_ghidra!();
    let name = create_struct();
    success(set(
        &name,
        "4",
        &["--name", "anchor", "--type", "byte[4]", "--comment", "keep"],
    ));
    let created = success(set(
        &name,
        "12",
        &[
            "--name",
            "sized",
            "--type",
            "string",
            "--size",
            "8",
            "--comment",
            "text",
        ],
    ));
    assert_eq!(created["status"], "created");
    assert!(created["before"].is_null());
    assert_eq!(created["after"]["size"], 8);
    let before = definition(&name);
    assert_eq!(field(&before, "sized")["size"], 8);
    assert_eq!(before["size"], 20);

    // Exercise replacement, placement in padding, and structure growth. Ghidra
    // ignores a requested size larger than this fixed type's own length.
    for offset in ["4", "8", "24"] {
        rejected_unchanged(
            &name,
            &before,
            set(
                &name,
                offset,
                &["--name", "invalid", "--type", "byte", "--size", "4"],
            ),
            "Ghidra cannot honor --size",
        );
    }

    // Ghidra can honor a smaller component length even for a fixed-size array.
    // Accept it only when the stored component and structure use that length.
    success(set(
        &name,
        "24",
        &["--name", "bounded", "--type", "byte[4]", "--size", "1"],
    ));
    let after = definition(&name);
    assert_eq!(field(&after, "bounded")["offset"], 24);
    assert_eq!(field(&after, "bounded")["size"], 1);
    assert_eq!(after["size"], 25);
    assert_eq!(field(&after, "anchor"), field(&before, "anchor"));
    assert_eq!(field(&after, "sized"), field(&before, "sized"));
    let resized = success(set(&name, "12", &["--type", "string", "--size", "4"]));
    assert_eq!(resized["status"], "updated");
    assert_eq!(resized["before"], created["after"]);
    assert_eq!(resized["after"]["name"], "sized");
    assert_eq!(resized["after"]["comment"], "text");
    assert_eq!(resized["after"]["size"], 4);
    assert_eq!(resized["size_before"], 25);
    assert_eq!(resized["size_after"], 25);
    let same = success(set(&name, "12", &["--type", "string", "--size", "4"]));
    assert_eq!(same["status"], "unchanged");
    assert_eq!(same["changed"], false);
    let saved = definition(&name);
    // Shrinking the earlier field adds four undefined byte components before bounded.
    let mut bounded = field(&after, "bounded").clone();
    bounded["ordinal"] = json!(bounded["ordinal"].as_u64().unwrap() + 4);
    assert_eq!(field(&saved, "bounded"), &bounded);
    assert_eq!(field(&saved, "anchor"), field(&before, "anchor"));
    let client = harness().client().unwrap();
    client.program_close().unwrap();
    client.open_program(TEST_PROGRAM).unwrap();
    assert_eq!(definition(&name), saved);
}

#[test]
#[serial]
fn field_sizes_require_a_type_and_valid_integer_before_mutation() {
    require_ghidra!();
    let name = create_struct();
    success(set(&name, "0", &["--name", "anchor", "--type", "byte[4]"]));
    let before = definition(&name);
    rejected_unchanged(
        &name,
        &before,
        set(&name, "0", &["--type", "byte", "--size", "0"]),
        "Field size must be positive",
    );

    let client = harness().client().unwrap();
    for (command, args, message) in [
        (
            "type_field_set",
            json!({"type_name": name, "offset": 0, "field_name": "renamed", "size": 2}),
            "--size requires --type",
        ),
        (
            "type_field_set",
            json!({"type_name": name, "offset": 0, "field_type": "byte", "size": 4294967297_u64}),
            "size must be an integer",
        ),
        (
            "type_field_append",
            json!({"type_name": name, "field_name": "invalid", "field_type": "byte", "size": 1.5}),
            "size must be an integer",
        ),
    ] {
        let error = client.send_command(command, Some(args)).unwrap_err();
        assert!(error.to_string().contains(message), "{error:#}");
        assert_eq!(definition(&name), before);
    }
}

#[test]
#[serial]
fn clear_preserves_size_and_offsets_while_delete_compacts() {
    require_ghidra!();
    let name = create_struct();
    for (offset, field_name, field_type) in
        [("0x0", "head", "byte[8]"), ("0x10", "later", "byte[4]")]
    {
        success(set(
            &name,
            offset,
            &["--name", field_name, "--type", field_type],
        ));
    }
    command(&[
        "field", "append", &name, "--name", "appended", "--type", "byte",
    ])
    .assert_success();
    let original = definition(&name);
    assert_eq!(original["size"], 21);
    assert_eq!(field(&original, "appended")["offset"], 20);

    let cleared = success(clear(&name, "0"));
    assert_eq!(cleared["status"], "cleared");
    assert_eq!(cleared["changed"], true);
    assert_eq!(cleared["size_before"], 21);
    assert_eq!(cleared["size_after"], 21);
    assert_eq!(cleared["before"]["name"], "head");
    assert!(cleared["after"].is_null());
    let after = definition(&name);
    assert_eq!(after["size"], 21);
    // Clearing one eight-byte field creates eight undefined byte components.
    for name in ["later", "appended"] {
        let mut expected = field(&original, name).clone();
        expected["ordinal"] = json!(expected["ordinal"].as_u64().unwrap() + 7);
        assert_eq!(field(&after, name), &expected);
    }
    for offset in ["0", "8"] {
        let unchanged = success(clear(&name, offset));
        assert_eq!(unchanged["status"], "unchanged");
        assert_eq!(unchanged["changed"], false);
        assert!(unchanged["before"].is_null());
        assert!(unchanged["after"].is_null());
        assert_eq!(definition(&name), after);
    }
    success(set(&name, "0", &["--type", "byte[8]"]));
    let unnamed = success(clear(&name, "0"));
    assert_eq!(unnamed["before"].get("name"), Some(&Value::Null));
    assert!(!unnamed["before"]["display_name"]
        .as_str()
        .unwrap()
        .is_empty());
    assert_eq!(unnamed["size_after"], 21);

    command(&["field", "delete", &name, "--field", "later"]).assert_success();
    let deleted = definition(&name);
    assert_eq!(deleted["size"], 17);
    assert_eq!(field(&deleted, "appended")["offset"], 16);
    harness().client().unwrap().program_close().unwrap();
    assert_eq!(definition(&name), deleted);
}

#[test]
#[serial]
fn named_edits_and_offset_deletion_return_consistent_field_receipts() {
    require_ghidra!();
    let name = create_struct();
    let created = success(set(&name, "0", &["--type", "byte[4]"]));
    assert_field_receipt(&created, "struct", &name, "created");
    assert!(created["after"]["name"].is_null());
    let appended = success(command(&[
        "field", "append", &name, "--name", "tail", "--type", "byte[4]",
    ]));
    assert_field_receipt(&appended, "struct", &name, "appended");
    assert_eq!(appended["after"]["offset"], 4);

    let deleted = success(command(&["field", "delete", &name, "--offset", "0x0"]));
    assert_field_receipt(&deleted, "struct", &name, "deleted");
    assert_eq!(deleted["before"], created["after"]);
    assert!(deleted["after"].is_null());
    assert_eq!(deleted["size_before"], 8);
    assert_eq!(deleted["size_after"], 4);
    assert_eq!(field(&definition(&name), "tail")["offset"], 0);

    let renamed = success(command(&[
        "field",
        "set",
        &name,
        "--field",
        "tail",
        "--name",
        "renamed",
        "--comment",
        "recovered",
    ]));
    assert_field_receipt(&renamed, "struct", &name, "updated");
    assert_eq!(renamed["before"]["name"], "tail");
    assert_eq!(renamed["after"]["name"], "renamed");
    let unchanged = success(command(&[
        "field",
        "set",
        &name,
        "--field",
        "renamed",
        "--comment",
        "recovered",
    ]));
    assert_field_receipt(&unchanged, "struct", &name, "unchanged");
    assert_eq!(unchanged["before"], renamed["after"]);
    assert_eq!(unchanged["after"], renamed["after"]);

    let cleared = success(command(&["field", "clear", &name, "--field", "renamed"]));
    assert_field_receipt(&cleared, "struct", &name, "cleared");
    assert_eq!(cleared["before"], renamed["after"]);
    assert!(cleared["after"].is_null());
    assert_eq!(cleared["size_before"], 4);
    assert_eq!(cleared["size_after"], 4);
    let unchanged = success(clear(&name, "0"));
    assert_field_receipt(&unchanged, "struct", &name, "unchanged");
    assert!(unchanged["before"].is_null());
    assert!(unchanged["after"].is_null());
    let saved = definition(&name);
    harness().client().unwrap().program_close().unwrap();
    assert_eq!(definition(&name), saved);
}

#[test]
#[serial]
fn field_selectors_reject_missing_ambiguous_and_interior_targets_without_mutation() {
    require_ghidra!();
    let name = create_struct();
    let unnamed = success(set(&name, "4", &["--type", "byte[4]"]));
    success(set(&name, "12", &["--name", "tail", "--type", "byte[4]"]));
    let before = definition(&name);
    for (offset, message) in [
        ("0", "No defined field"),
        ("5", "inside a field"),
        ("16", "No defined field"),
    ] {
        rejected_unchanged(
            &name,
            &before,
            command(&["field", "delete", &name, "--offset", offset]),
            message,
        );
    }
    let display_name = unnamed["after"]["display_name"].as_str().unwrap();
    for action in ["set", "clear", "delete"] {
        for selector in ["missing", display_name] {
            let mut args = vec!["field", action, &name, "--field", selector];
            if action == "set" {
                args.extend(["--name", "renamed"]);
            }
            rejected_unchanged(&name, &before, command(&args), "Field not found");
        }
    }
    let client = harness().client().unwrap();
    for args in [
        json!({"type_name": name}),
        json!({"type_name": name, "field": "tail", "offset": 4}),
        json!({"type_name": name, "field": "tail", "ordinal": 0}),
    ] {
        let error = client
            .send_command("type_field_delete", Some(args))
            .unwrap_err();
        assert!(error.to_string().contains("Exactly one"), "{error:#}");
        assert_eq!(definition(&name), before);
    }
    client.program_close().unwrap();
    assert_eq!(definition(&name), before);
}

#[test]
#[serial]
fn packed_layout_and_bitfield_or_zero_length_targets_are_guarded() {
    require_ghidra!();
    let prefix = format!("SpecialFields_{}", unique_suffix());
    harness()
        .client()
        .unwrap()
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
public class CreateSpecialFieldFixtures extends GhidraScript {
    public void run() throws Exception {
        var dtm = currentProgram.getDataTypeManager();
        String prefix = getScriptArgs()[0];
        var packed = new StructureDataType(CategoryPath.ROOT, prefix + "Packed", 0, dtm);
        packed.setPackingEnabled(true);
        packed.add(ByteDataType.dataType, "tag", "tag comment");
        packed.add(IntegerDataType.dataType, "value", "value comment");
        dtm.addDataType(packed, null);
        var bits = new StructureDataType(CategoryPath.ROOT, prefix + "Bits", 0, dtm);
        bits.addBitField(UnsignedIntegerDataType.dataType, 3, "flags", "bit comment");
        dtm.addDataType(bits, null);
        var zero = new StructureDataType(CategoryPath.ROOT, prefix + "Zero", 0, dtm);
        zero.add(ByteDataType.dataType, "start", null);
        zero.add(new ArrayDataType(ByteDataType.dataType, 0, -1, dtm), "zero", "empty");
        zero.add(ByteDataType.dataType, "end", null);
        dtm.addDataType(zero, null);
    }
}
"#,
            std::slice::from_ref(&prefix),
            &[],
            false,
        )
        .unwrap();
    let packed = format!("{prefix}Packed");
    let initial = definition(&packed);
    let value_offset = field(&initial, "value")["offset"]
        .as_u64()
        .unwrap()
        .to_string();
    let changed = success(set(
        &packed,
        &value_offset,
        &["--name", "renamed", "--comment", "updated"],
    ));
    assert_eq!(changed["status"], "updated");
    assert_eq!(changed["size_before"], changed["size_after"]);
    let packed_before = definition(&packed);
    assert_eq!(field(&packed_before, "tag"), field(&initial, "tag"));
    assert_eq!(
        field(&packed_before, "renamed")["offset"],
        field(&initial, "value")["offset"]
    );
    assert_eq!(
        field(&packed_before, "renamed")["type"],
        field(&initial, "value")["type"]
    );
    assert_eq!(field(&packed_before, "renamed")["comment"], "updated");
    rejected_unchanged(
        &packed,
        &packed_before,
        set(&packed, &value_offset, &["--type", "int"]),
        "packing disabled",
    );
    rejected_unchanged(
        &packed,
        &packed_before,
        command(&["field", "clear", &packed, "--field", "renamed"]),
        "packing disabled",
    );
    rejected_unchanged(
        &packed,
        &packed_before,
        set(&packed, "1", &["--type", "byte"]),
        "packing disabled",
    );

    for (name, field_name) in [
        (format!("{prefix}Bits"), "flags"),
        (format!("{prefix}Zero"), "zero"),
    ] {
        let before = definition(&name);
        let target = field(&before, field_name);
        if field_name == "zero" {
            assert_eq!(
                target["size"], 0,
                "Fixture must contain an actual zero-length field"
            );
        }
        let offset = target["offset"].as_u64().unwrap().to_string();
        for result in [
            set(&name, &offset, &["--comment", "changed"]),
            set(&name, &offset, &["--type", "byte"]),
            clear(&name, &offset),
            command(&["field", "delete", &name, "--offset", &offset]),
            command(&[
                "field",
                "set",
                &name,
                "--field",
                field_name,
                "--comment",
                "changed",
            ]),
            command(&["field", "clear", &name, "--field", field_name]),
        ] {
            let error = rejected_unchanged(&name, &before, result, "not supported by offset edits");
            assert_eq!(error["detail"]["field"]["name"], field_name);
        }
        let deleted = success(command(&["field", "delete", &name, "--field", field_name]));
        assert_field_receipt(&deleted, "struct", &name, "deleted");
        assert_eq!(deleted["before"], *target);
        assert!(!definition(&name)["components"]
            .as_array()
            .unwrap()
            .iter()
            .any(|field| field["name"] == field_name));
    }
}
