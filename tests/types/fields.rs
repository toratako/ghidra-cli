//! Offset field edits preserve recovered layouts and reject destructive guesses.

use super::common::helpers::GhidraResult;
use super::{ghidra, harness, test_project, unique_suffix, TEST_PROGRAM};
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
    command(&["create", &name]).assert_success();
    name
}

fn set(name: &str, offset: &str, attributes: &[&str]) -> GhidraResult {
    let mut args = vec!["set-field", name, "--offset", offset];
    args.extend_from_slice(attributes);
    command(&args)
}

fn clear(name: &str, offset: &str) -> GhidraResult {
    command(&["clear-field", name, "--offset", offset])
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
    assert_eq!(created["struct"], name);
    assert_eq!(created["path"], format!("/{name}"));
    assert_eq!(created["offset"], 16);
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
    rejected_unchanged(
        &name,
        &before,
        command(&[
            "add-field",
            &name,
            "--offset",
            "0x0",
            "--name",
            "blocked",
            "--type",
            "byte[8]",
        ]),
        "overlaps",
    );
    rejected_unchanged(
        &name,
        &before,
        command(&[
            "add-field",
            &name,
            "--offset",
            "0x6",
            "--name",
            "blocked",
            "--type",
            "byte",
        ]),
        "inside a field",
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
            "type_set_field",
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
fn clear_field_preserves_size_and_offsets_while_del_field_still_removes_bytes() {
    require_ghidra!();
    let name = create_struct();
    for (offset, field_name, field_type) in
        [("0x0", "head", "byte[8]"), ("0x10", "later", "byte[4]")]
    {
        command(&[
            "add-field",
            &name,
            "--offset",
            offset,
            "--name",
            field_name,
            "--type",
            field_type,
        ])
        .assert_success();
    }
    command(&["add-field", &name, "--name", "appended", "--type", "byte"]).assert_success();
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
    assert_eq!(field(&after, "later"), field(&original, "later"));
    assert_eq!(field(&after, "appended"), field(&original, "appended"));
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

    command(&["del-field", &name, "--name", "later"]).assert_success();
    let deleted = definition(&name);
    assert_eq!(deleted["size"], 17);
    assert_eq!(field(&deleted, "appended")["offset"], 16);
    harness().client().unwrap().program_close().unwrap();
    assert_eq!(definition(&name), deleted);
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
        clear(&packed, &value_offset),
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
        ] {
            let error = rejected_unchanged(&name, &before, result, "not supported by offset edits");
            assert_eq!(error["detail"]["field"]["name"], field_name);
        }
    }
}
