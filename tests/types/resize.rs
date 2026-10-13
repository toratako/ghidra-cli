//! Tail resizing preserves definitions and validates native propagation before saving.

use super::common::helpers::GhidraResult;
use super::{create_type_edit_program, harness, type_command, TEST_PROGRAM};
use serde_json::{json, Value};
use serial_test::serial;

fn success(result: GhidraResult) -> Value {
    result.assert_success();
    result.data()
}

fn definition(program: &str, name: &str) -> Value {
    success(type_command(program, &["get", name]))
}

fn field<'a>(definition: &'a Value, name: &str) -> &'a Value {
    definition["components"]
        .as_array()
        .unwrap()
        .iter()
        .find(|field| field["name"] == name)
        .unwrap_or_else(|| panic!("Missing field {name}: {definition}"))
}

fn resize(program: &str, name: &str, size: u32) -> Value {
    success(type_command(
        program,
        &["resize", name, "--size", &size.to_string()],
    ))
}

fn rejected(program: &str, name: &str, size: u32) {
    let result = type_command(program, &["resize", name, "--size", &size.to_string()]);
    result.assert_failure();
    let error: Value = serde_json::from_str(&result.stderr).unwrap();
    assert_eq!(error["detail"]["rolled_back"], true, "{error}");
    assert!(error["detail"].get("partial_changes_saved").is_none());
}

fn saved_variable_state() -> Value {
    let result = harness()
        .client()
        .unwrap()
        .script_run_source(
            include_str!("../fixtures/types/SavedVariablePropagationFixture.java"),
            &["read".to_owned()],
            &[],
            false,
        )
        .unwrap();
    serde_json::from_str(result["stdout"].as_str().unwrap().trim()).unwrap()
}

fn with_saved_variable_fixture(check: impl FnOnce(&ghidra_cli::ipc::client::BridgeClient, &str)) {
    let program = create_type_edit_program("x86:LE:32:default");
    let client = harness().client().unwrap();
    super::common::with_temporary_program(&client, &program, TEST_PROGRAM, || {
        client
            .script_run_source(
                include_str!("../fixtures/types/SavedVariablePropagationFixture.java"),
                &["create".to_owned()],
                &[],
                false,
            )
            .unwrap();
        check(&client, &program);
    });
}

#[test]
#[serial]
fn type_growth_rejects_newly_invalid_saved_returns_parameters_and_locals() {
    require_ghidra!();
    with_saved_variable_fixture(|client, program| {
        let mut accepted = Vec::new();
        for operation in ["Resize", "Field", "Import"] {
            for kind in ["Return", "Parameter", "Local"] {
                let name = format!("{operation}{kind}");
                let path = format!("/Audit/{name}");
                let before = saved_variable_state();
                let types = success(type_command(
                    program,
                    &["list", "--limit", "0", "--sort", "path"],
                ));
                let declaration = format!("struct {name} {{ long long grown; }};");
                let args = match operation {
                    "Resize" => vec!["resize", &path, "--size", "8"],
                    "Field" => vec!["field", "append", &path, "--type", "int", "--name", "added"],
                    _ => vec!["import-c", "--category", "/Audit", "--code", &declaration],
                };
                let result = type_command(program, &args);
                if result.exit_code == 0 {
                    accepted.push(name);
                    continue;
                }
                result.assert_failure();
                let error: Value = serde_json::from_str(&result.stderr).unwrap();
                assert_eq!(error["detail"]["rolled_back"], true, "{error}");
                assert!(
                    error["message"].as_str().unwrap().contains("saved"),
                    "{error}"
                );
                for reopen in [false, true] {
                    if reopen {
                        client.program_close().unwrap();
                        client.open_program(program).unwrap();
                    }
                    assert_eq!(saved_variable_state(), before, "{operation}/{kind}");
                    assert_eq!(
                        success(type_command(
                            program,
                            &["list", "--limit", "0", "--sort", "path"]
                        )),
                        types
                    );
                }
            }
        }
        assert!(
            accepted.is_empty(),
            "Type growth invalidated saved native applications: {accepted:?}"
        );
    });
}

#[test]
#[serial]
fn type_growth_preserves_valid_dynamic_abis_and_existing_incomplete_definitions() {
    require_ghidra!();
    with_saved_variable_fixture(|client, program| {
        let before = saved_variable_state();
        assert_eq!(
            before["preexisting_invalid"]["variables"][1]["valid"],
            false
        );
        client
            .script_run_source(
                include_str!("../fixtures/types/CheckSavedVariablePropagationCancellation.java"),
                &[],
                &[],
                false,
            )
            .unwrap();
        assert_eq!(saved_variable_state(), before);
        for args in [
            vec!["resize", "/Audit/DynamicValue", "--size", "8"],
            vec![
                "field",
                "append",
                "/Audit/DynamicValue",
                "--type",
                "int",
                "--name",
                "added",
            ],
            vec![
                "import-c",
                "--category",
                "/Audit",
                "--code",
                "struct DynamicValue { long long lanes[2]; };",
            ],
        ] {
            success(type_command(program, &args));
            let after = saved_variable_state();
            for variable in after["dynamic"]["variables"].as_array().unwrap() {
                assert_eq!(variable["valid"], true, "{after}");
            }
            for (name, row) in before.as_object().unwrap() {
                if name != "dynamic" {
                    assert_eq!(&after[name], row, "{name}");
                }
            }
            client.program_close().unwrap();
            client.open_program(program).unwrap();
            assert_eq!(saved_variable_state(), after);
        }
        let before = saved_variable_state();
        resize(program, "/Audit/PreexistingInvalid", 12);
        let mut expected = before["preexisting_invalid"].clone();
        expected["variables"][1]["length"] = json!(12);
        assert_eq!(saved_variable_state()["preexisting_invalid"], expected);
        resize(program, "/Audit/Unreferenced", 8);
        resize(program, "/Audit/ResizeLocal", 2);
        let after = saved_variable_state();
        let local = after["ResizeLocal"]["variables"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["name"] == "saved_local")
            .unwrap();
        assert_eq!(local["length"], 4);
        assert_eq!(local["storage_length"], 8);
        assert_eq!(local["valid"], true);
        client.program_close().unwrap();
        client.open_program(program).unwrap();
        assert_eq!(saved_variable_state(), after);
    });
}

#[test]
#[serial]
fn resize_preserves_explicit_fields_bitfields_zero_length_boundaries_and_settings() {
    require_ghidra!();
    let program = create_type_edit_program("x86:LE:64:default");
    let client = harness().client().unwrap();
    client.open_program(&program).unwrap();
    client
        .script_run_source(
            include_str!("../fixtures/types/CreateResizeFields.java"),
            &[],
            &[],
            false,
        )
        .unwrap();
    let before = definition(&program, "Tail");
    let resized = resize(&program, "/Tail", 12);
    assert_eq!(resized["status"], "resized");
    assert_eq!(resized["changed"], true);
    assert_eq!(resized["path"], "/Tail");
    assert_eq!(resized["size_before"], 16);
    assert_eq!(resized["size_after"], 12);
    let trimmed = definition(&program, "Tail");
    for name in ["value", "unknown", "boundary"] {
        assert_eq!(field(&trimmed, name), field(&before, name));
    }
    assert_eq!(field(&trimmed, "boundary")["offset"], 12);
    assert_eq!(field(&trimmed, "boundary")["size"], 0);
    let noop = resize(&program, "Tail", 12);
    assert_eq!(noop["status"], "unchanged");
    assert_eq!(noop["changed"], false);
    rejected(&program, "Tail", 11);
    rejected(&program, "Tail", 7);
    assert_eq!(definition(&program, "Tail"), trimmed);
    resize(&program, "Tail", 24);
    let expanded = definition(&program, "Tail");
    for name in ["value", "unknown", "boundary"] {
        assert_eq!(field(&expanded, name), field(&before, name));
    }
    let flags_before = definition(&program, "Flags");
    resize(&program, "Flags", 8);
    assert_eq!(
        field(&definition(&program, "Flags"), "bits"),
        field(&flags_before, "bits")
    );
    rejected(&program, "Flags", 7);
    rejected(&program, "Packed", 16);
    client.program_close().unwrap();
    assert_eq!(definition(&program, "Tail"), expanded);
    client
        .script_run_source(
            include_str!("../fixtures/types/CheckResizeFieldSettings.java"),
            &[],
            &[],
            false,
        )
        .unwrap();
    client.open_program(TEST_PROGRAM).unwrap();
}

#[test]
#[serial]
fn resize_zero_is_logical_and_wire_sizes_are_checked_before_mutation() {
    require_ghidra!();
    let program = create_type_edit_program("x86:LE:64:default");
    success(type_command(&program, &["create", "struct", "Empty"]));
    let client = harness().client().unwrap();
    let noop = resize(&program, "Empty", 0);
    assert_eq!(noop["size_before"], 0);
    assert_eq!(noop["size_after"], 0);
    assert_eq!(noop["changed"], false);
    resize(&program, "Empty", 9);
    resize(&program, "Empty", 0);
    client.program_close().unwrap();
    assert_eq!(definition(&program, "Empty")["size"], 0);
    let listed = success(type_command(&program, &["list", "--filter", "name=Empty"]));
    assert_eq!(listed[0]["size"], 0);
    let before = definition(&program, "Empty");
    for size in [json!(-1), json!(1.5), json!(2147483648_u64), json!("8")] {
        client
            .send_command(
                "type_resize",
                Some(json!({"type_name": "/Empty", "size": size})),
            )
            .expect_err("Invalid wire size reached resize");
        assert_eq!(definition(&program, "Empty"), before);
    }
    client
        .script_run_source(
            include_str!("../fixtures/types/CreateResizeComponentOverflow.java"),
            &[],
            &[],
            false,
        )
        .unwrap();
    let before = definition(&program, "BitCount");
    rejected(&program, "BitCount", i32::MAX as u32);
    client.program_close().unwrap();
    assert_eq!(definition(&program, "BitCount"), before);
    client.open_program(TEST_PROGRAM).unwrap();
}

#[test]
#[serial]
fn resize_propagates_complete_layouts_through_parents_typedefs_arrays_and_listing() {
    require_ghidra!();
    let program = create_type_edit_program("x86:LE:64:default");
    let client = harness().client().unwrap();
    client.open_program(&program).unwrap();
    client
        .script_run_source(
            include_str!("../fixtures/types/CreateResizePropagation.java"),
            &[],
            &[],
            false,
        )
        .unwrap();
    for size in [8, 2] {
        resize(&program, "Child", size);
        assert_eq!(
            field(&definition(&program, "Holder"), "child")["size"],
            size
        );
        assert_eq!(
            field(&definition(&program, "Holder"), "array")["size"],
            size * 3
        );
        assert_eq!(field(&definition(&program, "Holder"), "tail")["offset"], 36);
        assert_eq!(
            field(&definition(&program, "PackedHolder"), "tag")["offset"],
            size
        );
        assert_eq!(
            field(&definition(&program, "UnionHolder"), "child")["size"],
            size
        );
        client.program_close().unwrap();
        client.open_program(&program).unwrap();
        client
            .script_run_source(
                include_str!("../fixtures/types/CheckResizePropagation.java"),
                &[size.to_string()],
                &[],
                false,
            )
            .unwrap();
    }
    resize(&program, "Aligned", 12);
    // Ghidra uses the nonpacked structure's exact length as its array stride,
    // even with explicit minimum alignment; getAlignedLength() remains 12.
    assert_eq!(definition(&program, "AlignedArray")["size"], 24);
    client.open_program(TEST_PROGRAM).unwrap();
}

#[test]
#[serial]
fn resize_rejects_incomplete_embeddings_and_applications_with_durable_rollback() {
    require_ghidra!();
    let program = create_type_edit_program("x86:LE:64:default");
    let client = harness().client().unwrap();
    client.open_program(&program).unwrap();
    client
        .script_run_source(
            include_str!("../fixtures/types/CreateResizeConflicts.java"),
            &[],
            &[],
            false,
        )
        .unwrap();
    let before = success(type_command(&program, &["list", "--limit", "0"]));
    let holder = definition(&program, "ConstrainedHolder");
    for (name, size) in [
        ("Embedded", 8),
        ("MemoryEdge", 8),
        ("DataNeighbor", 8),
        ("InstructionNeighbor", 8),
        ("Overflow", 8),
        ("AppliedEmpty", 0),
        ("AppliedSettings", 8),
        ("ArraySettings", 8),
    ] {
        rejected(&program, name, size);
        client.program_close().unwrap();
        assert_eq!(
            success(type_command(&program, &["list", "--limit", "0"])),
            before
        );
        assert_eq!(definition(&program, "ConstrainedHolder"), holder);
        client
            .script_run_source(
                include_str!("../fixtures/types/CheckResizeConflictRollback.java"),
                &[],
                &[],
                false,
            )
            .unwrap();
    }
    client.open_program(TEST_PROGRAM).unwrap();
}

#[test]
#[serial]
fn field_growth_rejects_truncated_parent_embedding() {
    require_ghidra!();
    let program = create_type_edit_program("x86:LE:64:default");
    let client = harness().client().unwrap();
    client.open_program(&program).unwrap();
    client
        .script_run_source(
            include_str!("../fixtures/types/CreateFieldGrowthConflict.java"),
            &[],
            &[],
            false,
        )
        .unwrap();
    let child = definition(&program, "GrowingChild");
    let parent = definition(&program, "ConstrainedParent");
    for args in [
        vec![
            "field",
            "append",
            "GrowingChild",
            "--name",
            "extra",
            "--type",
            "dword",
        ],
        vec![
            "field",
            "set",
            "GrowingChild",
            "--offset",
            "4",
            "--name",
            "extra",
            "--type",
            "dword",
        ],
    ] {
        let failed = type_command(&program, &args);
        failed.assert_failure();
        let error: Value = serde_json::from_str(&failed.stderr).unwrap();
        assert_eq!(error["detail"]["rolled_back"], true, "{error}");
        assert_eq!(definition(&program, "GrowingChild"), child);
        assert_eq!(definition(&program, "ConstrainedParent"), parent);
    }
    client.program_close().unwrap();
    assert_eq!(definition(&program, "GrowingChild"), child);
    assert_eq!(definition(&program, "ConstrainedParent"), parent);
    client.open_program(TEST_PROGRAM).unwrap();
}
