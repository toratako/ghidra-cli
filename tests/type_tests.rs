//! Tests for type operations.

use predicates::prelude::*;
use serial_test::serial;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

#[macro_use]
mod common;
use common::{ensure_test_project, ghidra, DaemonTestHarness};

use common::test_project;
const TEST_PROGRAM: &str = common::FIXTURE_PROGRAM;

#[path = "types/application.rs"]
mod application;
#[path = "types/bitfields.rs"]
mod bitfields;
#[path = "types/calling_conventions.rs"]
mod calling_conventions;
#[path = "types/components.rs"]
mod components;
#[path = "types/definitions.rs"]
mod definitions;
#[path = "types/enums.rs"]
mod enums;
#[path = "types/fields.rs"]
mod fields;
#[path = "types/input.rs"]
mod input;
#[path = "types/registry.rs"]
mod registry;
#[path = "types/resize.rs"]
mod resize;
#[path = "types/resolution.rs"]
mod resolution;
#[path = "types/return_types.rs"]
mod return_types;
#[path = "types/signatures.rs"]
mod signatures;
#[path = "types/unions.rs"]
mod unions;
#[path = "types/uses.rs"]
mod uses;
#[path = "types/variables.rs"]
mod variables;

static HARNESS: OnceLock<DaemonTestHarness> = OnceLock::new();

fn harness() -> &'static DaemonTestHarness {
    HARNESS.get_or_init(|| {
        ensure_test_project(test_project(), TEST_PROGRAM);
        DaemonTestHarness::new(test_project(), TEST_PROGRAM).expect("Failed to start daemon")
    })
}

fn unique_suffix() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_nanos()
}

fn type_command(program: &str, args: &[&str]) -> common::helpers::GhidraResult {
    ghidra(harness())
        .arg("type")
        .args(args.iter().copied())
        .with_project(test_project(), program)
        .arg("--json")
        .run()
}

fn assert_field_receipt(value: &serde_json::Value, kind: &str, name: &str, status: &str) {
    let keys: Vec<_> = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        [
            "after",
            "before",
            "changed",
            "kind",
            "name",
            "path",
            "size_after",
            "size_before",
            "status"
        ]
    );
    assert_eq!(value["kind"], kind);
    assert_eq!(value["name"], name);
    assert_eq!(value["path"], format!("/{name}"));
    assert_eq!(value["status"], status);
    assert_eq!(value["changed"], status != "unchanged");
    assert!(value["size_before"].is_u64());
    assert!(value["size_after"].is_u64());
}

fn create_type_edit_program(language: &str) -> String {
    let program = format!("type-edits-{}", unique_suffix());
    harness()
        .client()
        .unwrap()
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.util.DefaultLanguageService;
public class CreateTypeEditProgram extends GhidraScript {
    public void run() throws Exception {
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID(getScriptArgs()[1]));
        var program = new ProgramDB(getScriptArgs()[0], language,
            language.getDefaultCompilerSpec(), this);
        try {
            state.getProject().getProjectData().getRootFolder()
                .createFile(getScriptArgs()[0], program, monitor);
        } finally { program.release(this); }
    }
}
"#,
            &[program.clone(), language.to_string()],
            &[],
            false,
        )
        .unwrap();
    program
}

#[test]
#[serial]
fn test_type_list() {
    require_ghidra!();
    let _harness = harness();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("type")
        .arg("list")
        .arg("--project")
        .arg(test_project())
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();
}

#[test]
#[serial]
fn test_type_get_primitive() {
    require_ghidra!();
    let _harness = harness();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("type")
        .arg("get")
        .arg("int")
        .arg("--project")
        .arg(test_project())
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success()
        .stdout(predicate::str::contains("size"));
}

#[test]
#[serial]
fn test_type_create_struct() {
    require_ghidra!();
    let _harness = harness();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("type")
        .arg("create")
        .arg("struct")
        .arg("MyTestStruct")
        .arg("--project")
        .arg(test_project())
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    // Verify created type exists
    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("type")
        .arg("get")
        .arg("MyTestStruct")
        .arg("--project")
        .arg(test_project())
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success()
        .stdout(predicate::str::contains("MyTestStruct"));
}

#[test]
#[serial]
fn test_type_field_set_places_at_exact_offset() {
    require_ghidra!();
    let _harness = harness();

    // Regression: `--offset` used to behave as insert-before (shifting every
    // later field by the new field's size) instead of placing the field at
    // that exact byte offset. Add three fields out of ascending order and
    // confirm none of them moved and the struct didn't grow past what the
    // offsets require. Uses "byte" (always 1 byte, unlike "pointer" whose
    // size depends on the target's bitness) so the offsets below stay
    // non-overlapping on any platform running this test.
    let _ = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("type")
        .arg("delete")
        .arg("OffsetPlacementStruct")
        .arg("--project")
        .arg(test_project())
        .arg("--program")
        .arg(TEST_PROGRAM)
        .output();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("type")
        .arg("create")
        .arg("struct")
        .arg("OffsetPlacementStruct")
        .arg("--project")
        .arg(test_project())
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    for (name, offset) in [("field_a", 36), ("field_b", 40), ("field_c", 60)] {
        assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
            .arg("type")
            .args(["field", "set"])
            .arg("OffsetPlacementStruct")
            .arg("--name")
            .arg(name)
            .arg("--type")
            .arg("byte")
            .arg("--offset")
            .arg(offset.to_string())
            .arg("--project")
            .arg(test_project())
            .arg("--program")
            .arg(TEST_PROGRAM)
            .assert()
            .success();
    }

    let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("type")
        .arg("get")
        .arg("OffsetPlacementStruct")
        .arg("--project")
        .arg(test_project())
        .arg("--program")
        .arg(TEST_PROGRAM)
        .arg("--format")
        .arg("json")
        .output()
        .expect("Failed to run command");
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str::<serde_json::Value>(stdout.trim())
        .unwrap_or_else(|e| panic!("bad JSON: {} in {}", e, stdout));
    let obj = &parsed["data"];

    assert_eq!(
        obj["size"].as_u64(),
        Some(61),
        "struct should be exactly as large as the last field (offset 60, 1 byte) requires, not bigger: {}",
        obj
    );

    let components = obj["components"].as_array().expect("components array");
    for (name, offset) in [("field_a", 36), ("field_b", 40), ("field_c", 60)] {
        let comp = components
            .iter()
            .find(|c| c["name"].as_str() == Some(name))
            .unwrap_or_else(|| panic!("field {} missing from struct: {}", name, obj));
        assert_eq!(
            comp["offset"].as_i64(),
            Some(offset),
            "field {} should sit at its requested offset, not be shifted: {}",
            name,
            obj
        );
    }
}

#[test]
#[serial]
fn test_type_field_append_accepts_common_c_type_names() {
    require_ghidra!();
    let _harness = harness();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("type")
        .arg("create")
        .arg("struct")
        .arg("CTypeNameStruct")
        .arg("--project")
        .arg(test_project())
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    // Regression: only "pointer" and "undefined4" used to resolve; ordinary
    // C/Ghidra builtin spellings (including ones `function set-signature`
    // already accepted, like "void *") were rejected with "Field type not
    // found".
    for (field, ty) in [
        ("f_uint", "uint"),
        ("f_dword", "dword"),
        ("f_int", "int"),
        ("f_charptr", "char *"),
        ("f_voidptr", "void *"),
        ("f_uint32", "uint32_t"),
        ("f_u32", "u32"),
        ("f_ulong", "ulong"),
    ] {
        assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
            .arg("type")
            .args(["field", "append"])
            .arg("CTypeNameStruct")
            .arg("--name")
            .arg(field)
            .arg("--type")
            .arg(ty)
            .arg("--project")
            .arg(test_project())
            .arg("--program")
            .arg(TEST_PROGRAM)
            .assert()
            .success();
    }
}

#[test]
#[serial]
fn test_type_get_nonexistent() {
    require_ghidra!();
    let _harness = harness();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("type")
        .arg("get")
        .arg("NonexistentType12345")
        .arg("--project")
        .arg(test_project())
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .failure();
}
