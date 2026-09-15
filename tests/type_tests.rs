//! Tests for type operations.

use predicates::prelude::*;
use serial_test::serial;
use std::collections::HashSet;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

#[macro_use]
mod common;
use common::{ensure_test_project, get_function_address, ghidra, DaemonTestHarness};

use common::test_project;
const TEST_PROGRAM: &str = common::FIXTURE_PROGRAM;

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

#[test]
#[serial]
fn test_function_set_signature_reports_application_failure() {
    require_ghidra!();
    let harness = harness();
    let client = harness.client().unwrap();
    let program = format!("signature-{}", uuid::Uuid::new_v4());
    client.script_run_source(r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
public class CreateSignatureTestProgram extends GhidraScript {
    public void run() throws Exception {
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:64:default"));
        var program = new ProgramDB(getScriptArgs()[0], language,
            language.getDefaultCompilerSpec(), this);
        try {
            int tx = program.startTransaction("signature fixture");
            try {
                var address = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
                program.getMemory().createInitializedBlock("code", address, 16, (byte) 0, monitor, false);
                var function = program.getFunctionManager().createFunction("signature_target", address,
                    new AddressSet(address, address.add(15)), SourceType.USER_DEFINED);
                program.getSymbolTable().createLabel(address.add(1), "collision", function,
                    SourceType.USER_DEFINED);
            } finally { program.endTransaction(tx, true); }
            state.getProject().getProjectData().getRootFolder()
                .createFile(getScriptArgs()[0], program, monitor);
        } finally { program.release(this); }
    }
}
"#, std::slice::from_ref(&program), &[], false).unwrap();

    let set_signature = |signature: &str| {
        ghidra(harness)
            .arg("function")
            .arg("set-signature")
            .arg("signature_target")
            .arg("--signature")
            .arg(signature)
            .with_project(test_project(), &program)
            .arg("--json")
            .run()
    };
    let valid = set_signature("int signature_target(int argument)");
    valid.assert_success();
    let result: serde_json::Value = valid.json();
    assert_eq!(result[0]["status"], "signature_set");
    assert!(result[0]["signature"]
        .as_str()
        .unwrap()
        .contains("int argument"));

    // This is valid C syntax, but applying the parameter conflicts with a label
    // in the function's namespace. Ghidra reports false without throwing.
    let invalid = set_signature("int signature_target(int collision)");
    // Restore the suite's selection even when the regression assertion fails.
    client.open_program(TEST_PROGRAM).unwrap();
    invalid.assert_failure();
    let error: serde_json::Value = serde_json::from_str(&invalid.stderr).unwrap();
    assert_eq!(error["status"], "error");
    assert!(
        error["message"]
            .as_str()
            .unwrap()
            .contains("Failed to set signature: Parameter name conflict"),
        "{error}"
    );

    let repaired = set_signature("void signature_target(int recovered)");
    repaired.assert_success();
    client.program_close().unwrap();
    client.open_program(&program).unwrap();
    let saved = client
        .send_command(
            "get_function",
            Some(serde_json::json!({"address": "signature_target"})),
        )
        .unwrap();
    client.open_program(TEST_PROGRAM).unwrap();
    assert!(
        saved["signature"]
            .as_str()
            .unwrap()
            .contains("void signature_target(int recovered)"),
        "{saved}"
    );
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
fn test_type_create() {
    require_ghidra!();
    let _harness = harness();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("type")
        .arg("create")
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
fn test_type_apply() {
    require_ghidra!();
    let harness = harness();

    let addr = get_function_address(harness, test_project(), TEST_PROGRAM, "main");

    let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("type")
        .arg("apply")
        .arg(&addr)
        .arg("int")
        .arg("--project")
        .arg(test_project())
        .arg("--program")
        .arg(TEST_PROGRAM)
        .output()
        .expect("Failed to run command");

    // Applying a type at a code address may conflict with existing instructions
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success()
            || stderr.contains("Conflicting instruction")
            || stderr.contains("conflict"),
        "Expected success or instruction conflict, got: {}",
        stderr
    );
}

/// Add bytes to a hex address while preserving its width, for the instruction
/// window restored by this suite's type-application test.
fn hex_addr_plus(addr: &str, delta: u64) -> String {
    let val = u64::from_str_radix(addr, 16).expect("hex address");
    format!("{:0width$x}", val + delta, width = addr.len())
}

/// Force-clear+redisassemble a small window at `addr` back to instructions,
/// via the same `clear --disasm-at` path a caller would use to recover from
/// this (ghidra-bug.md's own suggested workaround) -- used both to armor this
/// test against `main` having been left mid-disassembled by another test
/// sharing the fixture, and to restore it afterward.
fn restore_disassembly(harness: &DaemonTestHarness, addr: &str) {
    ghidra(harness)
        .arg("clear")
        .arg(format!("{}:{}", addr, hex_addr_plus(addr, 15)))
        .arg("--disasm-at")
        .arg(addr)
        .arg("--json")
        .with_project(test_project(), TEST_PROGRAM)
        .run()
        .assert_success();
}

#[test]
#[serial]
// This suite owns its project, so clearing main cannot affect another suite.
fn test_type_apply_force_on_function_entry_warns() {
    require_ghidra!();
    let harness = harness();

    let addr = get_function_address(harness, test_project(), TEST_PROGRAM, "main");
    // Earlier type tests in this suite can clear instructions. Start from a
    // defined function entry so this test exercises the intended conflict.
    restore_disassembly(harness, &addr);

    // --force on a function's own entry point clears its code (not a
    // conflicting data unit) -- the response must flag that distinctly so a
    // caller doesn't mistake it for a normal conflict-clear (ghidra-bug.md).
    let result = ghidra(harness)
        .arg("type")
        .arg("apply")
        .arg(&addr)
        .arg("int")
        .arg("--force")
        .arg("--json")
        .with_project(test_project(), TEST_PROGRAM)
        .run();

    // Restore `main`'s disassembly for the many other tests sharing this
    // fixture regardless of what the assertions below find.
    restore_disassembly(harness, &addr);

    result.assert_success();
    // The CLI wraps single-address results in a JSON array.
    let json: serde_json::Value = result.json();
    let entry = &json[0];
    assert_eq!(entry["cleared_conflicting"], true);
    assert_eq!(
        entry["is_function_entry"], true,
        "expected is_function_entry:true when --force clears a function's own entry, got: {}",
        entry
    );
    assert!(
        entry["warning"]
            .as_str()
            .is_some_and(|w| w.contains("main")),
        "expected a warning naming the cleared function, got: {}",
        entry
    );
}

#[test]
#[serial]
fn test_type_add_field_places_at_exact_offset() {
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
            .arg("add-field")
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
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("bad JSON: {} in {}", e, stdout));
    let obj = parsed.as_array().and_then(|a| a.first()).unwrap_or(&parsed);

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
fn test_type_add_field_accepts_common_c_type_names() {
    require_ghidra!();
    let _harness = harness();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("type")
        .arg("create")
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
            .arg("add-field")
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

#[test]
#[serial]
fn test_type_import_c_category_keeps_existing_same_named_types() {
    require_ghidra!();
    let harness = harness();

    let suffix = unique_suffix();
    let type_name = format!("CatIsoType_{}", suffix);
    let category_a = format!("/cat_a_{}", suffix);
    let category_b = format!("/cat_b_{}", suffix);
    let def_a = format!("struct {} {{ int a; }};", type_name);
    let def_b = format!("struct {} {{ int b; }};", type_name);

    ghidra(harness)
        .arg("type")
        .arg("import-c")
        .arg("--category")
        .arg(&category_a)
        .arg(&def_a)
        .with_project(test_project(), TEST_PROGRAM)
        .run()
        .assert_success();

    ghidra(harness)
        .arg("type")
        .arg("import-c")
        .arg("--category")
        .arg(&category_b)
        .arg(&def_b)
        .with_project(test_project(), TEST_PROGRAM)
        .run()
        .assert_success();

    let list_result = ghidra(harness)
        .arg("type")
        .arg("list")
        .arg("--filter")
        .arg(format!("name={type_name}"))
        .with_project(test_project(), TEST_PROGRAM)
        .json_format()
        .run();

    list_result.assert_success();
    let listed_types: Vec<serde_json::Value> = list_result.json();

    let categories: HashSet<String> = listed_types
        .iter()
        .filter(|item| item.get("name").and_then(|v| v.as_str()) == Some(type_name.as_str()))
        .filter_map(|item| item.get("category").and_then(|v| v.as_str()))
        .map(|s| s.to_string())
        .collect();

    assert!(
        categories.contains(&category_a),
        "Expected {} to remain after second import. Seen categories: {:?}",
        category_a,
        categories
    );
    assert!(
        categories.contains(&category_b),
        "Expected {} after second import. Seen categories: {:?}",
        category_b,
        categories
    );
}
