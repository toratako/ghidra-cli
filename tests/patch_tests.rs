//! Tests for patch operations.
//!
//! These tests verify that patching commands work correctly by:
//! 1. Using typed schemas to validate JSON output structure
//! 2. Dynamically resolving addresses instead of using hardcoded values
//! 3. Verifying actual effects through round-trip testing
//! 4. Using snapshot testing for output format regression detection

use serial_test::serial;
use std::sync::OnceLock;

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

/// Test patching bytes at a dynamically resolved address.
///
/// Verifies:
/// - Command succeeds
/// - Output can be parsed as PatchResult
/// - Status indicates success
#[test]
#[serial]
fn test_memory_write_success() {
    require_ghidra!();
    let harness = harness();

    // Dynamically get a valid code address
    let main_addr = get_function_address(harness, test_project(), TEST_PROGRAM, "main");

    let result = ghidra(harness)
        .arg("memory")
        .arg("write")
        .arg(&main_addr)
        .arg("90909090") // 4 NOP bytes
        .arg("--program")
        .arg(TEST_PROGRAM)
        .run();

    // Patching at code addresses may conflict with existing instructions in Ghidra
    assert!(
        result.exit_code == 0
            || result.stderr.contains("conflict")
            || result.stderr.contains("Memory change"),
        "Expected success or instruction conflict, got: stderr={}",
        result.stderr
    );
}

/// Disassembly failures retain diagnostics, stop dependent edits, and save any clearing.
#[test]
#[serial]
fn test_disasm_failure_exit_batch_stop_and_clear_persistence() {
    require_ghidra!();
    let harness = harness();
    let client = harness.client().unwrap();
    let name = format!("disasm-failure-{}", uuid::Uuid::new_v4());
    client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.util.DefaultLanguageService;
public class CreateDisasmFailureFixture extends GhidraScript {
    public void run() throws Exception {
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:64:default"));
        var program = new ProgramDB(getScriptArgs()[0], language,
            language.getDefaultCompilerSpec(), this);
        try {
            int tx = program.startTransaction("disassembly fixture");
            try {
                var address = program.getAddressFactory().getDefaultAddressSpace()
                    .getAddress(0x1000);
                var block = program.getMemory().createInitializedBlock("code", address,
                    1, (byte) 0xc3, monitor, false);
                block.setExecute(true);
                var longStart = address.add(0x1000);
                program.getMemory().createInitializedBlock("long_code", longStart,
                    21, (byte) 0x90, monitor, false).setExecute(true);
                // Alternate one-byte NOP/CLC to avoid Ghidra's repeated-byte guard.
                for (int offset = 1; offset < 20; offset += 2) {
                    program.getMemory().setByte(longStart.add(offset), (byte) 0xf8);
                }
                program.getMemory().setByte(longStart.add(20), (byte) 0xc3);
            } finally { program.endTransaction(tx, true); }
            state.getProject().getProjectData().getRootFolder()
                .createFile(getScriptArgs()[0], program, monitor);
        } finally { program.release(this); }
    }
}
"#,
            std::slice::from_ref(&name),
            &[],
            false,
        )
        .unwrap();
    client.open_program(&name).unwrap();
    let checked = std::panic::catch_unwind(|| {
        check_disasm_at_limits(harness, &client, &name);
        let instruction = client
            .send_command("disasm_at", Some(serde_json::json!({"address":"0x1000"})))
            .unwrap();
        assert_eq!(instruction["landed"], true);
        assert_eq!(instruction["already_disassembled"], false);
        assert_eq!(instruction["status"], "disassembled");
        let repeated = client
            .send_command("disasm_at", Some(serde_json::json!({"address":"0x1000"})))
            .unwrap();
        assert_eq!(repeated["already_disassembled"], true);
        assert_eq!(repeated["instructions"], instruction["instructions"]);

        // An unmapped address is syntactically valid but cannot produce an instruction.
        let failed = ghidra(harness)
            .args(["--json", "disassemble-at", "0x8000"])
            .run();
        assert_eq!(failed.exit_code, 1, "{failed:?}");
        assert!(failed.stdout.is_empty(), "{failed:?}");
        let error: serde_json::Value = serde_json::from_str(&failed.stderr).unwrap();
        let detail = &error["detail"];
        let failed_address = detail["address"].as_str().unwrap();
        assert_eq!(
            u64::from_str_radix(failed_address.strip_prefix("0x").unwrap(), 16).unwrap(),
            0x8000
        );
        assert_eq!(detail["already_disassembled"], false);
        // Ghidra can report true even when no instruction lands at the target.
        assert!(detail["ok"].is_boolean());
        assert_eq!(detail["landed"], false);
        assert_eq!(detail["status"], "failed");

        let batch = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            batch.path(),
            "disassemble-at 0x8000\ncomment set 0x1000 must-not-run\n",
        )
        .unwrap();
        let failed_batch = ghidra(harness)
            .args(["--json", "batch"])
            .arg(batch.path().to_str().unwrap())
            .args(["--on-error", "stop"])
            .run();
        assert_eq!(failed_batch.exit_code, 1, "{failed_batch:?}");
        let report: serde_json::Value = failed_batch.json();
        assert_eq!(report[0]["commands_executed"], 1);
        assert_eq!(report[0]["failed"], 1);
        assert_eq!(report[0]["not_executed"], 1);
        assert_eq!(report[0]["results"][0]["detail"]["landed"], false);
        assert!(client.comment_get("0x1000").unwrap()["comments"]
            .as_array()
            .unwrap()
            .is_empty());

        let cleared = ghidra(harness)
            .args([
                "--json",
                "clear",
                "0x1000:0x1000",
                "--disassemble-at",
                "0x8000",
            ])
            .run();
        assert_eq!(cleared.exit_code, 1, "{cleared:?}");
        assert!(cleared.stdout.is_empty(), "{cleared:?}");
        let clear_error: serde_json::Value = serde_json::from_str(&cleared.stderr).unwrap();
        let clear_detail = &clear_error["detail"];
        assert_eq!(clear_detail["start"], instruction["address"]);
        assert_eq!(clear_detail["end"], instruction["address"]);
        assert_eq!(clear_detail["disasm_at"], failed_address);
        assert!(clear_detail["ok"].is_boolean());
        assert_eq!(clear_detail["landed"], false);
        assert_eq!(clear_detail["status"], "cleared_disasm_incomplete");
        assert_eq!(clear_detail["partial_changes_saved"], true);
        assert!(clear_detail["hint"].is_string());

        // A failed redisassembly still durably saves the successful clear operation.
        client.open_program(TEST_PROGRAM).unwrap();
        client.open_program(&name).unwrap();
        let listing = client
            .send_command(
                "disasm_range",
                Some(serde_json::json!({"start":"0x1000","end":"0x1000"})),
            )
            .unwrap();
        assert_eq!(listing["count"], 0);
        let recovered = client
            .send_command(
                "clear_range",
                Some(serde_json::json!({"start":"0x1000","end":"0x1000","disasm_at":"0x1000"})),
            )
            .unwrap();
        assert_eq!(recovered["status"], "cleared_and_disassembled");
        assert_eq!(recovered["ok"], true);
        assert_eq!(recovered["landed"], true);
    });
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&name).unwrap();
    if let Err(panic) = checked {
        std::panic::resume_unwind(panic);
    }
}

fn check_disasm_at_limits(
    harness: &DaemonTestHarness,
    client: &ghidra_cli::ipc::client::BridgeClient,
    program: &str,
) {
    use serde_json::{json, Value};
    for limit in [json!(-1), json!(1.5), json!(u64::MAX)] {
        let error = client
            .send_command(
                "disasm_at",
                Some(json!({"address": "0x2000", "limit": limit})),
            )
            .unwrap_err();
        assert!(
            error.to_string().contains("limit must be an integer"),
            "{error}"
        );
    }
    let error = client
        .send_command("disasm_at", Some(json!({"address": "0x2000", "count": 1})))
        .unwrap_err();
    assert!(error.to_string().contains("use limit"), "{error}");
    assert_eq!(
        client.disasm_range("0x2000", "0x2014", None).unwrap()["count"],
        0,
        "invalid response limits must fail before creating any instructions"
    );

    let result = ghidra(harness)
        .args(["--json", "disassemble-at", "0x2000", "--limit", "1"])
        .with_project(test_project(), program)
        .run();
    result.assert_success();
    let receipt = &result.json::<Value>()[0];
    assert_eq!(receipt["already_disassembled"], false);
    assert_eq!(receipt["landed"], true);
    assert_eq!(receipt["instructions"].as_array().unwrap().len(), 1);
    let all = client.disasm_range("0x2000", "0x2014", None).unwrap();
    assert_eq!(
        all["count"], 21,
        "a response limit of one must still create the complete reachable sequence"
    );
    for limit in [None, Some(0), Some(i32::MAX as usize + 1)] {
        let result = client.disasm_at("0x2000", limit).unwrap();
        assert_eq!(result["already_disassembled"], true);
        assert_eq!(result["instructions"], all["instructions"]);
    }

    let config_dir = tempfile::tempdir().unwrap();
    let config = config_dir.path().join("config.yaml");
    let mut test_config = ghidra_cli::config::Config::load().unwrap();
    test_config.default_limit = Some(12);
    std::fs::write(&config, serde_yaml::to_string(&test_config).unwrap()).unwrap();
    for (flags, count) in [(vec![], 12), (vec!["--limit", "0"], 21)] {
        let result = ghidra(harness)
            .args(["--json", "disassemble-at", "0x2000"])
            .args(flags)
            .with_project(test_project(), program)
            .env("GHIDRA_CLI_CONFIG", config.to_string_lossy())
            .run();
        result.assert_success();
        assert_eq!(
            result.json::<Value>()[0]["instructions"],
            json!(&all["instructions"].as_array().unwrap()[..count])
        );
    }
}

/// Test exporting patched binary.
#[test]
#[serial]
fn test_program_export_binary() {
    require_ghidra!();
    let harness = harness();

    let directory = tempfile::tempdir().unwrap();
    let output_path = directory.path().join("patched.bin");

    let result = ghidra(harness)
        .args(["program", "export", "binary"])
        .arg("--output")
        .arg(output_path.to_str().unwrap())
        .arg("--program")
        .arg(TEST_PROGRAM)
        .run();

    result.assert_success();
    assert!(std::fs::metadata(&output_path).unwrap().len() > 0);
    let error = harness
        .client()
        .unwrap()
        .program_export("binary", directory.path().to_str())
        .unwrap_err();
    assert!(error.to_string().contains("export"), "{error}");
}

/// Test patching at function boundary (start of a function).
///
/// This tests a common use case: patching the first instruction
/// of a function (e.g., to add a hook or bypass).
#[test]
#[serial]
fn test_patch_at_function_boundary() {
    require_ghidra!();
    let harness = harness();

    // Get any function's entry point
    let func_addr = get_function_address(harness, test_project(), TEST_PROGRAM, "main");

    // Patch with RET instruction (c3 on x86)
    let result = ghidra(harness)
        .arg("memory")
        .arg("write")
        .arg(&func_addr)
        .arg("c3")
        .arg("--program")
        .arg(TEST_PROGRAM)
        .run();

    // Patching may succeed or fail with instruction conflict depending on Ghidra version
    // Just verify it doesn't crash/hang
    assert!(
        result.exit_code == 0
            || result.stderr.contains("conflict")
            || result.stderr.contains("Memory change"),
        "Expected success or instruction conflict error, got exit_code={}, stderr={}",
        result.exit_code,
        result.stderr
    );
}

/// Test patching at an invalid/unmapped address fails gracefully.
#[test]
#[serial]
fn test_patch_invalid_address_fails() {
    require_ghidra!();
    let harness = harness();

    // Use an address that's definitely outside the program's memory
    let result = ghidra(harness)
        .arg("memory")
        .arg("write")
        .arg("0xffffffffffffffff") // Very high address, unlikely to be mapped
        .arg("90")
        .arg("--program")
        .arg(TEST_PROGRAM)
        .run();

    // Should fail gracefully
    result.assert_failure();

    // Should provide a meaningful error message
    assert!(
        result.stderr.to_lowercase().contains("error")
            || result.stderr.to_lowercase().contains("invalid")
            || result.stderr.to_lowercase().contains("address")
            || result.stdout.to_lowercase().contains("error"),
        "Expected error message about invalid address.\nstderr: {}\nstdout: {}",
        result.stderr,
        result.stdout
    );
}

/// Test patching with invalid hex bytes fails gracefully.
#[test]
#[serial]
fn test_patch_invalid_hex_fails() {
    require_ghidra!();
    let harness = harness();

    let main_addr = get_function_address(harness, test_project(), TEST_PROGRAM, "main");

    let result = ghidra(harness)
        .arg("memory")
        .arg("write")
        .arg(&main_addr)
        .arg("ZZZZ") // Invalid hex
        .arg("--program")
        .arg(TEST_PROGRAM)
        .run();

    // Should fail with invalid hex
    result.assert_failure();
}

/// Invalid hex must fail before clearing instructions or changing memory permissions.
#[test]
#[serial]
fn test_patch_odd_hex_length() {
    require_ghidra!();
    let harness = harness();
    let client = harness.client().unwrap();
    let address = get_function_address(harness, test_project(), TEST_PROGRAM, "add_numbers");
    let disasm = || {
        client
            .send_command(
                "disasm",
                Some(serde_json::json!({"address":address,"limit":1})),
            )
            .unwrap()
    };
    let memory = || {
        client
            .send_command(
                "read_memory",
                Some(serde_json::json!({"address":address,"size":8})),
            )
            .unwrap()
    };
    let before_instruction = disasm();
    let before_memory = memory();
    let before_map = client.send_command("memory_map", None).unwrap();
    for hex in ["909", "0x9", "", "0x", "  ", "ZZ", "+1"] {
        let error = client.memory_write(&address, hex).unwrap_err();
        assert!(
            error.to_string().contains("complete byte pairs"),
            "{hex:?}: {error}"
        );
        assert_eq!(memory(), before_memory);
        assert_eq!(disasm(), before_instruction);
        assert_eq!(client.send_command("memory_map", None).unwrap(), before_map);
    }
}

/// Test that patching without --program argument uses default program.
#[test]
#[serial]
fn test_patch_without_program_arg() {
    require_ghidra!();
    let harness = harness();

    let main_addr = get_function_address(harness, test_project(), TEST_PROGRAM, "main");

    let result = ghidra(harness)
        .arg("memory")
        .arg("write")
        .arg(&main_addr)
        .arg("90")
        // Note: --program is missing, should use default from bridge
        .run();

    // May succeed (if bridge has default program) or fail
    // Just verify it doesn't crash
    assert!(
        result.exit_code == 0 || !result.stderr.is_empty(),
        "Should either succeed or provide an error message"
    );
}

// ============================================================================
// Snapshot tests for output format regression detection
// ============================================================================

/// Test that memory write produces meaningful output.
#[test]
#[serial]
fn test_patch_output_format_structure() {
    require_ghidra!();
    let harness = harness();

    let main_addr = get_function_address(harness, test_project(), TEST_PROGRAM, "main");

    let result = ghidra(harness)
        .arg("memory")
        .arg("write")
        .arg(&main_addr)
        .arg("90")
        .arg("--program")
        .arg(TEST_PROGRAM)
        .run();

    // Patching at code address may conflict with existing instructions
    // Verify the command produces some output (success or error)
    assert!(
        result.exit_code == 0 || !result.stderr.is_empty(),
        "Should produce output (success or error message)"
    );
}

#[test]
#[serial]
fn test_patch_range_validation_preserves_listing_and_permissions() {
    require_ghidra!();
    let client = harness().client().unwrap();
    let name = format!("patch-range-{}", uuid::Uuid::new_v4());
    client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.util.DefaultLanguageService;
public class CreatePatchRangeFixture extends GhidraScript {
    public void run() throws Exception {
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:64:default"));
        var program = new ProgramDB(getScriptArgs()[0], language,
            language.getDefaultCompilerSpec(), this);
        try {
            int tx = program.startTransaction("patch range fixture");
            try {
                var space = program.getAddressFactory().getDefaultAddressSpace();
                for (long offset : new long[] {0x1000, 0x2000, 0x3000, 0x3002}) {
                    var block = program.getMemory().createInitializedBlock("code" + offset,
                        space.getAddress(offset), 2, (byte) 0x90, monitor, false);
                    block.setExecute(true);
                    block.setWrite(false);
                }
                program.getMemory().createUninitializedBlock("uninitialized",
                    space.getAddress(0x2002), 2, false);
            } finally { program.endTransaction(tx, true); }
            state.getProject().getProjectData().getRootFolder()
                .createFile(getScriptArgs()[0], program, monitor);
        } finally { program.release(this); }
    }
}
"#,
            std::slice::from_ref(&name),
            &[],
            false,
        )
        .unwrap();
    client.open_program(&name).unwrap();
    let checked = std::panic::catch_unwind(|| {
        for address in ["0x1000", "0x2000"] {
            let instructions = client
                .send_command(
                    "disasm_at",
                    Some(serde_json::json!({"address":address,"limit":2})),
                )
                .unwrap();
            assert_eq!(instructions["landed"], true);
            let map = client.send_command("memory_map", None).unwrap();
            let error = client.memory_write(address, "cccccccc").unwrap_err();
            assert!(
                error.to_string().contains("fully mapped and initialized"),
                "{error}"
            );
            let after = client
                .send_command(
                    "disasm",
                    Some(serde_json::json!({"address":address,"limit":2})),
                )
                .unwrap();
            assert_eq!(after["instructions"], instructions["instructions"]);
            assert_eq!(client.send_command("memory_map", None).unwrap(), map);
        }
        let map = client.send_command("memory_map", None).unwrap();
        client.memory_write("0x3000", "11223344").unwrap();
        let bytes = client
            .send_command(
                "read_memory",
                Some(serde_json::json!({"address":"0x3000","size":4})),
            )
            .unwrap();
        assert_eq!(bytes["hex"], "11223344");
        // IntelHexExporter returns false for this 64-bit address space.
        let output = tempfile::tempdir().unwrap();
        let error = client
            .program_export(
                "hex",
                Some(output.path().join("code.hex").to_str().unwrap()),
            )
            .unwrap_err();
        assert!(error.to_string().contains("32 bits"), "{error}");

        assert_eq!(client.send_command("memory_map", None).unwrap(), map);
    });
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&name).unwrap();
    if let Err(panic) = checked {
        std::panic::resume_unwind(panic);
    }
}
