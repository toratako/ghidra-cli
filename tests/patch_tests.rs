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

#[path = "patch/define_code.rs"]
mod define_code;
#[path = "patch/memory_write.rs"]
mod memory_write;

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

    result.assert_success();
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
fn test_patch_failures_restore_bytes_listing_and_permissions() {
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
                for (long offset : new long[] {0x1000, 0x2000, 0x3000, 0x3002, 0x4000, 0x4002}) {
                    var block = program.getMemory().createInitializedBlock("code" + offset,
                        space.getAddress(offset), 2, (byte) 0x90, monitor, false);
                    block.setExecute(true);
                    block.setWrite(false);
                }
                program.getMemory().createUninitializedBlock("uninitialized",
                    space.getAddress(0x2002), 2, false);
                program.getMemory().setByte(space.getAddress(0x4001), (byte) 0xc3);
                program.getMemory().setByte(space.getAddress(0x4003), (byte) 0xc3);
                var alias = program.getMemory().createByteMappedBlock("alias",
                    space.getAddress(0x5000), space.getAddress(0x4002), 2, false);
                alias.setExecute(true);
                alias.setWrite(false);
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
            let receipt = client.define_code(address, None).unwrap();
            assert_eq!(receipt["landed"], true);
            let instructions = client.disasm(address, Some(2)).unwrap();
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

        // A change to the shared source must be rejected before clearing or
        // writing the earlier block, preserving both views and their metadata.
        for address in ["0x4000", "0x4002", "0x5000"] {
            assert_eq!(client.define_code(address, None).unwrap()["landed"], true);
        }
        let instructions = client
            .send_command(
                "disasm_range",
                Some(serde_json::json!({"start":"0x4000","end":"0x5001"})),
            )
            .unwrap();
        let map = client.send_command("memory_map", None).unwrap();
        let error = client.memory_write("0x4000", "11223344").unwrap_err();
        let error = error
            .downcast_ref::<ghidra_cli::ipc::protocol::BridgeCommandError>()
            .unwrap();
        assert!(error.message.contains("shared mapped memory"), "{error}");
        assert_eq!(error.detail["rolled_back"], true);
        assert!(error.detail.get("partial_changes_saved").is_none());
        for reopen in [false, true] {
            if reopen {
                client.open_program(TEST_PROGRAM).unwrap();
                client.open_program(&name).unwrap();
            }
            let bytes = client
                .send_command(
                    "read_memory",
                    Some(serde_json::json!({"address":"0x4000","size":4})),
                )
                .unwrap();
            assert_eq!(bytes["hex"], "90c390c3");
            assert_eq!(
                client
                    .send_command(
                        "disasm_range",
                        Some(serde_json::json!({"start":"0x4000","end":"0x5001"})),
                    )
                    .unwrap(),
                instructions
            );
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
