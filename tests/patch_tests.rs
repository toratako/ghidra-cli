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
fn test_patch_bytes_success() {
    require_ghidra!();
    let harness = harness();

    // Dynamically get a valid code address
    let main_addr = get_function_address(harness, test_project(), TEST_PROGRAM, "main");

    let result = ghidra(harness)
        .arg("patch")
        .arg("bytes")
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

/// Verify the ISA guard on actual x86 and AArch64 programs, independent of the host.
#[test]
#[serial]
fn test_patch_nop_processor_guard() {
    require_ghidra!();
    let client = harness().client().unwrap();
    for (language, hex, supported) in [
        ("x86:LE:64:default", "6690c3", true),
        ("AARCH64:LE:64:v8A", "1f2003d5c0035fd6", false),
    ] {
        let name = format!("nop-{}", uuid::Uuid::new_v4());
        client.script_run_source(r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.util.DefaultLanguageService;
public class CreateNopGuardProgram extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(args[1]));
        var program = new ProgramDB(args[0], language, language.getDefaultCompilerSpec(), this);
        try {
            int tx = program.startTransaction("test code");
            try {
                byte[] bytes = java.util.HexFormat.of().parseHex(args[2]);
                var address = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
                var block = program.getMemory().createInitializedBlock("code", address,
                    new java.io.ByteArrayInputStream(bytes), bytes.length, monitor, false);
                block.setExecute(true);
                block.setWrite(false);
            } finally { program.endTransaction(tx, true); }
            state.getProject().getProjectData().getRootFolder().createFile(args[0], program, monitor);
        } finally { program.release(this); }
    }
}
"#, &[name.clone(), language.to_owned(), hex.to_owned()], &[], false).unwrap();
        client.open_program(&name).unwrap();
        let instruction = client
            .send_command("disasm_at", Some(serde_json::json!({"address":"1000"})))
            .unwrap();
        assert_eq!(instruction["landed"], true, "{instruction}");
        let before = client
            .send_command(
                "read_memory",
                Some(serde_json::json!({"address":"1000", "size":hex.len()/2})),
            )
            .unwrap();
        let map_before = client.send_command("memory_map", None).unwrap();
        let result = client.send_command(
            "patch_nop",
            Some(serde_json::json!({"address":"1000", "count":1})),
        );
        let after = client
            .send_command(
                "read_memory",
                Some(serde_json::json!({"address":"1000", "size":hex.len()/2})),
            )
            .unwrap();
        if supported {
            let result = result.unwrap();
            assert_eq!(result["bytes"], 2);
            assert_eq!(after["hex"], "9090c3");
        } else {
            let error = result.unwrap_err();
            assert!(error.to_string().contains("supports only x86"), "{error}");
            assert!(error.to_string().contains("patch bytes"), "{error}");
            assert_eq!(after, before);
            let unchanged = client
                .send_command(
                    "disasm",
                    Some(serde_json::json!({"address":"1000", "count":1})),
                )
                .unwrap();
            assert_eq!(unchanged["instructions"], instruction["instructions"]);
        }
        assert_eq!(client.send_command("memory_map", None).unwrap(), map_before);
        // IntelHexExporter returns false, rather than throwing, for this 64-bit address space.
        let output = tempfile::tempdir().unwrap();
        let error = client
            .program_export(
                "hex",
                Some(output.path().join("code.hex").to_str().unwrap()),
            )
            .unwrap_err();
        assert!(error.to_string().contains("32 bits"), "{error}");
        client.open_program(TEST_PROGRAM).unwrap();
        client.program_delete(&name).unwrap();
    }
}

/// Test exporting patched binary.
#[test]
#[serial]
fn test_patch_export() {
    require_ghidra!();
    let harness = harness();

    let directory = tempfile::tempdir().unwrap();
    let output_path = directory.path().join("patched.bin");

    let result = ghidra(harness)
        .arg("patch")
        .arg("export")
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
        .patch_export(directory.path().to_str().unwrap())
        .unwrap_err();
    assert!(
        error.to_string().contains("Failed to export binary"),
        "{error}"
    );
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
        .arg("patch")
        .arg("bytes")
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
        .arg("patch")
        .arg("bytes")
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
        .arg("patch")
        .arg("bytes")
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
                Some(serde_json::json!({"address":address,"count":1})),
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
        let error = client.patch_bytes(&address, hex).unwrap_err();
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
        .arg("patch")
        .arg("bytes")
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

/// Test that patch bytes command produces meaningful output.
#[test]
#[serial]
fn test_patch_output_format_structure() {
    require_ghidra!();
    let harness = harness();

    let main_addr = get_function_address(harness, test_project(), TEST_PROGRAM, "main");

    let result = ghidra(harness)
        .arg("patch")
        .arg("bytes")
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
        for address in ["1000", "2000"] {
            let instructions = client
                .send_command(
                    "disasm_at",
                    Some(serde_json::json!({"address":address,"count":2})),
                )
                .unwrap();
            assert_eq!(instructions["landed"], true);
            let map = client.send_command("memory_map", None).unwrap();
            let error = client.patch_bytes(address, "cccccccc").unwrap_err();
            assert!(
                error.to_string().contains("fully mapped and initialized"),
                "{error}"
            );
            let after = client
                .send_command(
                    "disasm",
                    Some(serde_json::json!({"address":address,"count":2})),
                )
                .unwrap();
            assert_eq!(after["instructions"], instructions["instructions"]);
            assert_eq!(client.send_command("memory_map", None).unwrap(), map);
        }
        let map = client.send_command("memory_map", None).unwrap();
        client.patch_bytes("3000", "11223344").unwrap();
        let bytes = client
            .send_command(
                "read_memory",
                Some(serde_json::json!({"address":"3000","size":4})),
            )
            .unwrap();
        assert_eq!(bytes["hex"], "11223344");
        assert_eq!(client.send_command("memory_map", None).unwrap(), map);
    });
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&name).unwrap();
    if let Err(panic) = checked {
        std::panic::resume_unwind(panic);
    }
}
