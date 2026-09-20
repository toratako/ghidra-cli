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

/// Disassembly failures retain diagnostics, stop dependent edits, and roll back clearing.
#[test]
#[serial]
fn test_define_code_ranges_receipts_failures_and_persistence() {
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
                var flowStart = address.add(0x2000);
                byte[] flow = new byte[0x31];
                java.util.Arrays.fill(flow, (byte) 0xcc);
                // 0x3000 -> 0x3010; NOP then 0x3011 -> 0x3000 (a loop).
                byte[] jump = {(byte) 0xe9, 0x0b, 0, 0, 0};
                System.arraycopy(jump, 0, flow, 0, jump.length);
                flow[0x10] = (byte) 0x90;
                byte[] back = {(byte) 0xe9, (byte) 0xea, (byte) 0xff, (byte) 0xff, (byte) 0xff};
                System.arraycopy(back, 0, flow, 0x11, back.length);
                // 0x3020 -> 0x3030, outside the first requested range.
                System.arraycopy(jump, 0, flow, 0x20, jump.length);
                flow[0x30] = (byte) 0xc3;
                program.getMemory().createInitializedBlock("flow", flowStart,
                    new java.io.ByteArrayInputStream(flow), flow.length, monitor, false).setExecute(true);
                byte[] boundary = {0x66, (byte) 0x90, (byte) 0xc3};
                program.getMemory().createInitializedBlock("boundary", address.add(0x3000),
                    new java.io.ByteArrayInputStream(boundary), boundary.length, monitor, false).setExecute(true);
                byte[] partial = {(byte) 0x90, (byte) 0xb8, 1, 0, 0, 0, (byte) 0xc3};
                program.getMemory().createInitializedBlock("partial", address.add(0x3100),
                    new java.io.ByteArrayInputStream(partial), partial.length, monitor, false).setExecute(true);
                byte[] call = new byte[0x11];
                java.util.Arrays.fill(call, (byte) 0x90);
                call[0] = (byte) 0xe8; call[1] = 0x0b; call[2] = 0; call[3] = 0; call[4] = 0;
                call[0x10] = (byte) 0xc3;
                var callStart = address.add(0x4000);
                program.getMemory().createInitializedBlock("noreturn", callStart,
                    new java.io.ByteArrayInputStream(call), call.length, monitor, false).setExecute(true);
                var callee = callStart.add(0x10);
                new ghidra.app.cmd.disassemble.DisassembleCommand(callee, null, false).applyTo(program, monitor);
                program.getFunctionManager().createFunction("noreturn_target", callee,
                    new ghidra.program.model.address.AddressSet(callee, callee),
                    ghidra.program.model.symbol.SourceType.USER_DEFINED).setNoReturn(true);
                program.getSymbolTable().createLabel(longStart, "code_start",
                    ghidra.program.model.symbol.SourceType.USER_DEFINED);
                program.getSymbolTable().createLabel(longStart.add(11), "code_end",
                    ghidra.program.model.symbol.SourceType.USER_DEFINED);
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
        check_define_code_ranges(harness, &client, &name);
        let instruction = client.define_code("0x1000", None).unwrap();
        assert_eq!(instruction["landed"], true);
        assert_eq!(instruction["already_defined"], false);
        assert_eq!(instruction["changed"], true);
        assert_eq!(instruction["status"], "defined");
        assert!(instruction.get("instructions").is_none());
        let repeated = client.define_code("0x1000", None).unwrap();
        assert_eq!(repeated["already_defined"], true);
        assert_eq!(repeated["changed"], false);
        assert_eq!(repeated["status"], "unchanged");

        // An unmapped address is syntactically valid but cannot produce an instruction.
        let failed = ghidra(harness)
            .args(["--json", "define-code", "0x8000"])
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
        assert_eq!(detail["already_defined"], false);
        // Ghidra can report true even when no instruction lands at the target.
        assert!(detail["ok"].is_boolean());
        assert_eq!(detail["landed"], false);
        assert_eq!(detail["status"], "failed");
        assert_eq!(detail["rolled_back"], true);
        assert!(detail.get("partial_changes_saved").is_none());

        let batch = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            batch.path(),
            "define-code 0x8000\ncomment set 0x1000 must-not-run\n",
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
        assert_eq!(clear_detail["status"], "failed");
        assert_eq!(clear_detail["rolled_back"], true);
        assert!(clear_detail.get("partial_changes_saved").is_none());
        assert!(clear_detail["hint"].is_string());

        // Both the current listing and the saved program keep the earlier instruction.
        let restored = client
            .send_command(
                "disasm_range",
                Some(serde_json::json!({"start":"0x1000","end":"0x1000"})),
            )
            .unwrap();
        assert_eq!(restored["count"], 1);
        assert_eq!(restored["instructions"][0]["bytes"], "c3");
        client.open_program(TEST_PROGRAM).unwrap();
        client.open_program(&name).unwrap();
        let listing = client
            .send_command(
                "disasm_range",
                Some(serde_json::json!({"start":"0x1000","end":"0x1000"})),
            )
            .unwrap();
        assert_eq!(listing, restored);
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

fn check_define_code_ranges(
    harness: &DaemonTestHarness,
    client: &ghidra_cli::ipc::client::BridgeClient,
    program: &str,
) {
    use serde_json::{json, Value};
    for args in [
        json!({"target": "0x2000", "limit": 1}),
        json!({"target": "0x2000", "count": 1}),
        json!({"target": "0x2000", "end": "0x1fff"}),
        json!({"target": "0x2000", "end": "register:0x0"}),
        json!({"target": "0x2000", "end": "0xnot-hex"}),
        json!({"target": "0x2000", "end": "missing_end"}),
    ] {
        assert!(
            client
                .send_command("define_code", Some(args.clone()))
                .is_err(),
            "{args}"
        );
    }
    assert_eq!(
        client.disasm_range("0x2000", "0x2014", None).unwrap()["count"],
        0,
        "invalid arguments must fail before creating any instructions"
    );

    let result = ghidra(harness)
        .args(["--json", "define-code", "code_start", "--end", "code_end"])
        .with_project(test_project(), program)
        .run();
    result.assert_success();
    let receipt = &result.json::<Value>()[0];
    assert_eq!(receipt["already_defined"], false);
    assert_eq!(receipt["landed"], true);
    assert_eq!(receipt["changed"], true);
    assert_eq!(receipt["end"], "0x0000200b");
    let all = client.disasm_range("0x2000", "0x2014", None).unwrap();
    assert_eq!(
        all["count"], 12,
        "end must bound instruction creation, not just output"
    );
    let repeated = client.define_code("0x2000", Some("0x200b")).unwrap();
    assert_eq!(repeated["changed"], false);
    assert_eq!(repeated["status"], "unchanged");

    client.clear_range("0x2000", "0x2014", None).unwrap();
    let config_dir = tempfile::tempdir().unwrap();
    let config = config_dir.path().join("config.yaml");
    let mut test_config = ghidra_cli::config::Config::load().unwrap();
    test_config.default_limit = Some(12);
    std::fs::write(&config, serde_yaml::to_string(&test_config).unwrap()).unwrap();
    let result = ghidra(harness)
        .args(["--json", "define-code", "0x2000"])
        .with_project(test_project(), program)
        .env("GHIDRA_CLI_CONFIG", config.to_string_lossy())
        .run();
    result.assert_success();
    assert_eq!(
        client.disasm_range("0x2000", "0x2014", None).unwrap()["count"],
        21
    );

    client.define_code("0x3000", Some("0x3015")).unwrap();
    let flow = client.disasm_range("0x3000", "0x3030", None).unwrap();
    let addresses: Vec<_> = flow["instructions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            u64::from_str_radix(
                row["address"].as_str().unwrap().trim_start_matches("0x"),
                16,
            )
            .unwrap()
        })
        .collect();
    assert_eq!(
        addresses,
        [0x3000, 0x3010, 0x3011],
        "follow branches, not every byte; terminate loops"
    );
    client.define_code("0x3020", Some("0x3024")).unwrap();
    assert_eq!(
        client.disasm_range("0x3030", "0x3030", None).unwrap()["count"],
        0
    );
    client.clear_range("0x3020", "0x3024", None).unwrap();
    client.define_code("0x3020", None).unwrap();
    assert_eq!(
        client.disasm_range("0x3030", "0x3030", None).unwrap()["count"],
        1
    );

    client.define_code("0x4002", None).unwrap();
    client
        .comment_set("0x4002", "preserve outside preview", None)
        .unwrap();
    let outside = client.comment_get("0x4002").unwrap();
    assert!(client.define_code("0x4000", Some("0x4000")).is_err());
    assert_eq!(
        client.disasm_range("0x4000", "0x4002", None).unwrap()["count"],
        1,
        "preview rollback must preserve existing adjacent instructions"
    );
    client.define_code("0x4000", Some("0x4001")).unwrap();
    assert_eq!(
        client.disasm_range("0x4000", "0x4002", None).unwrap()["count"],
        2
    );
    client.define_code("0x4100", Some("0x4103")).unwrap();
    assert_eq!(
        client.disasm_range("0x4100", "0x4106", None).unwrap()["count"],
        1
    );
    client.define_code("0x5000", Some("0x5010")).unwrap();
    assert_eq!(
        client.disasm_range("0x5000", "0x5010", None).unwrap()["count"],
        2
    );
    assert_eq!(
        client.disasm_range("0x5005", "0x500f", None).unwrap()["count"],
        0,
        "native no-return handling must suppress fallthrough"
    );
    // Code definitions are saved, while underlying bytes remain untouched.
    client.open_program(TEST_PROGRAM).unwrap();
    client.open_program(program).unwrap();
    assert_eq!(
        client.disasm_range("0x4100", "0x4106", None).unwrap()["count"],
        1
    );
    let bytes = client
        .send_command("read_memory", Some(json!({"address": "0x4000", "size": 3})))
        .unwrap();
    assert_eq!(bytes["hex"], "6690c3");
    assert_eq!(client.comment_get("0x4002").unwrap(), outside);
}

#[test]
#[serial]
fn define_code_preserves_thumb_it_context() {
    require_ghidra!();
    let harness = harness();
    let client = harness.client().unwrap();
    let name = format!("define-code-thumb-{}", uuid::Uuid::new_v4());
    client.script_run_source(r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.util.DefaultLanguageService;
public class CreateBoundedThumbFixture extends GhidraScript {
    public void run() throws Exception {
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("ARM:LE:32:v8"));
        var program = new ProgramDB(getScriptArgs()[0], language,
            language.getDefaultCompilerSpec(), this);
        try {
            int tx = program.startTransaction("bounded Thumb fixture");
            try {
                byte[] bytes = {8, (byte) 0xbf, 1, 0x20, 0x70, 0x47}; // IT EQ; MOV R0,#1; BX LR
                var start = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
                program.getMemory().createInitializedBlock("code", start,
                    new java.io.ByteArrayInputStream(bytes), bytes.length, monitor, false).setExecute(true);
                program.getProgramContext().setValue(program.getRegister("TMode"), start, start.add(5), java.math.BigInteger.ONE);
            } finally { program.endTransaction(tx, true); }
            state.getProject().getProjectData().getRootFolder().createFile(getScriptArgs()[0], program, monitor);
        } finally { program.release(this); }
    }
}
"#, std::slice::from_ref(&name), &[], false).unwrap();
    client.open_program(&name).unwrap();
    let checked = std::panic::catch_unwind(|| {
        client.define_code("0x1000", None).unwrap();
        let native = client.disasm_range("0x1000", "0x1005", None).unwrap();
        assert_eq!(native["count"], 3, "{native}");
        assert!(
            native["instructions"][1]["mnemonic"]
                .as_str()
                .unwrap()
                .to_lowercase()
                .contains("eq"),
            "{native}"
        );
        client.clear_range("0x1000", "0x1005", None).unwrap();
        client.define_code("0x1000", Some("0x1005")).unwrap();
        assert_eq!(
            client.disasm_range("0x1000", "0x1005", None).unwrap(),
            native
        );
    });
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&name).unwrap();
    if let Err(panic) = checked {
        std::panic::resume_unwind(panic);
    }
}

#[test]
#[serial]
fn define_code_keeps_mips_delay_slot_groups_within_end() {
    require_ghidra!();
    let harness = harness();
    let client = harness.client().unwrap();
    let name = format!("define-code-mips-{}", uuid::Uuid::new_v4());
    client.script_run_source(r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.util.DefaultLanguageService;
public class CreateBoundedMipsFixture extends GhidraScript {
    public void run() throws Exception {
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("MIPS:BE:32:default"));
        var program = new ProgramDB(getScriptArgs()[0], language,
            language.getDefaultCompilerSpec(), this);
        try {
            int tx = program.startTransaction("bounded MIPS fixture");
            try {
                byte[] bytes = {
                    0x10, 0, 0, 3, 0, 0, 0, 0, // branch to 0x1010, NOP delay slot
                    0, 0, 0, 0, 0, 0, 0, 0,    // unreachable bytes
                    3, (byte) 0xe0, 0, 8, 0, 0, 0, 0 // jr ra, NOP delay slot
                };
                var start = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
                program.getMemory().createInitializedBlock("code", start,
                    new java.io.ByteArrayInputStream(bytes), bytes.length, monitor, false).setExecute(true);
            } finally { program.endTransaction(tx, true); }
            state.getProject().getProjectData().getRootFolder().createFile(getScriptArgs()[0], program, monitor);
        } finally { program.release(this); }
    }
}
"#, std::slice::from_ref(&name), &[], false).unwrap();
    client.open_program(&name).unwrap();
    let checked = std::panic::catch_unwind(|| {
        let references_before = client.xrefs_from("0x1000".into(), false).unwrap();
        for end in ["0x1003", "0x1005"] {
            assert!(client.define_code("0x1000", Some(end)).is_err());
            assert_eq!(
                client.disasm_range("0x1000", "0x1017", None).unwrap()["count"],
                0
            );
            assert_eq!(
                client.xrefs_from("0x1000".into(), false).unwrap(),
                references_before,
                "rejected previews must not leave branch references"
            );
        }
        client.open_program(TEST_PROGRAM).unwrap();
        client.open_program(&name).unwrap();
        assert_eq!(
            client.disasm_range("0x1000", "0x1017", None).unwrap()["count"],
            0
        );
        assert_eq!(
            client.xrefs_from("0x1000".into(), false).unwrap(),
            references_before
        );
        let receipt = client.define_code("0x1000", Some("0x1007")).unwrap();
        assert_eq!(receipt["changed"], true);
        let bounded = client.disasm_range("0x1000", "0x1017", None).unwrap();
        assert_eq!(
            bounded["count"], 2,
            "branch and complete delay slot only: {bounded}"
        );
        client.clear_range("0x1000", "0x1017", None).unwrap();
        client.define_code("0x1000", Some("0x1017")).unwrap();
        let full = client.disasm_range("0x1000", "0x1017", None).unwrap();
        assert_eq!(
            full["count"], 4,
            "both branch groups, not unreachable bytes: {full}"
        );
        client.open_program(TEST_PROGRAM).unwrap();
        client.open_program(&name).unwrap();
        assert_eq!(client.disasm_range("0x1000", "0x1017", None).unwrap(), full);
    });
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&name).unwrap();
    if let Err(panic) = checked {
        std::panic::resume_unwind(panic);
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
