use super::{ghidra, harness, test_project, DaemonTestHarness, TEST_PROGRAM};
use crate::common::get_function_address;
use serial_test::serial;

#[test]
#[serial]
fn test_define_data() {
    require_ghidra!();
    let harness = harness();

    let addr = get_function_address(harness, test_project(), TEST_PROGRAM, "main");

    let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("listing")
        .arg("define-data")
        .arg(&addr)
        .arg("--type")
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
    let hex = addr.strip_prefix("0x").expect("prefixed hex address");
    let val = u64::from_str_radix(hex, 16).expect("hex address");
    format!("0x{:0width$x}", val + delta, width = hex.len())
}

/// Force-clear+redisassemble a small window at `addr` back to instructions,
/// via the same `listing undefine --disassemble-at` path a caller would use to recover from
/// this (ghidra-bug.md's own suggested workaround) -- used both to armor this
/// test against `main` having been left mid-disassembled by another test
/// sharing the fixture, and to restore it afterward.
fn restore_disassembly(harness: &DaemonTestHarness, addr: &str) {
    ghidra(harness)
        .args(["listing", "undefine", addr, "--end"])
        .arg(hex_addr_plus(addr, 15))
        .arg("--disassemble-at")
        .arg(addr)
        .arg("--json")
        .with_project(test_project(), TEST_PROGRAM)
        .run()
        .assert_success();
}

#[test]
#[serial]
// This suite owns its project, so clearing main cannot affect another suite.
fn test_define_data_force_on_function_entry_warns() {
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
        .arg("listing")
        .arg("define-data")
        .arg(&addr)
        .arg("--type")
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
    let json: serde_json::Value = result.data();
    let entry = &json;
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
fn define_data_reports_the_overlapping_unit_when_the_start_is_undefined() {
    require_ghidra!();
    let harness = harness();
    let client = harness.client().unwrap();
    let name = format!("define-data-conflicts-{}", uuid::Uuid::new_v4());
    client
        .script_run_source(
            include_str!("../fixtures/types/CreateDataConflictFixture.java"),
            std::slice::from_ref(&name),
            &[],
            false,
        )
        .unwrap();
    client.open_program(&name).unwrap();
    let checked = std::panic::catch_unwind(|| {
        let before = client.send_command("data_list", None).unwrap();
        for (target, kind, start, end, type_name) in [
            ("0x1000", "data", "0x00001002", "0x00001003", "uint32_t"),
            ("0x1003", "data", "0x00001002", "0x00001003", "uint16_t"),
            (
                "0x1010",
                "instruction",
                "0x00001012",
                "0x00001013",
                "uint32_t",
            ),
        ] {
            let result = ghidra(harness)
                .args([
                    "--json",
                    "listing",
                    "define-data",
                    target,
                    "--type",
                    type_name,
                ])
                .with_project(test_project(), &name)
                .run();
            result.assert_failure();
            let error: serde_json::Value = serde_json::from_str(&result.stderr).unwrap();
            let detail = &error["detail"];
            assert_eq!(detail["conflicting_start"], start, "{error}");
            assert_eq!(detail["conflicting_end"], end, "{error}");
            assert_eq!(detail["conflicting_length"], 2, "{error}");
            assert_eq!(detail["conflicting_kind"], kind, "{error}");
            assert_eq!(detail["rolled_back"], true);
            if kind == "data" {
                assert_eq!(detail["conflicting_defined"], true);
                assert_eq!(detail["conflicting_type"], "word");
            }
        }
        assert_eq!(client.send_command("data_list", None).unwrap(), before);
        assert_eq!(
            client.disasm("0x1012", Some(1)).unwrap()["instructions"][0]["bytes"],
            "6690"
        );
    });
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&name).unwrap();
    if let Err(panic) = checked {
        std::panic::resume_unwind(panic);
    }
}

const DEFINE_DATA_FAILURE_PROBE: &str =
    include_str!("../fixtures/types/DefineDataFailureProbe.java");

fn check_define_data_native_failure(mode: &str) {
    require_ghidra!();
    let client = harness().client().unwrap();
    client
        .script_run_source(
            DEFINE_DATA_FAILURE_PROBE,
            &[
                format!("define-data-failure-{}", uuid::Uuid::new_v4()),
                mode.to_owned(),
            ],
            &[],
            false,
        )
        .unwrap();
}

#[test]
#[serial]
fn define_data_rolls_back_native_null_after_forced_clearing() {
    check_define_data_native_failure("null");
}

#[test]
#[serial]
fn define_data_cancels_during_native_forced_clearing_and_restores_metadata() {
    check_define_data_native_failure("cancel");
}
