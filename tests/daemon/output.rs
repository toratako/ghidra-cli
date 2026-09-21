use super::{start_daemon, TEST_PROGRAM};
use crate::common::{self, ensure_test_project, test_project};
use serial_test::serial;
use std::time::Duration;

#[test]
#[serial]
fn management_results_are_single_json_documents() {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    for flag in ["--json", "--pretty"] {
        for command in [
            ["bridge", "start"],
            ["bridge", "status"],
            ["bridge", "ping"],
            ["job", "list"],
        ] {
            let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
                .args([flag, "--quiet"])
                .args(command)
                .args(["--project", test_project()])
                .output()
                .unwrap();
            assert!(output.status.success(), "{command:?}: {output:?}");
            let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert!(value.is_object(), "{command:?}: {value}");
            assert!(output.stderr.is_empty(), "{command:?}: {output:?}");
            if command == ["bridge", "status"] {
                assert_eq!(value["state"], "running");
                assert!(value["port"].is_number());
                assert!(value["info"].is_object());
            }
        }
    }
    let function =
        crate::common::helpers::get_fixture_function(&harness.client().unwrap(), "add_numbers");
    let address = function.address.as_str();
    for flag in ["--json", "--pretty"] {
        let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
            .args([
                flag,
                "function",
                "create",
                address,
                "--project",
                test_project(),
            ])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        assert!(output.stdout.is_empty(), "{output:?}");
        let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
        assert!(error["detail"].is_object(), "{error}");
    }
    let project_path = ghidra_cli::config::Config::load()
        .unwrap()
        .get_project_dir()
        .unwrap()
        .join(test_project());
    let initial_pid = ghidra_cli::ghidra::bridge::read_pid_file(&project_path)
        .unwrap()
        .unwrap();
    for args in [
        vec!["program", "save"],
        vec!["bridge", "restart"],
        vec!["bridge", "stop"],
    ] {
        // restart leaves a JVM running; inherited Windows pipe handles would
        // make assert_cmd's output readers wait past its process timeout.
        let output = common::run_command_with_output(
            std::process::Command::new(assert_cmd::cargo::cargo_bin!("ghidra-cli"))
                .args(["--json", "--quiet"])
                .args(&args)
                .args(["--project", test_project(), "--program", TEST_PROGRAM]),
            Duration::from_secs(300),
        )
        .unwrap();
        assert!(output.status.success(), "{args:?}: {output:?}");
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        if args == ["program", "save"] {
            assert_eq!(value["saved"], true);
            assert_eq!(
                ghidra_cli::ghidra::bridge::read_pid_file(&project_path).unwrap(),
                Some(initial_pid),
                "program save restarted the bridge"
            );
        }
        assert!(output.stderr.is_empty(), "{output:?}");
    }
}

#[test]
#[serial]
fn test_batch_failure_exit_and_results() {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    let address =
        common::get_function_address(&harness, test_project(), TEST_PROGRAM, "add_numbers");
    let batch = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        batch.path(),
        format!("program info\nfunction create {address}\nprogram info\n"),
    )
    .unwrap();
    let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .args(["--json", "batch"])
        .arg(batch.path())
        .args(["--project", test_project()])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["detail"]["commands_executed"], 3);
    assert_eq!(error["detail"]["failed"], 1);
    assert!(error["detail"].get("results").is_none());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report[0]["commands_executed"], 3);
    assert_eq!(report[0]["failed"], 1);
    assert!(report[0]["results"][0]["result"]["function_count"].is_number());
    assert!(report[0]["results"][1]["detail"].is_object());
    assert!(report[0]["results"][2]["result"]["function_count"].is_number());
    std::fs::write(batch.path(), "program info\nprogram save\n").unwrap();
    let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .args(["--json", "batch"])
        .arg(batch.path())
        .args(["--project", test_project()])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result[0]["failed"], 0);
    assert_eq!(result[0]["results"][1]["result"]["saved"], true);
    assert!(harness.client().unwrap().ping().unwrap());
}
