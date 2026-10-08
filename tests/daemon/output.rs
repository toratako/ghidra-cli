use super::{start_daemon, TEST_PROGRAM};
use crate::common::{self, ensure_test_project, test_project};
use serial_test::serial;
use std::time::Duration;

#[test]
#[serial]
fn unicode_requests_responses_and_saved_edits_ignore_jvm_default_charset() {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    let address =
        common::helpers::get_fixture_function(&harness.client().unwrap(), "add_numbers").address;
    let prior = harness.client().unwrap().comment_get(&address).unwrap()["comments"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["type"] == "PLATE")
        .map(|row| row["text"].as_str().unwrap().to_owned());

    // _JAVA_OPTIONS applies after the launcher's UTF-8 default. Keep the suite's
    // own environment unchanged and let the harness own the restarted process.
    let output = common::run_command_with_output(
        std::process::Command::new(assert_cmd::cargo::cargo_bin!("ghidra-cli"))
            .args([
                "--json",
                "bridge",
                "restart",
                "--project",
                test_project(),
                "--program",
                TEST_PROGRAM,
            ])
            .env("_JAVA_OPTIONS", "-Dfile.encoding=US-ASCII"),
        Duration::from_secs(300),
    )
    .unwrap();
    assert!(output.status.success(), "{output:?}");
    let project_path = ghidra_cli::config::Config::load()
        .unwrap()
        .get_project_dir()
        .unwrap()
        .join(test_project());
    let port = ghidra_cli::ghidra::bridge::read_port_file(&project_path)
        .unwrap()
        .unwrap();
    let client = ghidra_cli::ipc::client::BridgeClient::new(port);
    let charset = client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
public class CheckBridgeCharset extends GhidraScript {
    public void run() {
        println(java.nio.charset.Charset.defaultCharset().name());
    }
}
"#,
            &[],
            &[],
            false,
        )
        .unwrap();
    assert!(charset["stdout"].as_str().unwrap().contains("US-ASCII"));

    let text = "日本語 🛠️ café";
    client.comment_set(&address, text, Some("PLATE")).unwrap();
    let comments = client.comment_get(&address).unwrap();
    assert!(
        comments["comments"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["type"] == "PLATE" && row["text"] == text),
        "Unicode was altered at the bridge socket boundary: {comments}"
    );
    drop(harness);

    let reopened = start_daemon();
    let client = reopened.client().unwrap();
    let comments = client.comment_get(&address).unwrap();
    assert!(
        comments["comments"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["type"] == "PLATE" && row["text"] == text),
        "Saved Unicode edit was altered: {comments}"
    );
    match prior {
        Some(text) => client.comment_set(&address, &text, Some("PLATE")).unwrap(),
        None => client
            .comment_delete(&address, Some("PLATE"), false)
            .unwrap(),
    };
}

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
            let value: serde_json::Value = crate::json_output::from_slice(&output.stdout).unwrap();
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
        let value: serde_json::Value = crate::json_output::from_slice(&output.stdout).unwrap();
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
    let report: serde_json::Value = crate::json_output::from_slice(&output.stdout).unwrap();
    assert_eq!(report["commands_executed"], 3);
    assert_eq!(report["failed"], 1);
    assert!(report["results"][0]["result"]["data"]["function_count"].is_number());
    assert!(report["results"][1]["detail"].is_object());
    assert!(report["results"][2]["result"]["data"]["function_count"].is_number());
    std::fs::write(batch.path(), "program info\nprogram save\n").unwrap();
    let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .args(["--json", "batch"])
        .arg(batch.path())
        .args(["--project", test_project()])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let result: serde_json::Value = crate::json_output::from_slice(&output.stdout).unwrap();
    assert_eq!(result["failed"], 0);
    assert_eq!(result["results"][1]["result"]["data"]["saved"], true);
    assert!(harness.client().unwrap().ping().unwrap());
}
