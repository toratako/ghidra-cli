use super::{batch_path_argument, RecordedBridge};
use serde_json::Value;

#[test]
fn batch_on_error_controls_runtime_failures_after_preflight() {
    for policy in [None, Some("continue"), Some("stop")] {
        let bridge = RecordedBridge::new();
        std::fs::write(
            bridge.root.path().join("batch.txt"),
            "comment set 0x1000 --text before\nsymbol rename missing renamed\ncomment set 0x1001 --text after\n",
        )
        .unwrap();
        let mut command = bridge.command();
        command.args(["batch", "batch.txt"]);
        if let Some(policy) = policy {
            command.args(["--on-error", policy]);
        }
        let output = command.output().unwrap();
        assert_eq!(output.status.code(), Some(1), "{policy:?}: {output:?}");
        assert!(!output.stdout.is_empty());
        let error: Value = serde_json::from_slice(&output.stderr).unwrap();
        assert!(error["detail"].get("results").is_none());
        let report: Value = crate::json_output::from_slice(&output.stdout).unwrap();
        let detail = &report;
        let stopped = policy == Some("stop");
        assert_eq!(detail["commands_parsed"], 3);
        assert_eq!(detail["commands_executed"], if stopped { 2 } else { 3 });
        assert_eq!(detail["failed"], 1);
        assert_eq!(detail["not_executed"], usize::from(stopped));
        assert!(detail["results"][0]["result"]["data"].is_object());
        assert_eq!(detail["results"][1]["line"], 2);
        assert_eq!(detail["results"][1]["exit_code"], 1);
        let requests = bridge.requests.lock().unwrap();
        let comments: Vec<_> = requests
            .iter()
            .filter(|r| r["command"] == "comment_set")
            .map(|r| r["args"]["text"].as_str().unwrap())
            .collect();
        assert_eq!(
            comments,
            if stopped {
                vec!["before"]
            } else {
                vec!["before", "after"]
            }
        );
    }
}

#[test]
fn nested_batch_inherits_on_error_unless_overridden() {
    for (parent_policy, child_policy, expected_comments, child_stopped) in [
        ("stop", None, vec!["before"], true),
        (
            "continue",
            None,
            vec!["before", "inner-after", "outer-after"],
            false,
        ),
        (
            "stop",
            Some("continue"),
            vec!["before", "inner-after"],
            false,
        ),
        (
            "continue",
            Some("stop"),
            vec!["before", "outer-after"],
            true,
        ),
    ] {
        let bridge = RecordedBridge::new();
        let child_option = child_policy
            .map(|policy| format!(" --on-error {policy}"))
            .unwrap_or_default();
        std::fs::write(
            bridge.root.path().join("batch.txt"),
            format!(
                "comment set 0x1000 --text before\nbatch nested.txt{child_option}\ncomment set 0x1003 --text outer-after\n"
            ),
        )
        .unwrap();
        std::fs::write(
            bridge.root.path().join("nested.txt"),
            "symbol rename missing renamed\ncomment set 0x1002 --text inner-after\n",
        )
        .unwrap();
        let output = bridge
            .command()
            .args(["batch", "batch.txt", "--on-error", parent_policy])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        assert!(!output.stdout.is_empty());
        let error: Value = serde_json::from_slice(&output.stderr).unwrap();
        assert!(error["detail"].get("results").is_none());
        let report: Value = crate::json_output::from_slice(&output.stdout).unwrap();
        let detail = &report;
        assert_eq!(detail["failed"], 1);
        assert_eq!(detail["not_executed"], usize::from(parent_policy == "stop"));
        let nested = &detail["results"][1]["detail"];
        assert_eq!(nested["failed"], 1);
        assert_eq!(nested["not_executed"], usize::from(child_stopped));
        let requests = bridge.requests.lock().unwrap();
        let comments: Vec<_> = requests
            .iter()
            .filter(|r| r["command"] == "comment_set")
            .map(|r| r["args"]["text"].as_str().unwrap())
            .collect();
        assert_eq!(comments, expected_comments);
    }
}

#[test]
fn batch_routes_each_target_and_keeps_explicit_program_switches() {
    let first = RecordedBridge::new();
    let second = RecordedBridge::new();
    std::fs::write(
        first.root.path().join("nested.txt"),
        "comment set 0x1000 --text nested --program C\n",
    )
    .unwrap();
    std::fs::write(first.root.path().join("batch.txt"), format!(
        "comment set 0x1000 --text marker --program B\nprogram info\nbatch nested.txt\nprogram info --project {} --program D\n",
        batch_path_argument(&second.project),
    )).unwrap();
    let result = first.run(&["batch", "batch.txt", "--program", "A"]);
    let rows = &result["results"];
    assert_eq!(rows[0]["result"]["data"]["observed_program"], "B");
    assert_eq!(rows[1]["result"]["data"]["observed_program"], "B");
    assert_eq!(
        rows[2]["result"]["data"]["results"][0]["result"]["data"]["observed_program"],
        "C"
    );
    assert_eq!(rows[3]["result"]["data"]["observed_program"], "D");
    assert_eq!(
        second.requests.lock().unwrap().last().unwrap()["command"],
        "program_info"
    );
}

#[test]
fn batch_inherits_a_relative_project_directory_without_joining_it_twice() {
    let bridge = RecordedBridge::new();
    std::fs::write(bridge.root.path().join("batch.txt"), "program info\n").unwrap();
    let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .current_dir(bridge.root.path())
        .env("GHIDRA_CLI_CONFIG", bridge.root.path().join("config.yaml"))
        .env(
            "GHIDRA_INSTALL_DIR",
            bridge.root.path().join("unused-install"),
        )
        .env(
            "GHIDRA_PROJECT_DIR",
            bridge.root.path().join("wrong-projects"),
        )
        .args([
            "--projects-dir",
            "projects",
            "--project",
            "project",
            "batch",
            "batch.txt",
        ])
        .timeout(std::time::Duration::from_secs(15))
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let result: Value = crate::json_output::from_slice(&output.stdout).unwrap();
    assert_eq!(
        result["results"][0]["result"]["data"]["observed_program"],
        "A"
    );
}

#[test]
fn batch_save_of_a_stopped_project_does_not_start_it() {
    let bridge = RecordedBridge::new();
    let stopped = bridge.root.path().join("stopped");
    std::fs::write(
        bridge.root.path().join("batch.txt"),
        format!("program save --project {}\n", batch_path_argument(&stopped)),
    )
    .unwrap();
    let result = bridge.run(&["batch", "batch.txt"]);
    assert_eq!(result["results"][0]["result"]["data"]["state"], "stopped");
    assert_eq!(result["results"][0]["result"]["data"]["saved"], false);
}

#[test]
fn project_directory_overrides_are_local_to_each_batch_line() {
    let first = RecordedBridge::new();
    let second = RecordedBridge::new();
    std::fs::write(first.root.path().join("batch.txt"), format!(
        "program info --program first\nprogram info --project project --projects-dir {} --program second\nprogram info --project project\n",
        batch_path_argument(second.project.parent().unwrap()),
    )).unwrap();
    let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .current_dir(first.root.path())
        .env("GHIDRA_CLI_CONFIG", first.root.path().join("config.yaml"))
        .env(
            "GHIDRA_INSTALL_DIR",
            first.root.path().join("unused-install"),
        )
        .env(
            "GHIDRA_PROJECT_DIR",
            first.root.path().join("wrong-projects"),
        )
        .arg("--projects-dir")
        .arg(first.project.parent().unwrap())
        .args(["--project", "project", "batch", "batch.txt"])
        .timeout(std::time::Duration::from_secs(15))
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let report: Value = crate::json_output::from_slice(&output.stdout).unwrap();
    let observed: Vec<_> = report["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["result"]["data"]["observed_program"].as_str().unwrap())
        .collect();
    assert_eq!(observed, ["first", "second", "first"]);
}

#[test]
fn batch_queries_inherit_targets_and_keep_program_selection() {
    let first = RecordedBridge::new();
    let second = RecordedBridge::new();
    std::fs::write(first.root.path().join("batch.txt"), format!(
        "memory map\ncomment set 0x1000 --text marker --program B\nmemory map\nmemory map --program C\nmemory map --project {} --program D\nmemory map\n",
        batch_path_argument(&second.project),
    )).unwrap();
    let output = first
        .command()
        .args(["batch", "batch.txt", "--program", "A"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let result: Value = crate::json_output::from_slice(&output.stdout).unwrap();
    for (index, program) in [(0, "A"), (1, "B"), (2, "B"), (3, "C"), (4, "D"), (5, "C")] {
        let data = &result["results"][index]["result"]["data"];
        let observed = if index == 1 { data } else { &data[0] };
        assert_eq!(observed["observed_program"], program);
    }
    for (bridge, expected) in [(&first, vec!["A", "B", "C"]), (&second, vec!["D"])] {
        let requests = bridge.requests.lock().unwrap();
        let opened: Vec<_> = requests
            .iter()
            .filter(|r| r["command"] == "open_program")
            .map(|r| r["args"]["program"].as_str().unwrap())
            .collect();
        assert_eq!(opened, expected);
    }
}

#[test]
fn batch_rejects_invalid_arguments_before_selecting_any_program() {
    let bridge = RecordedBridge::new();
    std::fs::write(
        bridge.root.path().join("batch.txt"),
        "function delete --program must-not-open\ncomment set 0x1000 --text after\n",
    )
    .unwrap();
    let output = bridge
        .command()
        .args(["batch", "batch.txt", "--on-error", "continue"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let report: Value = crate::json_output::from_slice(&output.stdout).unwrap();
    assert_eq!(report["commands_executed"], 0);
    assert_eq!(report["failed"], 1);
    assert_eq!(report["not_executed"], 2);
    assert!(report["validation_errors"][0]["error"].is_string());
    assert!(bridge.requests.lock().unwrap().is_empty());
}

#[test]
fn batch_reports_results_on_stdout_and_stops_on_save_failure_or_timeout() {
    for (failure, code) in [("test-save-failure", 1), ("test-timeout", 75)] {
        let bridge = RecordedBridge::new();
        std::fs::write(
            bridge.root.path().join("nested.txt"),
            format!(
                "comment set 0x1000 --text {failure}\ncomment set 0x1000 --text must-not-run\n"
            ),
        )
        .unwrap();
        std::fs::write(
            bridge.root.path().join("batch.txt"),
            "program info\nbatch nested.txt\ncomment set 0x1000 --text must-not-run\n",
        )
        .unwrap();
        let output = bridge
            .command()
            .env("GHIDRA_CLI_READ_TIMEOUT", "1")
            .args(["batch", "batch.txt", "--on-error", "continue"])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(code), "{output:?}");
        let report: Value = crate::json_output::from_slice(&output.stdout).unwrap();
        assert_eq!(report["commands_executed"], 2);
        assert_eq!(report["not_executed"], 1);
        assert_eq!(report["results"][1]["exit_code"], code);
        assert_eq!(report["results"][1]["detail"]["not_executed"], 1);
        let diagnostic: Value = serde_json::from_slice(&output.stderr).unwrap();
        assert!(diagnostic["detail"].get("results").is_none());
        assert_eq!(diagnostic["exit_code"], code);
        let recovery = &report["recovery"];
        assert_eq!(recovery["action"], "inspect_state");
        assert_eq!(recovery["file"], "nested.txt");
        assert_eq!(recovery["line"], 1);
        let argv: Vec<String> = serde_json::from_value(recovery["argv"].clone()).unwrap();
        assert_eq!(
            &argv[1..3],
            if code == 75 {
                ["job", "list"]
            } else {
                ["program", "save"]
            }
        );
        assert!(!argv.iter().any(|arg| arg == "--from-line"));
        assert!(!bridge
            .requests
            .lock()
            .unwrap()
            .iter()
            .any(|r| r["args"]["text"] == "must-not-run"));
    }
}
