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
        .env_remove("GHIDRA_JAR")
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
        .env_remove("GHIDRA_JAR")
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
fn batch_project_path_aliases_share_program_selection() {
    let bridge = RecordedBridge::new();
    let old_port_file = super::bridge::port_file_path(&bridge.project).unwrap();
    let old_pid_file = super::bridge::pid_file_path(&bridge.project).unwrap();
    std::fs::create_dir_all(bridge.project.with_added_extension("rep")).unwrap();
    std::fs::rename(
        old_port_file,
        super::bridge::port_file_path(&bridge.project).unwrap(),
    )
    .unwrap();
    std::fs::rename(
        old_pid_file,
        super::bridge::pid_file_path(&bridge.project).unwrap(),
    )
    .unwrap();
    let alias_directory = bridge.project.parent().unwrap().join("alias");
    std::fs::create_dir(&alias_directory).unwrap();
    let alias = alias_directory.join("..").join("project");
    assert_eq!(
        super::bridge::port_file_path(&alias).unwrap(),
        super::bridge::port_file_path(&bridge.project).unwrap()
    );
    std::fs::write(
        bridge.root.path().join("batch.txt"),
        format!(
            "program info --program A\nprogram info --project {} --program B\ncomment set 0x1000 --text inherited\n",
            batch_path_argument(&alias),
        ),
    )
    .unwrap();
    let report = bridge.run(&["batch", "batch.txt"]);
    let observed: Vec<_> = report["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["result"]["data"]["observed_program"].as_str().unwrap())
        .collect();
    assert_eq!(observed, ["A", "B", "B"]);
    let requests = bridge.requests.lock().unwrap();
    let targets: Vec<_> = requests
        .iter()
        .filter(|r| r["command"] != "bridge_info")
        .map(|r| r["program"].as_str().unwrap())
        .collect();
    assert_eq!(targets, ["A", "B", "B"]);
}

#[test]
fn batch_queries_inherit_targets_and_keep_program_selection() {
    let first = RecordedBridge::with_info(serde_json::json!({
        "protocol_version": 4, "auto_save": true, "atomic_edits": true,
        "named_import": true, "explicit_addresses": true,
        "test_interleave_program": "another-client-program",
    }));
    let second = RecordedBridge::new();
    std::fs::write(first.root.path().join("batch.txt"), format!(
        "memory block list\ncomment set 0x1000 --text marker --program B\nmemory block list\nmemory block list --program C\nmemory block list --project {} --program D\nmemory block list\n",
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
    for (bridge, targets) in [
        (&first, vec!["A", "B", "B", "C", "C"]),
        (&second, vec!["D"]),
    ] {
        let requests = bridge.requests.lock().unwrap();
        let selections: Vec<_> = requests
            .iter()
            .filter(|r| r["command"] == "open_program")
            .map(|r| r["args"]["program"].as_str().unwrap())
            .collect();
        assert!(selections.is_empty(), "{selections:?}");
        let actual: Vec<_> = requests
            .iter()
            .filter(|r| {
                matches!(
                    r["command"].as_str(),
                    Some("memory_block_list" | "comment_set")
                )
            })
            .map(|r| r["program"].as_str().unwrap())
            .collect();
        assert_eq!(actual, targets);
    }
}

#[test]
fn batch_updates_target_from_failed_requests_and_clears_it_after_close() {
    let bridge = RecordedBridge::new();
    std::fs::write(
        bridge.root.path().join("batch.txt"),
        concat!(
            "comment set 0x1000 --text first\n",
            "comment set 0x1001 --text missing --program missing-program\n",
            "comment set 0x1002 --text after-missing\n",
            "comment set 0x1003 --text test-rollback --program B\n",
            "comment set 0x1004 --text after-rollback\n",
            "program close\n",
            "program list\n",
        ),
    )
    .unwrap();
    let output = bridge
        .command()
        .args(["batch", "batch.txt", "--program", "A"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let report: Value = crate::json_output::from_slice(&output.stdout).unwrap();
    assert_eq!(report["commands_executed"], 7);
    assert_eq!(report["failed"], 2);
    assert_eq!(
        report["results"][2]["result"]["data"]["observed_program"],
        "A"
    );
    assert_eq!(
        report["results"][4]["result"]["data"]["observed_program"],
        "B"
    );
    let requests = bridge.requests.lock().unwrap();
    let operations: Vec<_> = requests
        .iter()
        .filter(|r| r["command"] != "bridge_info")
        .collect();
    assert_eq!(operations.len(), 7);
    let targets: Vec<_> = operations.iter().map(|r| r["program"].as_str()).collect();
    assert_eq!(
        targets,
        [
            Some("A"),
            Some("missing-program"),
            Some("A"),
            Some("B"),
            Some("B"),
            Some("B"),
            None
        ]
    );
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
        assert_eq!(
            recovery["action"],
            if code == 75 {
                "retrieve_result"
            } else {
                "inspect_state"
            }
        );
        assert_eq!(recovery["file"], "nested.txt");
        assert_eq!(recovery["line"], 1);
        let argv: Vec<String> = serde_json::from_value(recovery["argv"].clone()).unwrap();
        assert_eq!(
            &argv[1..3],
            if code == 75 {
                ["job", "result"]
            } else {
                ["program", "save"]
            }
        );
        if code == 75 {
            let request = bridge
                .requests
                .lock()
                .unwrap()
                .iter()
                .find(|request| request["args"]["text"] == "test-timeout")
                .unwrap()
                .clone();
            assert_eq!(argv[3], request["job_id"].as_str().unwrap());
            assert_eq!(
                report["results"][1]["detail"]["results"][0]["detail"]["job_id"],
                request["job_id"]
            );
        }
        assert!(!argv.iter().any(|arg| arg == "--from-line"));
        assert!(!bridge
            .requests
            .lock()
            .unwrap()
            .iter()
            .any(|r| r["args"]["text"] == "must-not-run"));
    }
}
