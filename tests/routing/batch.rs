use super::{batch_path_argument, RecordedBridge};
use serde_json::{json, Value};

fn failed_report(bridge: &RecordedBridge, args: &[&str]) -> (Value, Value) {
    let output = bridge.command().args(args).output().unwrap();
    assert!(!output.status.success(), "{output:?}");
    let report: Value = crate::json_output::from_slice(&output.stdout).unwrap();
    let diagnostic: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(report["recovery"], diagnostic["detail"]["recovery"]);
    (report.clone(), diagnostic)
}

#[test]
fn batch_from_line_skips_prefix_validation_and_keeps_physical_lines() {
    let bridge = RecordedBridge::new();
    std::fs::write(
        bridge.root.path().join("batch.txt"),
        "invalid-prefix\nbatch missing.txt\n# resume here\n\nprogram info\n",
    )
    .unwrap();
    let report = bridge.run(&["batch", "batch.txt", "--from-line", "0x3"]);
    assert_eq!(report["from_line"], 3);
    assert_eq!(report["commands_parsed"], 1);
    assert_eq!(report["commands_executed"], 1);
    assert_eq!(report["not_executed"], 0);
    assert_eq!(report["results"][0]["line"], 5);
    assert_eq!(
        bridge
            .requests
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r["command"] == "program_info")
            .count(),
        1
    );
}

#[test]
fn batch_selected_suffix_is_validated_before_any_bridge_work() {
    let bridge = RecordedBridge::new();
    std::fs::write(
        bridge.root.path().join("batch.txt"),
        "ignored\nprogram info\ninvalid-command\n",
    )
    .unwrap();
    for start in ["2", "4"] {
        let (report, _) = failed_report(&bridge, &["batch", "batch.txt", "--from-line", start]);
        assert_eq!(report["commands_executed"], 0);
        assert_eq!(report["recovery"]["action"], "fix_input");
        assert!(bridge.requests.lock().unwrap().is_empty());
    }
    let output = bridge
        .command()
        .args(["batch", "batch.txt", "--from-line", "0"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(bridge.requests.lock().unwrap().is_empty());
}

#[test]
fn batch_required_program_targets_are_validated_before_any_bridge_work() {
    let bridge = RecordedBridge::new();
    std::fs::write(
        bridge.root.path().join("batch.txt"),
        "comment set 0x1000 --text before\nprogram open\nbatch nested.txt\n",
    )
    .unwrap();
    std::fs::write(
        bridge.root.path().join("nested.txt"),
        "program delete\nprogram open ''\n",
    )
    .unwrap();
    // The outer selection does not supply a missing open/delete operand.
    for args in [
        vec!["batch", "batch.txt"],
        vec!["--program", "A", "batch", "batch.txt", "--on-error", "stop"],
    ] {
        let (report, _) = failed_report(&bridge, &args);
        assert_eq!(report["validation_failed"], true);
        assert_eq!(report["commands_executed"], 0);
        let errors = report["validation_errors"].as_array().unwrap();
        assert_eq!(errors.len(), 3);
        assert_eq!(errors[0]["file"], "batch.txt");
        assert_eq!(errors[0]["line"], 2);
        assert_eq!(errors[1]["file"], "nested.txt");
        assert_eq!(errors[1]["line"], 1);
        assert_eq!(errors[2]["file"], "nested.txt");
        assert_eq!(errors[2]["line"], 2);
        for error in errors {
            assert!(!error["error"].as_str().unwrap().is_empty());
        }
        assert!(bridge.requests.lock().unwrap().is_empty());
    }
}

#[test]
fn batch_program_operands_override_context_options() {
    let bridge = RecordedBridge::new();
    std::fs::write(
        bridge.root.path().join("batch.txt"),
        "--program ignored program open A\nprogram info\nbatch nested.txt\n",
    )
    .unwrap();
    std::fs::write(
        bridge.root.path().join("nested.txt"),
        "program delete B --program ignored\n",
    )
    .unwrap();
    let report = bridge.run(&["batch", "batch.txt"]);
    assert_eq!(report["commands_executed"], 3);
    assert_eq!(
        report["results"][1]["result"]["data"]["observed_program"],
        "A"
    );
    let requests = bridge.requests.lock().unwrap();
    assert!(requests
        .iter()
        .any(|request| request["command"] == "open_program" && request["args"]["program"] == "A"));
    assert!(
        requests
            .iter()
            .any(|request| request["command"] == "program_delete"
                && request["args"]["program"] == "B")
    );
}

#[test]
fn nested_batch_from_line_is_local_to_each_file() {
    let bridge = RecordedBridge::new();
    std::fs::write(
        bridge.root.path().join("batch.txt"),
        "ignored\nbatch nested.txt --from-line 3\nprogram info\n",
    )
    .unwrap();
    std::fs::write(
        bridge.root.path().join("nested.txt"),
        "ignored\ninvalid-prefix\n# child\nprogram info\n",
    )
    .unwrap();
    let report = bridge.run(&["batch", "batch.txt", "--from-line", "2"]);
    let child = &report["results"][0]["result"]["data"];
    assert_eq!(child["file"], "nested.txt");
    assert_eq!(child["from_line"], 3);
    assert_eq!(child["results"][0]["line"], 4);
    assert_eq!(report["results"][1]["line"], 3);
}

#[test]
fn batch_recovery_restores_selected_program_and_does_not_replay_prefix() {
    let bridge = RecordedBridge::new();
    let file = bridge.root.path().join("batch.txt");
    std::fs::write(&file, "comment set 0x1000 --text before --program B\n# failed edit\ncomment set 0x1001 --text test-rollback\ncomment set 0x1002 --text after\n").unwrap();
    let (report, diagnostic) = failed_report(
        &bridge,
        &["batch", "batch.txt", "--program", "A", "--on-error", "stop"],
    );
    let recovery = &report["recovery"];
    assert_eq!(recovery["action"], "resume_from_line");
    assert_eq!(recovery["line"], 3);
    assert_eq!(recovery["project"], json!(bridge.project));
    let argv: Vec<String> = serde_json::from_value(recovery["argv"].clone()).unwrap();
    assert!(argv.windows(2).any(|args| args == ["--program", "B"]));
    assert!(diagnostic["message"]
        .as_str()
        .unwrap()
        .contains("--from-line 3"));
    std::fs::write(&file, "comment set 0x1000 --text before --program B\n# failed edit\ncomment set 0x1001 --text fixed\ncomment set 0x1002 --text after\n").unwrap();
    // Another command changes selection between failure and resumption.
    bridge.run(&["program", "info", "--program", "A"]);
    bridge.requests.lock().unwrap().clear();
    let output = bridge.command().args(&argv[1..]).output().unwrap();
    assert!(output.status.success(), "{output:?}");
    let resumed: Value = crate::json_output::from_slice(&output.stdout).unwrap();
    assert_eq!(resumed["results"][0]["line"], 3);
    assert_eq!(
        resumed["results"][0]["result"]["data"]["observed_program"],
        "B"
    );
    let requests = bridge.requests.lock().unwrap();
    let edits: Vec<_> = requests
        .iter()
        .filter(|r| r["command"] == "comment_set")
        .map(|r| r["args"]["text"].as_str().unwrap())
        .collect();
    assert_eq!(edits, ["fixed", "after"]);
}

#[test]
fn batch_recovery_does_not_replay_completed_later_or_nested_commands() {
    let bridge = RecordedBridge::new();
    std::fs::write(
        bridge.root.path().join("batch.txt"),
        "comment set 0x1000 --text test-rollback\ncomment set 0x1001 --text after\n",
    )
    .unwrap();
    let (report, _) = failed_report(&bridge, &["batch", "batch.txt"]);
    assert_eq!(report["recovery"]["reason"], "continued_execution");
    assert!(report["recovery"].get("argv").is_none());
    std::fs::write(
        bridge.root.path().join("nested.txt"),
        "comment set 0x1000 --text before\ncomment set 0x1001 --text test-rollback\n",
    )
    .unwrap();
    std::fs::write(
        bridge.root.path().join("batch.txt"),
        "# outer\nbatch nested.txt\ncomment set 0x1002 --text after\n",
    )
    .unwrap();
    let (report, diagnostic) =
        failed_report(&bridge, &["batch", "batch.txt", "--on-error", "stop"]);
    assert_eq!(report["recovery"]["reason"], "nested_batch");
    assert_eq!(report["recovery"]["file"], "nested.txt");
    assert_eq!(report["recovery"]["line"], 2);
    assert_eq!(
        report["recovery"]["parents"],
        json!([{"file": "batch.txt", "line": 2}])
    );
    assert!(report["recovery"].get("argv").is_none());
    assert!(!diagnostic["message"]
        .as_str()
        .unwrap()
        .contains("--from-line"));
}

#[test]
fn batch_resume_hint_requires_reproducible_project_selections() {
    let outer = RecordedBridge::new();
    let other = RecordedBridge::new();
    std::fs::write(
        outer.root.path().join("batch.txt"),
        format!(
            "comment set 0x1000 --text test-rollback\nprogram info --project {}\n",
            batch_path_argument(&other.project)
        ),
    )
    .unwrap();
    let (report, _) = failed_report(&outer, &["batch", "batch.txt", "--on-error", "stop"]);
    assert_eq!(report["recovery"]["reason"], "target_context");
    assert!(report["recovery"].get("argv").is_none());
    assert!(other.requests.lock().unwrap().is_empty());
}

#[test]
fn lost_batch_response_stops_nested_and_outer_execution_and_names_the_project() {
    let outer = RecordedBridge::new();
    let other = RecordedBridge::new();
    std::fs::write(
        outer.root.path().join("batch.txt"),
        "batch nested.txt\ncomment set 0x1001 --text must-not-run\n",
    )
    .unwrap();
    std::fs::write(
        outer.root.path().join("nested.txt"),
        format!(
            "comment set 0x1000 --text test-lost-response --project {}\ncomment set 0x1002 --text must-not-run\n",
            batch_path_argument(&other.project)
        ),
    )
    .unwrap();
    let (report, diagnostic) = failed_report(&outer, &["batch", "batch.txt"]);
    assert_eq!(diagnostic["exit_code"], 1);
    assert_eq!(report["outcome_unknown"], true);
    assert_eq!(report["recovery"]["action"], "retrieve_result");
    assert_eq!(report["recovery"]["reason"], "outcome_unknown");
    assert_eq!(report["recovery"]["project"], json!(other.project));
    let argv: Vec<String> = serde_json::from_value(report["recovery"]["argv"].clone()).unwrap();
    assert_eq!(&argv[1..3], ["job", "result"]);
    let request = other
        .requests
        .lock()
        .unwrap()
        .iter()
        .find(|request| request["args"]["text"] == "test-lost-response")
        .unwrap()
        .clone();
    assert_eq!(argv[3], request["job_id"].as_str().unwrap());
    for bridge in [&outer, &other] {
        assert!(!bridge
            .requests
            .lock()
            .unwrap()
            .iter()
            .any(|r| r["args"]["text"] == "must-not-run"));
    }
}

#[test]
fn batch_save_recovery_uses_the_failed_saves_project() {
    let outer = RecordedBridge::new();
    let other = RecordedBridge::with_info(json!({"test_save_failure": true}));
    std::fs::write(
        outer.root.path().join("batch.txt"),
        format!(
            "program save --project {}\ncomment set 0x1000 --text must-not-run\n",
            batch_path_argument(&other.project),
        ),
    )
    .unwrap();
    let (report, _) = failed_report(&outer, &["batch", "batch.txt"]);
    assert_eq!(report["recovery"]["reason"], "save_failed");
    assert_eq!(report["recovery"]["project"], json!(other.project));
    let argv: Vec<String> = serde_json::from_value(report["recovery"]["argv"].clone()).unwrap();
    assert_eq!(argv.last().unwrap(), other.project.to_str().unwrap());
    assert!(!outer
        .requests
        .lock()
        .unwrap()
        .iter()
        .any(|r| r["command"] == "comment_set"));
}

#[test]
fn batch_resume_hint_is_visible_in_human_diagnostics() {
    let bridge = RecordedBridge::new();
    std::fs::write(
        bridge.root.path().join("config.yaml"),
        "default_output_format: full\n",
    )
    .unwrap();
    std::fs::write(
        bridge.root.path().join("batch.txt"),
        "comment set 0x1000 --text test-rollback\n",
    )
    .unwrap();
    let output = bridge
        .command()
        .args(["batch", "batch.txt"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let diagnostic = String::from_utf8(output.stderr).unwrap();
    assert!(diagnostic.contains("batch.txt:1"), "{diagnostic}");
    assert!(diagnostic.contains("rolled back"), "{diagnostic}");
    assert!(diagnostic.contains("--from-line 1"), "{diagnostic}");
    assert!(diagnostic.contains("--program A"), "{diagnostic}");
}
