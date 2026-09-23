use super::{RecordedBridge, ACTIVE_JOB_ID, JOB_ID};
use serde_json::{json, Value};

#[test]
fn only_unknown_outcomes_show_job_identity_and_targeted_recovery() {
    for flags in [vec!["--json"], vec![]] {
        for text in ["reviewed", "test-rollback", "test-lost-response"] {
            let bridge = RecordedBridge::new();
            std::fs::write(
                bridge.root.path().join("config.yaml"),
                "default_output_format: full\n",
            )
            .unwrap();
            let output = bridge
                .command()
                .args(["comment", "set", "0x1000", "--text", text])
                .args(&flags)
                .output()
                .unwrap();
            let requests = bridge.requests.lock().unwrap();
            let edits: Vec<_> = requests
                .iter()
                .filter(|request| request["command"] == "comment_set")
                .collect();
            assert_eq!(edits.len(), 1, "{output:?}");
            assert!(!requests
                .iter()
                .any(|request| request["command"] == "job_result"));
            let id = edits[0]["job_id"].as_str().unwrap();
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            if text == "reviewed" {
                assert!(output.status.success(), "{output:?}");
                assert!(stderr.is_empty());
                assert!(!stdout.contains(id));
            } else {
                assert_eq!(output.status.code(), Some(1), "{output:?}");
                assert!(stdout.is_empty());
                if text == "test-rollback" {
                    assert!(!stderr.contains(id));
                    assert!(!stderr.contains("job result"));
                } else if flags == ["--json"] {
                    let diagnostic: Value = serde_json::from_slice(&output.stderr).unwrap();
                    assert_eq!(diagnostic["detail"]["job_id"], id);
                    assert_eq!(diagnostic["detail"]["command"], "comment_set");
                    assert_eq!(
                        diagnostic["detail"]["recovery"]["argv"],
                        json!([
                            "ghidra-cli",
                            "job",
                            "result",
                            id,
                            "--project",
                            bridge.project
                        ])
                    );
                } else {
                    assert!(stderr.contains(&format!("job result {id}")), "{stderr}");
                    assert!(stderr.contains("--project"), "{stderr}");
                }
            }
        }
    }
}

#[test]
fn scoped_mutation_recovers_the_edit_job_after_a_lost_response() {
    let bridge = RecordedBridge::new();
    let output = bridge
        .command()
        .args([
            "--json",
            "comment",
            "set",
            "0x1000",
            "--text",
            "test-lost-response",
            "--program",
            "B",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let error: Value = serde_json::from_slice(&output.stderr).unwrap();
    let requests = bridge.requests.lock().unwrap();
    let operations: Vec<_> = requests
        .iter()
        .filter(|request| request["command"] != "bridge_info")
        .collect();
    assert_eq!(operations.len(), 1, "{operations:?}");
    let edit = operations[0];
    assert_eq!(edit["command"], "comment_set");
    assert_eq!(edit["program"], "B");
    assert_eq!(error["detail"]["job_id"], edit["job_id"]);
    assert_eq!(error["detail"]["command"], "comment_set");
    assert_eq!(error["detail"]["recovery"]["argv"][3], edit["job_id"]);
}

#[test]
fn management_commands_preserve_control_requests_and_json_output() {
    let bridge = RecordedBridge::new();
    for flags in [vec![], vec!["--json"], vec!["--pretty"]] {
        for (args, expected_request, expected_args) in [
            (vec!["bridge", "status"], "bridge_info", Value::Null),
            (vec!["bridge", "ping"], "ping", Value::Null),
            (vec!["job", "list"], "status", Value::Null),
            (
                vec!["job", "get", JOB_ID],
                "job_status",
                json!({"job_id": JOB_ID}),
            ),
            (
                vec!["job", "result", JOB_ID],
                "job_result",
                json!({"job_id": JOB_ID}),
            ),
            (vec!["job", "cancel"], "job_cancel", json!({"job_id": null})),
            (
                vec!["job", "cancel", JOB_ID],
                "job_cancel",
                json!({"job_id": JOB_ID}),
            ),
        ] {
            bridge.requests.lock().unwrap().clear();
            let output = bridge.command().args(&flags).args(&args).output().unwrap();
            assert!(output.status.success(), "{flags:?} {args:?}: {output:?}");
            assert!(output.stderr.is_empty(), "{args:?}: {output:?}");
            let result: Value = crate::json_output::from_slice(&output.stdout).unwrap();
            assert!(result.is_object(), "{args:?}: {result}");
            assert_eq!(
                output.stdout.iter().filter(|&&c| c == b'\n').count() > 1,
                flags == ["--pretty"],
                "{flags:?} {args:?}: {output:?}"
            );
            match args.as_slice() {
                ["bridge", "status"] => {
                    assert_eq!(result["state"], "running");
                    assert_eq!(result["port"], bridge.port);
                    assert_eq!(result["project"], json!(bridge.project));
                    assert_eq!(result["info"]["auto_save"], true);
                }
                ["bridge", "ping"] => {
                    assert_eq!(result["responsive"], true);
                    assert_eq!(result["project"], json!(bridge.project));
                }
                ["job", "list"] => {
                    assert_eq!(result["bridge_state"], "running");
                    assert!(result["active_job"].is_null());
                    assert_eq!(result["queued_jobs"], json!([]));
                }
                ["job", "result", _] => assert_eq!(result["response"]["status"], "success"),
                ["job", "get", _] => assert_eq!(result["job"]["id"], JOB_ID),
                ["job", "cancel"] => assert_eq!(result["job_id"], ACTIVE_JOB_ID),
                ["job", "cancel", _] => assert_eq!(result["job_id"], JOB_ID),
                _ => unreachable!(),
            }
            let requests = bridge.requests.lock().unwrap();
            let request = requests.last().unwrap();
            assert_eq!(request["command"], expected_request, "{requests:?}");
            assert_eq!(request["args"], expected_args, "{request}");
            assert!(requests.iter().all(|r| r.get("program").is_none()));
            let expected_commands = if args == ["bridge", "status"] {
                vec!["ping", "bridge_info"]
            } else {
                vec![expected_request]
            };
            assert_eq!(
                requests
                    .iter()
                    .map(|r| r["command"].as_str().unwrap())
                    .collect::<Vec<_>>(),
                expected_commands,
                "management requests must not select a program or enter the program job queue"
            );
        }
    }
}

#[test]
fn management_targets_use_config_or_explicit_project_at_each_command_level() {
    let configured = RecordedBridge::new();
    let explicit = RecordedBridge::new();
    let config = configured.root.path().join("config.yaml");
    std::fs::write(
        &config,
        serde_yaml::to_string(&json!({
            "default_project": configured.project,
            "default_program": "configured-startup-program",
        }))
        .unwrap(),
    )
    .unwrap();
    for args in [
        vec!["bridge", "status"],
        vec!["bridge", "ping"],
        vec!["job", "list"],
        vec!["job", "get", JOB_ID],
        vec!["job", "result", JOB_ID],
        vec!["job", "cancel"],
        vec!["job", "cancel", JOB_ID],
    ] {
        for position in [None, Some(0), Some(1), Some(args.len())] {
            configured.requests.lock().unwrap().clear();
            explicit.requests.lock().unwrap().clear();
            let mut command = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli");
            command
                .env("GHIDRA_CLI_CONFIG", &config)
                .env("GHIDRA_DEFAULT_PROJECT", "unused-environment-project")
                .env("GHIDRA_DEFAULT_PROGRAM", "unused-environment-program")
                .args(["--program", "unused-explicit-program"])
                .timeout(std::time::Duration::from_secs(15));
            if let Some(position) = position {
                command
                    .args(&args[..position])
                    .arg("--project")
                    .arg(&explicit.project)
                    .args(&args[position..]);
            } else {
                command.args(&args);
            }
            let output = command.output().unwrap();
            assert!(output.status.success(), "{args:?} {position:?}: {output:?}");
            let (selected, unused) = if position.is_some() {
                (&explicit, &configured)
            } else {
                (&configured, &explicit)
            };
            assert!(unused.requests.lock().unwrap().is_empty());
            let requests = selected.requests.lock().unwrap();
            assert!(!requests.is_empty(), "{args:?} {position:?}");
            assert!(!requests.iter().any(|r| r["command"] == "open_program"));
            assert!(requests.iter().all(|r| r.get("program").is_none()));
        }
    }
}

#[test]
fn editing_capabilities_are_required_before_program_selection_or_edits() {
    for mut info in [
        json!({"auto_save": true, "named_import": true}),
        json!({"auto_save": false, "named_import": true}),
        json!({"auto_save": true, "named_import": true, "explicit_addresses": false}),
        json!({"auto_save": true, "named_import": true, "explicit_addresses": true}),
        json!({"auto_save": true, "named_import": true, "explicit_addresses": true, "atomic_edits": false}),
        json!({"auto_save": false, "named_import": true, "explicit_addresses": true, "atomic_edits": true}),
    ] {
        info["protocol_version"] = json!(4);
        let bridge = RecordedBridge::with_info(info);
        std::fs::write(bridge.root.path().join("binary"), "test input").unwrap();
        for args in [
            vec!["program", "info", "--program", "B"],
            vec![
                "comment",
                "set",
                "0x1000",
                "--text",
                "marker",
                "--program",
                "B",
            ],
            vec!["program", "import", "binary", "--no-analyze"],
        ] {
            bridge.requests.lock().unwrap().clear();
            let output = bridge.command().args(&args).output().unwrap();
            assert!(!output.status.success(), "{args:?}: {output:?}");
            assert!(output.stdout.is_empty(), "{args:?}: {output:?}");
            let error: Value = serde_json::from_slice(&output.stderr).unwrap();
            assert!(
                error["message"]
                    .as_str()
                    .unwrap()
                    .contains("ghidra-cli bridge restart"),
                "{args:?}: {error}"
            );
            let requests = bridge.requests.lock().unwrap();
            assert_eq!(requests.len(), 1, "No fallback or replay: {requests:?}");
            assert_eq!(requests[0]["command"], "bridge_info");
        }
    }
}

#[test]
fn pending_save_recovery_preserves_selection_and_bypasses_edit_capabilities() {
    for program in [None, Some("B")] {
        let bridge = RecordedBridge::with_info(if program.is_some() {
            json!({"protocol_version": 4})
        } else {
            json!({})
        });
        std::fs::write(
            bridge.root.path().join("config.yaml"),
            "default_program: configured-startup-program\n",
        )
        .unwrap();
        let mut command = bridge.command();
        command.args(["program", "save"]);
        if let Some(program) = program {
            command.args(["--program", program]);
        }
        let output = command.output().unwrap();
        assert!(output.status.success(), "{program:?}: {output:?}");
        assert!(output.stderr.is_empty(), "{output:?}");
        let result: Value = crate::json_output::from_slice(&output.stdout).unwrap();
        assert_eq!(result["project"], json!(bridge.project));
        assert_eq!(result["observed_program"], program.unwrap_or("A"));
        let mut expected = Vec::new();
        if program.is_some() {
            expected.push(json!({"command": "bridge_info"}));
        }
        let mut save = json!({"command": "program_save"});
        if let Some(program) = program {
            save["program"] = json!(program);
        }
        expected.push(save);
        let requests = bridge.requests.lock().unwrap();
        for (expected, actual) in expected.iter_mut().zip(requests.iter()) {
            if let Some(id) = actual.get("job_id") {
                expected["job_id"] = id.clone();
            }
        }
        assert_eq!(
            *requests, expected,
            "Recovery must bypass editing capabilities; only a targeted save checks the protocol"
        );
    }
}

#[test]
fn unsupported_request_protocol_prevents_program_operations_and_scoped_saves() {
    for version in [None, Some(3), Some(5)] {
        let mut info = json!({"auto_save": true, "atomic_edits": true, "named_import": true, "explicit_addresses": true});
        if let Some(version) = version {
            info["protocol_version"] = json!(version);
        }
        let bridge = RecordedBridge::with_info(info);
        for args in [
            vec!["program", "info"],
            vec![
                "comment",
                "set",
                "0x1000",
                "--text",
                "marker",
                "--program",
                "B",
            ],
            vec!["program", "save", "B"],
        ] {
            bridge.requests.lock().unwrap().clear();
            let output = bridge.command().args(&args).output().unwrap();
            assert!(
                !output.status.success(),
                "{version:?}: {args:?}: {output:?}"
            );
            let error: Value = serde_json::from_slice(&output.stderr).unwrap();
            assert!(
                error["message"]
                    .as_str()
                    .unwrap()
                    .contains("ghidra-cli bridge restart"),
                "{error}"
            );
            assert_eq!(
                *bridge.requests.lock().unwrap(),
                [json!({"command": "bridge_info"})]
            );
        }
    }
}

#[test]
fn missing_scoped_target_leaves_the_selected_program_unchanged() {
    let bridge = RecordedBridge::new();
    let output = bridge
        .command()
        .args([
            "comment",
            "set",
            "0x1000",
            "--text",
            "marker",
            "--program",
            "missing-program",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success(), "{output:?}");
    let error: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["message"], "Program not found: missing-program");
    assert!(error
        .get("detail")
        .is_none_or(|detail| detail.get("outcome_unknown").is_none()));
    assert_eq!(bridge.run(&["program", "info"])["observed_program"], "A");
    let requests = bridge.requests.lock().unwrap();
    let edits: Vec<_> = requests
        .iter()
        .filter(|r| r["command"] == "comment_set")
        .collect();
    assert_eq!(edits.len(), 1);
    assert_eq!(edits[0]["program"], "missing-program");
    assert!(requests.iter().all(|r| r["command"] != "open_program"));
}

#[test]
fn explicit_save_failure_preserves_recovery_details_and_running_bridge() {
    let bridge = RecordedBridge::with_info(json!({"test_save_failure": true}));
    let output = bridge.command().args(["program", "save"]).output().unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    let error: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["message"], "Save failed");
    assert_eq!(error["detail"], json!({"save_failed": true}));
    let requests = bridge.requests.lock().unwrap().clone();
    assert_eq!(
        requests,
        vec![json!({"command": "program_save", "job_id": requests[0]["job_id"]})],
        "A failed save must return to the caller without an implicit retry or restart"
    );
    assert_eq!(
        super::bridge::read_port_file(&bridge.project).unwrap(),
        Some(bridge.port)
    );
    assert_eq!(
        super::bridge::read_pid_file(&bridge.project).unwrap(),
        Some(std::process::id())
    );
    assert_eq!(bridge.run(&["bridge", "ping"])["responsive"], true);
}

#[test]
fn starting_a_running_bridge_keeps_its_program_selection() {
    let bridge = RecordedBridge::new();
    std::fs::write(
        bridge.root.path().join("config.yaml"),
        "default_program: configured-startup-program\n",
    )
    .unwrap();
    for args in [
        vec!["bridge", "start"],
        vec!["bridge", "start", "--program", "B"],
    ] {
        let result = bridge.run(&args);
        assert_eq!(result["state"], "running");
        assert_eq!(result["project"], json!(bridge.project));
        assert_eq!(result["port"], bridge.port);
        assert!(
            bridge.requests.lock().unwrap().is_empty(),
            "Start options must not reopen a program or restart an existing bridge"
        );
    }
    assert_eq!(bridge.run(&["program", "info"])["observed_program"], "A");
}

#[test]
fn deletion_preserves_targets_and_receipt_output_in_standalone_and_batch() {
    for (command, wire) in [
        (vec!["function", "delete", "main"], "delete_function"),
        (vec!["function", "delete", "0x1000"], "delete_function"),
        (
            vec!["comment", "delete", "0x1000", "--all"],
            "comment_delete",
        ),
        (
            vec!["comment", "delete", "0x1000", "--type", "pre"],
            "comment_delete",
        ),
    ] {
        for batch in [false, true] {
            let bridge = RecordedBridge::new();
            let mut args = command.clone();
            args.extend([
                "--program",
                "B",
                "--fields",
                "status,address",
                "--format",
                "json-compact",
                "--json",
            ]);
            let result = if batch {
                std::fs::write(bridge.root.path().join("batch.txt"), args.join(" ")).unwrap();
                bridge.run(&["batch", "batch.txt"])["results"][0]["result"]["data"].clone()
            } else {
                bridge.run(&args)
            };
            assert_eq!(result, json!({"status": "deleted", "address": "0x1000"}));
            let requests = bridge.requests.lock().unwrap();
            let domain: Vec<_> = requests
                .iter()
                .filter(|r| r["command"] != "bridge_info")
                .collect();
            assert_eq!(domain.len(), 1, "{domain:?}");
            assert_eq!(domain[0]["program"], "B");
            assert_eq!(domain[0]["command"], wire);
            assert_eq!(
                domain[0]["args"],
                if wire == "comment_delete" {
                    json!({"address": "0x1000", "comment_type": if command.contains(&"--all") { None } else { Some("pre") }, "all": command.contains(&"--all")})
                } else {
                    json!({"address": command.last().unwrap()})
                }
            );
        }
    }
}
