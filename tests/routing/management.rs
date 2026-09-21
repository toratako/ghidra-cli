use super::RecordedBridge;
use serde_json::{json, Value};

#[test]
fn management_commands_preserve_control_requests_and_json_output() {
    let bridge = RecordedBridge::new();
    for flags in [vec![], vec!["--json"], vec!["--pretty"]] {
        for (args, expected_request, expected_args) in [
            (vec!["bridge", "status"], "bridge_info", Value::Null),
            (vec!["bridge", "ping"], "ping", Value::Null),
            (vec!["job", "list"], "status", Value::Null),
            (
                vec!["job", "get", "42"],
                "job_status",
                json!({"job_id": 42}),
            ),
            (vec!["job", "cancel"], "job_cancel", json!({"job_id": null})),
            (
                vec!["job", "cancel", "42"],
                "job_cancel",
                json!({"job_id": 42}),
            ),
        ] {
            bridge.requests.lock().unwrap().clear();
            let output = bridge.command().args(&flags).args(&args).output().unwrap();
            assert!(output.status.success(), "{flags:?} {args:?}: {output:?}");
            assert!(output.stderr.is_empty(), "{args:?}: {output:?}");
            let result: Value = serde_json::from_slice(&output.stdout).unwrap();
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
                ["job", "get", _] => assert_eq!(result["job"]["id"], 42),
                ["job", "cancel"] => assert_eq!(result["job_id"], 7),
                ["job", "cancel", _] => assert_eq!(result["job_id"], 42),
                _ => unreachable!(),
            }
            let requests = bridge.requests.lock().unwrap();
            let request = requests.last().unwrap();
            assert_eq!(request["command"], expected_request, "{requests:?}");
            assert_eq!(request["args"], expected_args, "{request}");
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
        vec!["job", "get", "42"],
        vec!["job", "cancel"],
        vec!["job", "cancel", "42"],
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
        }
    }
}

#[test]
fn editing_capabilities_are_required_before_program_selection_or_edits() {
    for info in [
        json!({"auto_save": true, "named_import": true}),
        json!({"auto_save": false, "named_import": true}),
        json!({"auto_save": true, "named_import": true, "explicit_addresses": false}),
        json!({"auto_save": true, "named_import": true, "explicit_addresses": true}),
        json!({"auto_save": true, "named_import": true, "explicit_addresses": true, "atomic_edits": false}),
        json!({"auto_save": false, "named_import": true, "explicit_addresses": true, "atomic_edits": true}),
    ] {
        let bridge = RecordedBridge::with_info(info);
        std::fs::write(bridge.root.path().join("binary"), "test input").unwrap();
        for args in [
            vec!["program", "info", "--program", "B"],
            vec!["comment", "set", "0x1000", "marker", "--program", "B"],
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
fn pending_save_recovery_does_not_require_atomic_edit_capability() {
    let bridge = RecordedBridge::with_info(json!({"auto_save": true}));
    let output = bridge.command().args(["program", "save"]).output().unwrap();
    assert!(output.status.success(), "{output:?}");
    let requests = bridge.requests.lock().unwrap();
    assert_eq!(
        requests.len(),
        1,
        "Save must not restart or replay: {requests:?}"
    );
    assert_eq!(requests[0]["command"], "program_save");
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
            vec!["comment", "delete", "0x1000", "--comment-type", "pre"],
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
                bridge.run(&["batch", "batch.txt"])[0]["results"][0]["result"].clone()
            } else {
                bridge.run(&args)
            };
            assert_eq!(result, json!([{"status": "deleted", "address": "0x1000"}]));
            let requests = bridge.requests.lock().unwrap();
            let domain: Vec<_> = requests
                .iter()
                .filter(|r| r["command"] != "bridge_info")
                .collect();
            assert_eq!(domain.len(), 2, "{domain:?}");
            assert_eq!(domain[0]["command"], "open_program");
            assert_eq!(domain[0]["args"]["program"], "B");
            assert_eq!(domain[1]["command"], wire);
            assert_eq!(
                domain[1]["args"],
                if wire == "comment_delete" {
                    json!({"address": "0x1000", "comment_type": if command.contains(&"--all") { None } else { Some("pre") }, "all": command.contains(&"--all")})
                } else {
                    json!({"address": command.last().unwrap()})
                }
            );
        }
    }
}
