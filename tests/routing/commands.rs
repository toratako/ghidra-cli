use super::{batch_arguments, RecordedBridge};
use serde_json::{json, Value};

#[test]
fn renamed_commands_preserve_wire_requests_in_standalone_and_batch() {
    let bridge = RecordedBridge::new();
    for (args, wire, key, expected) in [
        (
            vec!["xref", "to", "0x1000", "--limit", "0"],
            "xrefs_to",
            "address",
            "0x1000",
        ),
        (
            vec!["xref", "from", "0x1000", "--limit", "0"],
            "xrefs_from",
            "address",
            "0x1000",
        ),
        (
            vec!["xref", "from", "main", "--function", "--limit", "0"],
            "xrefs_from",
            "address",
            "main",
        ),
        (
            vec!["string", "refs", "needle", "--limit", "0"],
            "string_refs",
            "pattern",
            "needle",
        ),
        (
            vec!["disassemble", "0x1000", "--limit", "0"],
            "disasm",
            "address",
            "0x1000",
        ),
        (
            vec!["function", "disassemble", "main", "--limit", "0"],
            "function_disasm",
            "target",
            "main",
        ),
        (
            vec!["listing", "define-code", "0x1000", "--end", "0x1010"],
            "define_code",
            "target",
            "0x1000",
        ),
    ] {
        bridge.requests.lock().unwrap().clear();
        let standalone = bridge.run(&args);
        let standalone_request = bridge
            .requests
            .lock()
            .unwrap()
            .iter()
            .find(|request| request["command"] == wire)
            .unwrap()
            .clone();
        assert_eq!(standalone_request["args"][key], expected);
        if wire == "define_code" {
            assert_eq!(standalone_request["args"]["end"], "0x1010");
        }
        if wire == "xrefs_from" {
            assert_eq!(
                standalone_request["args"]["function"],
                args.contains(&"--function")
            );
        }
        bridge.requests.lock().unwrap().clear();
        std::fs::write(bridge.root.path().join("batch.txt"), batch_arguments(&args)).unwrap();
        let report = bridge.run(&["batch", "batch.txt"]);
        assert_eq!(report[0]["failed"], 0, "{args:?}: {report}");
        let requests = bridge.requests.lock().unwrap();
        let request = requests
            .iter()
            .find(|request| request["command"] == wire)
            .unwrap();
        assert_eq!(request["args"], standalone_request["args"], "{args:?}");
        let result = &report[0]["results"][0]["result"];
        // Mutations are wrapped as one receipt in standalone JSON output.
        assert_eq!(
            result,
            if wire == "define_code" {
                &standalone[0]
            } else {
                &standalone
            },
            "{args:?}"
        );
    }
}

#[test]
fn invalid_mutation_arguments_fail_before_bridge_or_config_errors() {
    let bridge = RecordedBridge::new();
    std::fs::write(bridge.root.path().join("invalid.yaml"), "default_limit: [").unwrap();
    for args in [
        vec!["function", "delete"],
        vec!["comment", "set", "0x1000", "marker", "--unknown-option"],
    ] {
        for invalid_config in [false, true] {
            let mut command = bridge.command();
            command.args(&args).args(["--program", "must-not-open"]);
            if invalid_config {
                command.env("GHIDRA_CLI_CONFIG", bridge.root.path().join("invalid.yaml"));
            }
            let output = command.output().unwrap();
            assert_eq!(output.status.code(), Some(2), "{output:?}");
            assert!(bridge.requests.lock().unwrap().is_empty());
        }
    }
}

#[test]
fn positional_targets_preserve_requests_in_standalone_and_batch() {
    let bridge = RecordedBridge::new();
    for (args, wire, key) in [
        (
            vec![
                "function",
                "set-signature",
                "entry",
                "--signature",
                "int entry(void)",
            ],
            "function_set_signature",
            "target",
        ),
        (
            vec![
                "function",
                "set-return-type",
                "entry",
                "--type",
                "unsigned long",
            ],
            "function_set_return_type",
            "target",
        ),
        (
            vec![
                "function",
                "set-calling-convention",
                "entry",
                "--convention",
                "__cdecl",
            ],
            "function_set_calling_convention",
            "target",
        ),
        (
            vec!["function", "set-noreturn", "entry", "--value", "false"],
            "function_set_noreturn",
            "target",
        ),
        (
            vec![
                "function", "edit-var", "entry", "--var", "local_10", "--name", "value",
            ],
            "function_edit_var",
            "target",
        ),
        (vec!["function", "get", "entry"], "get_function", "address"),
        (vec!["decompile", "entry"], "decompile", "address"),
        (
            vec!["graph", "callers", "entry"],
            "graph_callers",
            "function",
        ),
        (
            vec!["graph", "callees", "entry"],
            "graph_callees",
            "function",
        ),
    ] {
        bridge.requests.lock().unwrap().clear();
        bridge.run(&args);
        let standalone = {
            let requests = bridge.requests.lock().unwrap();
            let operations: Vec<_> = requests.iter().filter(|r| r["command"] == wire).collect();
            assert_eq!(operations.len(), 1, "{args:?}: {requests:?}");
            assert_eq!(operations[0]["args"][key], "entry", "{args:?}");
            operations[0]["args"].clone()
        };
        bridge.requests.lock().unwrap().clear();
        std::fs::write(bridge.root.path().join("batch.txt"), batch_arguments(&args)).unwrap();
        let report = bridge.run(&["batch", "batch.txt"]);
        assert_eq!(report[0]["failed"], 0, "{args:?}: {report}");
        let requests = bridge.requests.lock().unwrap();
        let operations: Vec<_> = requests.iter().filter(|r| r["command"] == wire).collect();
        assert_eq!(operations.len(), 1, "{args:?}: {requests:?}");
        assert_eq!(operations[0]["args"], standalone, "{args:?}");
    }
}

#[test]
fn single_objects_and_mutations_reject_list_flags_before_program_dispatch() {
    let bridge = RecordedBridge::new();
    let flags = [
        "--filter name=other",
        "--sort name",
        "--offset 1",
        "--limit 0",
        "--count",
    ];
    let mut lines: Vec<_> = [
        "function delete main",
        "listing define-code 0x1000",
        "comment delete 0x1000 --all",
        "memory read 0x1000 8",
        "program info",
        "program stats",
    ]
    .into_iter()
    .flat_map(|command| {
        flags
            .iter()
            .map(move |flag| format!("{command} --program must-not-open {flag}"))
    })
    .collect();
    let rejected = lines.len();
    for line in &lines {
        let output = bridge
            .command()
            .args(line.split_whitespace())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        assert!(bridge.requests.lock().unwrap().is_empty());
    }
    lines.push("program info".into());
    std::fs::write(bridge.root.path().join("batch.txt"), lines.join("\n")).unwrap();
    let output = bridge
        .command()
        .args(["batch", "batch.txt"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    for result in report[0]["validation_errors"]
        .as_array()
        .unwrap()
        .iter()
        .take(rejected)
    {
        assert!(
            result["error"]
                .as_str()
                .unwrap()
                .contains("unexpected argument"),
            "{result}"
        );
    }
    let error: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["detail"]["failed"], rejected);
    assert_eq!(report[0]["commands_executed"], 0);
    assert!(bridge.requests.lock().unwrap().is_empty());
}

#[test]
fn standalone_targets_use_config_or_explicit_flags() {
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
    for with_flags in [false, true] {
        configured.requests.lock().unwrap().clear();
        explicit.requests.lock().unwrap().clear();
        let mut command = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli");
        command
            .env("GHIDRA_CLI_CONFIG", &config)
            .env(
                "GHIDRA_INSTALL_DIR",
                configured.root.path().join("unused-install"),
            )
            .args(["symbol", "externals"]);
        if with_flags {
            command
                .arg("--project")
                .arg(&explicit.project)
                .args(["--program", "explicit-program"]);
        }
        let output = command.output().unwrap();
        assert!(output.status.success(), "{output:?}");
        let (selected, unused) = if with_flags {
            (&explicit, &configured)
        } else {
            (&configured, &explicit)
        };
        assert!(unused.requests.lock().unwrap().is_empty());
        let requests = selected.requests.lock().unwrap();
        assert!(requests.iter().any(|r| r["command"] == "symbol_externals"));
        let opened: Vec<_> = requests
            .iter()
            .filter(|r| r["command"] == "open_program")
            .collect();
        if with_flags {
            assert_eq!(opened.len(), 1);
            assert_eq!(opened[0]["args"]["program"], "explicit-program");
        } else {
            // A running bridge keeps its current selection, even with a configured default.
            assert!(opened.is_empty(), "{opened:?}");
        }
    }
}
