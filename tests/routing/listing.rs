use super::{batch_arguments, RecordedBridge};
use serde_json::{json, Value};

#[test]
fn listing_undefine_preserves_targets_and_atomic_redisassembly_in_standalone_and_batch() {
    let outer = RecordedBridge::new();
    let selected = RecordedBridge::new();
    for disasm_at in [None, Some("0x1000")] {
        let mut args = vec![
            "listing",
            "undefine",
            "0x1000",
            "--end",
            "0x1010",
            "--project",
            selected.project.to_str().unwrap(),
            "--program",
            "B",
        ];
        if let Some(address) = disasm_at {
            args.extend(["--disassemble-at", address]);
        }
        for batch in [false, true] {
            outer.requests.lock().unwrap().clear();
            selected.requests.lock().unwrap().clear();
            let receipt = if batch {
                std::fs::write(outer.root.path().join("batch.txt"), batch_arguments(&args))
                    .unwrap();
                let report = outer.run(&["batch", "batch.txt"]);
                assert_eq!(report["failed"], 0, "{report}");
                report["results"][0]["result"]["data"].clone()
            } else {
                outer.run(&args)
            };
            assert_eq!(receipt["observed_program"], "B");
            assert!(outer
                .requests
                .lock()
                .unwrap()
                .iter()
                .all(|request| request["command"] == "bridge_info"));
            let requests = selected.requests.lock().unwrap();
            let domain: Vec<_> = requests
                .iter()
                .filter(|r| r["command"] != "bridge_info")
                .collect();
            assert_eq!(domain.len(), 2, "{requests:?}");
            assert_eq!(domain[0]["command"], "open_program");
            assert_eq!(domain[0]["args"]["program"], "B");
            assert_eq!(domain[1]["command"], "clear_range");
            assert_eq!(
                domain[1]["args"],
                json!({"start": "0x1000", "end": "0x1010", "disasm_at": disasm_at})
            );
        }
    }
}

#[test]
fn listing_undefine_preserves_independently_qualified_addresses() {
    let bridge = RecordedBridge::new();
    for (start, end) in [
        ("overlay:0x1000", "overlay:0x1010"),
        ("overlay:0x1000", "0x1010"),
        ("ram:0x1234:0x0005", "ram:0x1234:0x0008"),
        ("0x1234:0x10", "0x1234:0x20"),
        ("word:0x1000.1", "word:0x1001.0"),
    ] {
        bridge.requests.lock().unwrap().clear();
        bridge.run(&["listing", "undefine", start, "--end", end]);
        let requests = bridge.requests.lock().unwrap();
        let edits: Vec<_> = requests
            .iter()
            .filter(|request| request["command"] != "bridge_info")
            .collect();
        assert_eq!(edits.len(), 1, "{start} --end {end}: {requests:?}");
        assert_eq!(edits[0]["command"], "clear_range");
        assert_eq!(
            edits[0]["args"],
            json!({"start": start, "end": end, "disasm_at": null}),
            "{start} --end {end}"
        );
    }
}

#[test]
fn listing_undefine_rejects_invalid_or_missing_bounds_before_dispatch() {
    let bridge = RecordedBridge::new();
    for (bounds, message, exit) in [
        (vec!["entry", "--end", "0x1010"], "Invalid START address", 1),
        (
            vec!["0x1000", "--end", "overlay:1010"],
            "Invalid --end address",
            1,
        ),
        (vec!["0x1000"], "--end <END>", 2),
    ] {
        let args: Vec<_> = ["listing", "undefine", "--program", "must-not-open"]
            .into_iter()
            .chain(bounds)
            .collect();
        let output = bridge.command().args(&args).output().unwrap();
        assert_eq!(output.status.code(), Some(exit), "{args:?}: {output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(message),
            "{output:?}"
        );

        std::fs::write(bridge.root.path().join("batch.txt"), batch_arguments(&args)).unwrap();
        let output = bridge
            .command()
            .args(["batch", "batch.txt"])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        let report: Value = crate::json_output::from_slice(&output.stdout).unwrap();
        assert_eq!(report["commands_executed"], 0);
        assert_eq!(report["validation_failed"], true);
        assert!(
            report["validation_errors"][0]["error"]
                .as_str()
                .unwrap()
                .contains(message),
            "{report}"
        );
        assert!(bridge.requests.lock().unwrap().is_empty());
    }
}

#[test]
fn instruction_queries_forward_ranges_and_apply_query_options_after_fetch() {
    let bridge = RecordedBridge::new();
    for command in [
        vec![
            "find",
            "instruction",
            "NOP",
            "--start",
            "0x1000",
            "--end",
            "0x1002",
            "--case-sensitive",
        ],
        vec!["disassemble", "0x1000", "--end", "0x1002"],
    ] {
        let rows = bridge.run(&command);
        assert_eq!(
            rows.as_array().unwrap().len(),
            1,
            "configured default limit"
        );
        let mut all = command.clone();
        all.extend(["--limit", "0"]);
        assert_eq!(bridge.run(&all).as_array().unwrap().len(), 3);
        let mut filtered = command.clone();
        filtered.extend([
            "--filter",
            "address != '0x1000'",
            "--fields",
            "address",
            "--sort=-address",
            "--skip",
            "1",
            "--limit",
            "1",
        ]);
        assert_eq!(bridge.run(&filtered), json!([{"address": "0x1001"}]));
        let mut count = command.clone();
        count.push("--count");
        assert_eq!(bridge.run(&count), 3);
        let requests = bridge.requests.lock().unwrap();
        let wire = if command[0] == "find" {
            "find_instruction"
        } else {
            "disasm_range"
        };
        let sent: Vec<_> = requests.iter().filter(|r| r["command"] == wire).collect();
        assert_eq!(sent.len(), 4);
        assert_eq!(sent[0]["args"]["limit"], 1);
        for request in &sent {
            assert_eq!(request["args"]["start"], "0x1000");
            assert_eq!(request["args"]["end"], "0x1002");
            if wire == "find_instruction" {
                assert_eq!(request["args"]["pattern"], "NOP");
                assert_eq!(request["args"]["case_sensitive"], true);
            }
        }
        for request in &sent[1..] {
            assert!(request["args"]["limit"].is_null());
        }
    }
}

#[test]
fn disassembly_queries_select_rows_before_paging_in_standalone_and_batch() {
    let bridge = RecordedBridge::new();
    let all = bridge.run(&["function", "disassemble", "main", "--limit", "0"]);
    assert_eq!(all.as_array().unwrap().len(), 3);
    for (flags, expected, fetch_limit) in [
        (vec![], json!([all[0]]), json!(1)),
        (vec!["--limit", "0"], all.clone(), Value::Null),
        (vec!["--limit", "2"], json!([all[0], all[1]]), json!(2)),
        (vec!["--count"], json!(3), Value::Null),
        (
            vec!["--filter", "mnemonic=RET"],
            json!([all[2]]),
            Value::Null,
        ),
        (
            vec!["--filter", "mnemonic=RET", "--count"],
            json!(1),
            Value::Null,
        ),
        (vec!["--skip", "1"], json!([all[1]]), Value::Null),
        (vec!["--sort=-address"], json!([all[2]]), Value::Null),
        (
            vec![
                "--sort=-address",
                "--skip",
                "1",
                "--limit",
                "1",
                "--fields",
                "address",
            ],
            json!([{"address": "0x1001"}]),
            Value::Null,
        ),
        (
            vec!["--skip", "1", "--limit", "1", "--count"],
            json!(1),
            Value::Null,
        ),
    ] {
        for (command, wire, target_key) in [
            (
                vec!["function", "disassemble", "main"],
                "function_disasm",
                "target",
            ),
            (vec!["disassemble", "main"], "disasm", "address"),
        ] {
            let args: Vec<_> = command
                .iter()
                .copied()
                .chain(flags.iter().copied())
                .collect();
            for batch in [false, true] {
                bridge.requests.lock().unwrap().clear();
                let result = if batch {
                    std::fs::write(bridge.root.path().join("batch.txt"), args.join(" ")).unwrap();
                    bridge.run(&["batch", "batch.txt"])["results"][0]["result"]["data"].clone()
                } else {
                    bridge.run(&args)
                };
                // Batch commands without query flags retain the bridge envelope.
                let expected_result = expected.clone();
                assert_eq!(result, expected_result, "{args:?}, batch={batch}");
                let requests = bridge.requests.lock().unwrap();
                let disassembly: Vec<_> = requests
                    .iter()
                    .filter(|r| matches!(r["command"].as_str(), Some("disasm" | "function_disasm")))
                    .collect();
                assert_eq!(disassembly.len(), 1);
                assert_eq!(disassembly[0]["command"], wire);
                assert_eq!(
                    disassembly[0]["args"],
                    json!({target_key: "main", "limit": fetch_limit})
                );
            }
        }
    }
}

#[test]
fn define_code_forwards_bounds_and_preserves_receipts_without_query_defaults() {
    let bridge = RecordedBridge::new();
    for config in [
        None,
        Some("{}\n"),
        Some("default_limit: 1\n"),
        Some("default_limit: 0\n"),
    ] {
        let config_path = bridge.root.path().join("config.yaml");
        if let Some(config) = config {
            std::fs::write(&config_path, config).unwrap();
        } else {
            std::fs::remove_file(&config_path).unwrap();
        }
        for (flags, end) in [
            (vec![], Value::Null),
            (vec!["--end", "0x1010"], json!("0x1010")),
        ] {
            let args: Vec<_> = ["listing", "define-code", "0x1000", "--program", "B"]
                .into_iter()
                .chain(flags)
                .collect();
            for batch in [false, true] {
                bridge.requests.lock().unwrap().clear();
                let receipt = if batch {
                    std::fs::write(bridge.root.path().join("batch.txt"), args.join(" ")).unwrap();
                    bridge.run(&["batch", "batch.txt"])["results"][0]["result"]["data"].clone()
                } else {
                    bridge.run(&args)
                };
                assert!(receipt.is_object(), "{receipt}");
                assert_eq!(
                    receipt,
                    json!({"address": "0x1000", "end": end,
                    "ok": true, "landed": true, "already_defined": false,
                    "changed": true, "status": "defined"})
                );
                let requests = bridge.requests.lock().unwrap();
                let edits: Vec<_> = requests
                    .iter()
                    .filter(|r| r["command"] == "define_code")
                    .collect();
                assert_eq!(edits.len(), 1);
                assert_eq!(edits[0]["args"], json!({"target": "0x1000", "end": end}));
                assert!(requests
                    .iter()
                    .any(|r| r["command"] == "open_program" && r["args"]["program"] == "B"));
            }
        }
    }
}

#[test]
fn flow_edits_preserve_omission_clear_and_explicit_no_fallthrough_in_batches() {
    let bridge = RecordedBridge::new();
    for (operation, flags, expected) in [
        ("get", vec![], json!({"address": "overlay:0x1000"})),
        (
            "set",
            vec!["--override", "call-return"],
            json!({"address": "overlay:0x1000", "override": "call-return", "fallthrough": null, "no_fallthrough": false}),
        ),
        (
            "set",
            vec!["--fallthrough", "overlay:0x1010"],
            json!({"address": "overlay:0x1000", "override": null, "fallthrough": "overlay:0x1010", "no_fallthrough": false}),
        ),
        (
            "set",
            vec!["--override", "call", "--no-fallthrough"],
            json!({"address": "overlay:0x1000", "override": "call", "fallthrough": null, "no_fallthrough": true}),
        ),
        (
            "clear",
            vec!["--override"],
            json!({"address": "overlay:0x1000", "override": true, "fallthrough": false}),
        ),
        (
            "clear",
            vec!["--fallthrough"],
            json!({"address": "overlay:0x1000", "override": false, "fallthrough": true}),
        ),
        (
            "clear",
            vec!["--override", "--fallthrough"],
            json!({"address": "overlay:0x1000", "override": true, "fallthrough": true}),
        ),
    ] {
        for batch in [false, true] {
            bridge.requests.lock().unwrap().clear();
            let args: Vec<_> = [
                "listing",
                "flow",
                operation,
                "overlay:0x1000",
                "--program",
                "B",
                "--fields",
                "observed_program",
            ]
            .into_iter()
            .chain(flags.iter().copied())
            .collect();
            let receipt = if batch {
                std::fs::write(bridge.root.path().join("flow.txt"), batch_arguments(&args))
                    .unwrap();
                bridge.run(&["batch", "flow.txt"])["results"][0]["result"]["data"].clone()
            } else {
                bridge.run(&args)
            };
            assert_eq!(receipt, json!({"observed_program": "B"}));
            let requests = bridge.requests.lock().unwrap();
            let wire = format!("listing_flow_{operation}");
            let operations: Vec<_> = requests.iter().filter(|r| r["command"] == wire).collect();
            assert_eq!(operations.len(), 1);
            assert_eq!(operations[0]["args"], expected);
        }
    }
}

#[test]
fn flow_inputs_fail_before_bridge_work() {
    let bridge = RecordedBridge::new();
    for args in [
        vec!["set", "0x1000"],
        vec!["clear", "0x1000"],
        vec![
            "set",
            "0x1000",
            "--fallthrough",
            "0x1010",
            "--no-fallthrough",
        ],
        vec!["set", "0x1000", "--fallthrough", "invalid"],
        vec!["get", "1000"],
    ] {
        let args: Vec<_> = ["listing", "flow", "--program", "must-not-open"]
            .into_iter()
            .chain(args)
            .collect();
        let output = bridge.command().args(&args).output().unwrap();
        assert!(!output.status.success(), "{args:?}");
        assert!(bridge.requests.lock().unwrap().is_empty());
    }
}
