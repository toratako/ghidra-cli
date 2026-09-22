use super::{batch_arguments, call_graph_fixture, call_rows_fixture, RecordedBridge};
use serde_json::{json, Value};

#[test]
fn graph_calls_queries_select_nodes_and_keep_outgoing_edges_in_standalone_and_batch() {
    let bridge = RecordedBridge::new();
    let all = call_graph_fixture();
    let graph = |nodes: &[usize], edges: &[usize]| {
        json!({
            "nodes": nodes.iter().map(|&i| all["nodes"][i].clone()).collect::<Vec<_>>(),
            "edges": edges.iter().map(|&i| all["edges"][i].clone()).collect::<Vec<_>>(),
            "node_count": nodes.len(),
            "edge_count": edges.len(),
        })
    };
    let mut projected = graph(&[1, 2], &[1, 2, 3]);
    projected["nodes"] = json!([{"name": "alpha"}, {"name": "beta"}]);
    for (flags, expected, fetch_limit) in [
        (vec![], graph(&[0], &[0]), json!(1)),
        (vec!["--limit", "0"], all.clone(), Value::Null),
        (vec!["--limit", "2"], graph(&[0, 1], &[0, 1, 2]), json!(2)),
        (vec!["--sort", "name"], graph(&[1], &[1, 2]), Value::Null),
        (
            vec!["--sort", "name", "--limit", "2"],
            graph(&[1, 2], &[1, 2, 3]),
            Value::Null,
        ),
        (vec!["--offset", "1"], graph(&[1], &[1, 2]), Value::Null),
        (
            vec!["--filter", "name=beta"],
            graph(&[2], &[3]),
            Value::Null,
        ),
        (
            vec![
                "--filter", "name~a", "--sort", "name", "--offset", "1", "--limit", "2",
            ],
            graph(&[2, 3], &[3, 4]),
            Value::Null,
        ),
        (
            vec!["--sort=-name", "--offset", "1", "--limit", "0"],
            graph(&[3, 2, 1], &[1, 2, 3, 4]),
            Value::Null,
        ),
        (
            vec!["--sort", "name", "--limit", "2", "--fields", "name"],
            projected.clone(),
            Value::Null,
        ),
        (
            vec!["--sort", "name", "--limit", "2", "--fields=-id,address"],
            projected,
            Value::Null,
        ),
        (vec!["--offset", "99"], graph(&[], &[]), Value::Null),
        (
            vec!["--filter", "name=absent"],
            graph(&[], &[]),
            Value::Null,
        ),
        (vec!["--count"], json!(4), Value::Null),
        (
            vec!["--offset", "1", "--limit", "2", "--count"],
            json!(2),
            Value::Null,
        ),
        (
            vec!["--filter", "name=absent", "--count"],
            json!(0),
            Value::Null,
        ),
    ] {
        let args: Vec<_> = ["graph", "calls"].into_iter().chain(flags).collect();
        for batch in [false, true] {
            bridge.requests.lock().unwrap().clear();
            let result = if batch {
                std::fs::write(bridge.root.path().join("batch.txt"), batch_arguments(&args))
                    .unwrap();
                bridge.run(&["batch", "batch.txt"])["results"][0]["result"]["data"].clone()
            } else {
                bridge.run(&args)
            };
            assert_eq!(result, expected, "{args:?}, batch={batch}");
            let requests = bridge.requests.lock().unwrap();
            let graphs: Vec<_> = requests
                .iter()
                .filter(|r| r["command"] == "graph_calls")
                .collect();
            assert_eq!(graphs.len(), 1);
            assert_eq!(graphs[0]["args"], json!({"limit": fetch_limit}), "{args:?}");
        }
    }
}

#[test]
fn decompiler_commands_share_native_timeout_configuration() {
    let bridge = RecordedBridge::new();
    for (args, wire) in [
        (vec!["decompile", "main"], "decompile"),
        (vec!["function", "var", "list", "main"], "function_var_list"),
        (
            vec!["function", "var", "get", "main", "--var", "value"],
            "function_var_get",
        ),
        (
            vec!["function", "set-return-type", "main", "--type", "void"],
            "function_set_return_type",
        ),
        (
            vec!["pcode", "function", "main", "--high"],
            "pcode_function",
        ),
        (
            vec![
                "function", "var", "set", "main", "--var", "param_1", "--name", "input",
            ],
            "function_var_set",
        ),
    ] {
        for (configured, expected) in [
            (None, 0),
            (Some("0"), 0),
            (Some("47"), 47),
            (Some("2147483"), 2147483),
        ] {
            bridge.requests.lock().unwrap().clear();
            let mut command = bridge.command();
            command.args(&args);
            if let Some(value) = configured {
                command.env("GHIDRA_CLI_DECOMPILE_TIMEOUT", value);
            }
            command.assert().success();
            let requests = bridge.requests.lock().unwrap();
            let request = requests
                .iter()
                .find(|request| request["command"] == wire)
                .unwrap();
            assert_eq!(request["args"]["timeout_secs"], expected, "{args:?}");
        }
        for configured in [
            "-1",
            "2147484",
            "2147483648",
            "4294967297",
            "1.5",
            "invalid",
        ] {
            bridge.requests.lock().unwrap().clear();
            let output = bridge
                .command()
                .env("GHIDRA_CLI_DECOMPILE_TIMEOUT", configured)
                .args(&args)
                .output()
                .unwrap();
            assert!(
                !output.status.success(),
                "{args:?}, {configured}: {output:?}"
            );
            let error: Value = serde_json::from_slice(&output.stderr).unwrap();
            assert!(
                error["message"]
                    .as_str()
                    .unwrap()
                    .contains("GHIDRA_CLI_DECOMPILE_TIMEOUT"),
                "{error}"
            );
            assert!(
                bridge
                    .requests
                    .lock()
                    .unwrap()
                    .iter()
                    .all(|request| request["command"] != wire),
                "Invalid configuration must not dispatch {wire}"
            );
        }
    }
}

#[test]
fn call_traversal_queries_share_rows_and_preserve_selection_before_limits() {
    let bridge = RecordedBridge::new();
    for direction in ["callers", "callees"] {
        let wire = format!("graph_{direction}");
        for (flags, expected, fetch_limit) in [
            (vec![], json!(&call_rows_fixture()[..1]), json!(1)),
            (
                vec!["--limit", "0"],
                json!(call_rows_fixture()),
                Value::Null,
            ),
            (vec!["--count"], json!(3), Value::Null),
            (vec!["--limit", "2", "--count"], json!(2), Value::Null),
            (
                vec!["--filter", "callee=leaf", "--fields", "caller,callee,via"],
                json!([{"caller": "helper", "callee": "leaf", "via": "0x3004"}]),
                Value::Null,
            ),
            (
                vec!["--sort", "-call_site", "--offset", "1", "--limit", "1"],
                json!([call_rows_fixture()[1].clone()]),
                Value::Null,
            ),
        ] {
            let mut args = vec!["graph", direction, "entry", "--depth", "3"];
            args.extend(flags);
            bridge.requests.lock().unwrap().clear();
            assert_eq!(bridge.run(&args), expected, "{args:?}");
            let standalone = {
                let requests = bridge.requests.lock().unwrap();
                let operations: Vec<_> = requests.iter().filter(|r| r["command"] == wire).collect();
                assert_eq!(operations.len(), 1);
                let request = operations[0]["args"].clone();
                assert_eq!(request["function"], "entry");
                assert_eq!(request["depth"], 3);
                assert_eq!(request["limit"], fetch_limit, "{args:?}");
                request
            };
            bridge.requests.lock().unwrap().clear();
            std::fs::write(bridge.root.path().join("calls.txt"), batch_arguments(&args)).unwrap();
            let batch = bridge.run(&["batch", "calls.txt"]);
            let actual = &batch["results"][0]["result"]["data"];
            assert_eq!(*actual, expected, "{args:?}: {batch}");
            let requests = bridge.requests.lock().unwrap();
            let operations: Vec<_> = requests.iter().filter(|r| r["command"] == wire).collect();
            assert_eq!(operations.len(), 1);
            assert_eq!(operations[0]["args"], standalone);
        }
    }
}

#[test]
fn decompile_forwards_jump_table_selection_without_truncating_nested_results() {
    let bridge = RecordedBridge::new();
    for with_jump_tables in [false, true] {
        for batch in [false, true] {
            bridge.requests.lock().unwrap().clear();
            let mut args = vec!["decompile", "main"];
            if with_jump_tables {
                args.push("--with-jump-tables");
            }
            let result = if batch {
                std::fs::write(bridge.root.path().join("batch.txt"), args.join(" ")).unwrap();
                bridge.run(&["batch", "batch.txt"])["results"][0]["result"]["data"].clone()
            } else {
                bridge.run(&args)
            };
            assert_eq!(result["basic_block_count"], 3);
            assert_eq!(result.get("jump_tables").is_some(), with_jump_tables);
            if with_jump_tables {
                assert_eq!(result["jump_tables"].as_array().unwrap().len(), 2);
                assert_eq!(
                    result["jump_tables"][0]["cases"].as_array().unwrap().len(),
                    2
                );
            }
            let requests = bridge.requests.lock().unwrap();
            let decompile: Vec<_> = requests
                .iter()
                .filter(|r| r["command"] == "decompile")
                .collect();
            assert_eq!(decompile.len(), 1);
            assert_eq!(
                decompile[0]["args"],
                json!({"address": "main", "with_vars": false, "with_params": false, "with_jump_tables": with_jump_tables, "timeout_secs": 0})
            );
        }
    }
}

#[test]
fn function_body_and_call_signature_preserve_scope_and_options_in_batches() {
    let bridge = RecordedBridge::new();
    for (args, wire, expected) in [
        (
            vec![
                "function",
                "get",
                "caller",
                "--with-frame",
                "--with-signature",
            ],
            "get_function",
            json!({"address": "caller", "with_frame": true, "with_signature": true}),
        ),
        (
            vec![
                "function",
                "set-body",
                "caller",
                "--range",
                "overlay:0x1000",
                "overlay:0x101f",
                "--range",
                "overlay:0x2000",
                "overlay:0x200f",
            ],
            "function_set_body",
            json!({"target": "caller", "ranges": [{"start": "overlay:0x1000", "end": "overlay:0x101f"}, {"start": "overlay:0x2000", "end": "overlay:0x200f"}]}),
        ),
        (
            vec![
                "function",
                "call-signature",
                "get",
                "caller",
                "--at",
                "ram:0x1234:0x10",
            ],
            "function_call_signature_get",
            json!({"target": "caller", "at": "ram:0x1234:0x10"}),
        ),
        (
            vec![
                "function",
                "call-signature",
                "set",
                "caller",
                "--at",
                "0x1010",
                "--signature",
                "int callback(char *, ...)",
                "--convention",
                "__cdecl",
            ],
            "function_call_signature_set",
            json!({"target": "caller", "at": "0x1010", "signature": "int callback(char *, ...)", "convention": "__cdecl"}),
        ),
        (
            vec![
                "function",
                "call-signature",
                "set",
                "caller",
                "--at",
                "0x1010",
                "--signature",
                "void callback(void)",
            ],
            "function_call_signature_set",
            json!({"target": "caller", "at": "0x1010", "signature": "void callback(void)", "convention": null}),
        ),
        (
            vec![
                "function",
                "call-signature",
                "clear",
                "caller",
                "--at",
                "0x1010",
            ],
            "function_call_signature_clear",
            json!({"target": "caller", "at": "0x1010"}),
        ),
    ] {
        for batch in [false, true] {
            bridge.requests.lock().unwrap().clear();
            let mut args = args.clone();
            args.extend(["--program", "B", "--fields", "observed_program"]);
            let receipt = if batch {
                std::fs::write(
                    bridge.root.path().join("functions.txt"),
                    batch_arguments(&args),
                )
                .unwrap();
                bridge.run(&["batch", "functions.txt"])["results"][0]["result"]["data"].clone()
            } else {
                bridge.run(&args)
            };
            assert_eq!(receipt, json!({"observed_program": "B"}));
            let requests = bridge.requests.lock().unwrap();
            let operations: Vec<_> = requests.iter().filter(|r| r["command"] == wire).collect();
            assert_eq!(operations.len(), 1, "{args:?}");
            assert_eq!(operations[0]["args"], expected, "{args:?}");
            assert!(requests
                .iter()
                .any(|r| r["command"] == "open_program" && r["args"]["program"] == "B"));
        }
    }
}

#[test]
fn variable_list_queries_preserve_context_and_filter_before_paging() {
    let bridge = RecordedBridge::new();
    let args = [
        "function",
        "var",
        "list",
        "main",
        "--filter",
        "kind=local",
        "--sort=-first_use",
        "--offset",
        "1",
        "--limit",
        "1",
        "--fields",
        "name,first_use",
    ];
    let output = bridge.command().args(args).output().unwrap();
    assert!(output.status.success(), "{output:?}");
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        result["data"],
        json!([{"name": "value", "first_use": "0x1010"}])
    );
    assert_eq!(result["meta"]["function"], "main");
    assert_eq!(result["meta"]["address"], "0x1000");
    assert_eq!(result["meta"]["program"], "A");
    assert_eq!(result["meta"]["modification"], "42");
    assert_eq!(result["meta"]["returned"], 1);
    assert_eq!(result["meta"]["offset"], 1);
    assert_eq!(
        bridge.run(&["function", "var", "list", "main", "--count"]),
        3
    );
    std::fs::write(
        bridge.root.path().join("variables.txt"),
        batch_arguments(&args),
    )
    .unwrap();
    let batch = bridge.run(&["batch", "variables.txt"]);
    assert_eq!(batch["results"][0]["result"], result);
    let requests = bridge.requests.lock().unwrap();
    for request in requests
        .iter()
        .filter(|r| r["command"] == "function_var_list")
    {
        assert_eq!(
            request["args"],
            json!({"target": "main", "timeout_secs": 0})
        );
    }
}

#[test]
fn variable_selection_sends_full_snapshot_and_keeps_filter_out_of_result_queries() {
    let bridge = RecordedBridge::new();
    for operation in ["get", "set"] {
        for batch in [false, true] {
            bridge.requests.lock().unwrap().clear();
            let mut args = vec![
                "function",
                "var",
                operation,
                "main",
                "--var",
                "value",
                "--filter",
                "kind=local",
                "--program",
                "B",
            ];
            if operation == "set" {
                args.extend(["--name", "length", "--fields", "after"]);
            }
            let receipt = if batch {
                std::fs::write(
                    bridge.root.path().join("selection.txt"),
                    batch_arguments(&args),
                )
                .unwrap();
                bridge.run(&["batch", "selection.txt"])["results"][0]["result"]["data"].clone()
            } else {
                bridge.run(&args)
            };
            if operation == "set" {
                assert_eq!(receipt, json!({"after": {"name": "length", "type": null}}));
            } else {
                assert_eq!(receipt["decompiler"]["name"], "value");
                assert_eq!(receipt["decompiler"]["kind"], "local");
                assert!(receipt["database"].is_null());
            }
            let requests = bridge.requests.lock().unwrap();
            let operations: Vec<_> = requests
                .iter()
                .filter(|r| r["command"].as_str().unwrap().starts_with("function_var_"))
                .collect();
            assert_eq!(operations.len(), 2);
            assert_eq!(operations[0]["command"], "function_var_list");
            assert_eq!(
                operations[1]["command"],
                format!("function_var_{operation}")
            );
            assert_eq!(operations[1]["args"]["var_name"], "value");
            assert_eq!(
                operations[1]["args"]["selection"],
                json!({
                    "program": "B", "function_address": "0x1000", "modification": "42",
                    "variable": {"name": "value", "kind": "local", "type": "int", "storage": "Stack[-0x8]:4", "ordinal": null, "first_use": "0x1010"},
                })
            );
            assert_eq!(operations[1]["args"]["timeout_secs"], 0);
        }
    }
}

#[test]
fn variable_selection_requires_exactly_one_same_name_candidate_before_mutation() {
    let bridge = RecordedBridge::new();
    for (filter, expected) in [
        ("kind=absent", "No variable named"),
        ("type=int", "matches 2 candidates"),
    ] {
        bridge.requests.lock().unwrap().clear();
        let output = bridge
            .command()
            .args([
                "function", "var", "set", "main", "--var", "value", "--filter", filter, "--name",
                "length",
            ])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(expected),
            "{output:?}"
        );
        let requests = bridge.requests.lock().unwrap();
        assert_eq!(
            requests
                .iter()
                .filter(|r| r["command"] == "function_var_list")
                .count(),
            1
        );
        assert!(requests.iter().all(|r| r["command"] != "function_var_set"));
    }
}

#[test]
fn function_edit_selectors_are_validated_before_program_selection_and_batch_execution() {
    let bridge = RecordedBridge::new();
    for args in [
        vec![
            "function",
            "set-body",
            "main",
            "--range",
            "0x1000",
            "overlay:1010",
        ],
        vec![
            "function",
            "call-signature",
            "clear",
            "main",
            "--at",
            "1010",
        ],
        vec![
            "function", "var", "set", "main", "--var", "value", "--filter", "invalid", "--name",
            "length",
        ],
    ] {
        let mut args = args;
        args.extend(["--program", "must-not-open"]);
        let output = bridge.command().args(&args).output().unwrap();
        assert!(!output.status.success(), "{args:?}");
        std::fs::write(
            bridge.root.path().join("invalid.txt"),
            batch_arguments(&args),
        )
        .unwrap();
        let output = bridge
            .command()
            .args(["batch", "invalid.txt"])
            .output()
            .unwrap();
        assert!(!output.status.success());
        let result: Value = crate::json_output::from_slice(&output.stdout).unwrap();
        assert_eq!(result["validation_failed"], true);
        assert_eq!(result["commands_executed"], 0);
        assert!(bridge.requests.lock().unwrap().is_empty());
    }
}
