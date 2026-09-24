use super::{batch_arguments, call_graph_fixture, call_rows_fixture, RecordedBridge};
use serde_json::{json, Value};

pub(super) fn flow_fixture(high: bool, program: &str) -> Value {
    let mut result = json!({
        "representation": if high { "high_pcode" } else { "instruction_cfg" },
        "result_id": "flow-result",
        "id_scope": "result",
        "project": {"location": "/projects", "name": "project"},
        "program": program, "modification": "42", "function": "main", "address": "0x1000",
        "body_ranges": [{"start": "0x1000", "end": "0x1010"}, {"start": "0x2000", "end": "0x2010"}],
        "limits": {"max_nodes": 1000, "max_edges": 4000},
        "completion": {"complete": false, "reasons": ["max_edges"], "returned_nodes": 2, "returned_edges": 2},
        "edges": [
            {"id": "e0", "from": "b0", "to": "b1", "kind": "fallthrough"},
            {"id": "e1", "from": "b1", "to": {"state": "omitted", "id": "b2"}, "kind": "conditional"}
        ]
    });
    if high {
        result["operations"] = json!([
            {"id": "op0", "opcode": "INT_ADD", "inputs": [{"slot": 0, "value": "v0"}, {"slot": 1, "value": "v0"}], "output": "v1"},
            {"id": "op1", "opcode": "RETURN", "inputs": [{"slot": 0, "value": "v1"}], "output": null}
        ]);
        result["values"] = json!([
            {"id": "v0", "definition": null, "uses": [{"operation": "op0", "slot": 0}, {"operation": "op0", "slot": 1}]},
            {"id": "v1", "definition": "op0", "uses": [{"operation": "op1", "slot": 0}]}
        ]);
        result["blocks"] = json!([
            {"id": "b0", "operations": ["op0"]}, {"id": "b1", "operations": ["op1"]}
        ]);
        result["high_variables"] = json!([{"id": "h0", "values": ["v0", "v1"]}]);
        result["symbols"] = json!([]);
    } else {
        result["nodes"] = json!([
            {"id": "b0", "entries": ["0x1000"], "ranges": [{"start": "0x1000", "end": "0x1010"}]},
            {"id": "b1", "entries": ["0x2000"], "ranges": [{"start": "0x2000", "end": "0x2010"}]}
        ]);
        result["calls"] = json!([
            {"block": "b0", "address": "0x1004", "target": "0x3000"},
            {"block": "b1", "address": "0x2004", "target": null, "state": "unresolved"}
        ]);
        result["boundaries"] = json!([
            {"block": "b1", "address": "0x2010", "kind": "return"}
        ]);
    }
    result
}

#[test]
fn flow_commands_preserve_complete_objects_and_limits_in_standalone_and_batch() {
    let bridge = RecordedBridge::new();
    for (base, wire, high) in [
        (vec!["graph", "cfg", "main"], "graph_cfg", false),
        (
            vec!["pcode", "function", "main", "--high"],
            "pcode_function",
            true,
        ),
    ] {
        for (flags, max_nodes, max_edges) in [
            (vec![], 1000, 4000),
            (vec!["--max-nodes", "37", "--max-edges", "53"], 37, 53),
        ] {
            for batch in [false, true] {
                bridge.requests.lock().unwrap().clear();
                let args: Vec<_> = base
                    .iter()
                    .copied()
                    .chain(flags.iter().copied())
                    .chain(["--program", "B"])
                    .collect();
                let result = if batch {
                    std::fs::write(bridge.root.path().join("flow.txt"), batch_arguments(&args))
                        .unwrap();
                    bridge.run(&["batch", "flow.txt"])["results"][0]["result"]["data"].clone()
                } else {
                    bridge.run(&args)
                };
                assert_eq!(result, flow_fixture(high, "B"), "{args:?}, batch={batch}");
                let mut expected = json!({
                    "function": "main", "max_nodes": max_nodes, "max_edges": max_edges,
                });
                if high {
                    expected["high"] = json!(true);
                    expected["timeout_secs"] = json!(0);
                }
                let requests = bridge.requests.lock().unwrap();
                let operations: Vec<_> = requests.iter().filter(|r| r["command"] == wire).collect();
                assert_eq!(operations.len(), 1);
                assert_eq!(operations[0]["args"], expected, "{args:?}, batch={batch}");
                assert!(requests
                    .iter()
                    .filter(|r| r["command"] != "bridge_info")
                    .all(|r| r["program"] == "B"));
            }
        }
    }
}

#[test]
fn raw_pcode_keeps_listing_request_and_ignores_decompiler_configuration() {
    let bridge = RecordedBridge::new();
    let output = bridge
        .command()
        .env("GHIDRA_CLI_DECOMPILE_TIMEOUT", "invalid")
        .args(["pcode", "function", "main"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let requests = bridge.requests.lock().unwrap();
    let requests: Vec<_> = requests
        .iter()
        .filter(|r| r["command"] == "pcode_function")
        .collect();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0]["args"],
        json!({"function": "main", "high": false})
    );
}

#[test]
fn invalid_flow_limits_fail_before_standalone_or_batch_dispatch() {
    let bridge = RecordedBridge::new();
    for args in [
        vec!["graph", "cfg", "main", "--max-nodes", "0"],
        vec![
            "pcode",
            "function",
            "main",
            "--high",
            "--max-edges",
            "2147483648",
        ],
        vec!["pcode", "function", "main", "--max-nodes", "4"],
    ] {
        assert!(!bridge
            .command()
            .args(&args)
            .output()
            .unwrap()
            .status
            .success());
        std::fs::write(
            bridge.root.path().join("invalid-flow.txt"),
            batch_arguments(&args),
        )
        .unwrap();
        let output = bridge
            .command()
            .args(["batch", "invalid-flow.txt"])
            .output()
            .unwrap();
        assert!(!output.status.success());
        let result: Value = crate::json_output::from_slice(&output.stdout).unwrap();
        assert_eq!(result["validation_failed"], true);
        assert_eq!(result["commands_executed"], 0);
        assert!(bridge.requests.lock().unwrap().is_empty());
    }
}

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
        (vec!["--skip", "1"], graph(&[1], &[1, 2]), Value::Null),
        (
            vec!["--filter", "name=beta"],
            graph(&[2], &[3]),
            Value::Null,
        ),
        (
            vec![
                "--filter", "name~a", "--sort", "name", "--skip", "1", "--limit", "2",
            ],
            graph(&[2, 3], &[3, 4]),
            Value::Null,
        ),
        (
            vec!["--sort=-name", "--skip", "1", "--limit", "0"],
            graph(&[3, 2, 1], &[1, 2, 3, 4]),
            Value::Null,
        ),
        (
            vec!["--sort", "name", "--limit", "2", "--fields", "name"],
            projected.clone(),
            Value::Null,
        ),
        (
            vec![
                "--sort",
                "name",
                "--limit",
                "2",
                "--exclude-fields=id,address",
            ],
            projected,
            Value::Null,
        ),
        (vec!["--skip", "99"], graph(&[], &[]), Value::Null),
        (
            vec!["--filter", "name=absent"],
            graph(&[], &[]),
            Value::Null,
        ),
        (vec!["--count"], json!(4), Value::Null),
        (
            vec!["--skip", "1", "--limit", "2", "--count"],
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
            vec!["function", "var", "infer-struct", "main", "--var", "value"],
            "function_var_infer_struct",
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
                vec!["--sort", "-call_site", "--skip", "1", "--limit", "1"],
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
            assert!(result.get("line_addresses").is_none());
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
                json!({"address": "main", "with_vars": false, "with_params": false, "with_jump_tables": with_jump_tables, "with_addresses": false, "timeout_secs": 0})
            );
        }
    }
}

#[test]
fn decompile_line_addresses_preserve_raw_code_projection_and_batch_output() {
    let bridge = RecordedBridge::new();
    for fields in [None, Some("code,line_addresses"), Some("code")] {
        for batch in [false, true] {
            bridge.requests.lock().unwrap().clear();
            let mut args = vec!["decompile", "main", "--with-addresses", "--program", "B"];
            if let Some(fields) = fields {
                args.extend(["--fields", fields]);
            }
            let result = if batch {
                std::fs::write(
                    bridge.root.path().join("addresses.txt"),
                    batch_arguments(&args),
                )
                .unwrap();
                bridge.run(&["batch", "addresses.txt"])["results"][0]["result"]["data"].clone()
            } else {
                bridge.run(&args)
            };
            assert_eq!(result["code"], "int main(void) {\n  return 0;\n}\n");
            if fields == Some("code") {
                assert!(result.get("line_addresses").is_none());
            } else {
                assert_eq!(
                    result["line_addresses"],
                    json!([{"line": 2, "addresses": ["0x1004", "0x1008"]}])
                );
            }
            let requests = bridge.requests.lock().unwrap();
            let operations: Vec<_> = requests
                .iter()
                .filter(|r| r["command"] == "decompile")
                .collect();
            assert_eq!(operations.len(), 1);
            assert_eq!(operations[0]["program"], "B");
            assert_eq!(
                operations[0]["args"],
                json!({"address": "main", "with_vars": false, "with_params": false,
                    "with_jump_tables": false, "with_addresses": true, "timeout_secs": 0})
            );
        }
    }
}

#[test]
fn signature_type_bindings_preserve_pairs_and_duplicates_in_standalone_and_batch() {
    let bridge = RecordedBridge::new();
    for (base, wire, mut expected) in [
        (
            vec!["function", "set-signature", "entry"],
            "function_set_signature",
            json!({"target": "entry"}),
        ),
        (
            vec![
                "function",
                "call-signature",
                "set",
                "entry",
                "--at",
                "0x1010",
            ],
            "function_call_signature_set",
            json!({"target": "entry", "at": "0x1010", "convention": null}),
        ),
    ] {
        expected["signature"] = json!("void entry(Profile *base, Cmp compare)");
        for bound in [false, true] {
            let mut args = base.clone();
            args.extend([
                "--signature",
                "void entry(Profile *base, Cmp compare)",
                "--program",
                "B",
            ]);
            if bound {
                args.extend([
                    "--bind-type",
                    "Profile",
                    "/Recovered Types/Profile",
                    "--bind-type",
                    "Cmp",
                    "/Recovered/Cmp",
                    "--bind-type",
                    "Cmp",
                    "/Other/Cmp",
                ]);
                expected["type_bindings"] = json!([
                    {"name": "Profile", "path": "/Recovered Types/Profile"},
                    {"name": "Cmp", "path": "/Recovered/Cmp"},
                    {"name": "Cmp", "path": "/Other/Cmp"},
                ]);
            }
            for batch in [false, true] {
                bridge.requests.lock().unwrap().clear();
                if batch {
                    std::fs::write(
                        bridge.root.path().join("signatures.txt"),
                        batch_arguments(&args),
                    )
                    .unwrap();
                    bridge.run(&["batch", "signatures.txt"]);
                } else {
                    bridge.run(&args);
                }
                let requests = bridge.requests.lock().unwrap();
                let edits: Vec<_> = requests.iter().filter(|r| r["command"] == wire).collect();
                assert_eq!(edits.len(), 1);
                assert_eq!(edits[0]["args"], expected);
                assert_eq!(edits[0]["program"], "B");
            }
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
                .filter(|r| r["command"] != "bridge_info")
                .all(|r| r["program"] == "B"));
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
        "--skip",
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
    assert_eq!(
        result["meta"]["project"],
        json!({"location":"/projects","name":"project"})
    );
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
fn variable_selection_sends_full_snapshot_and_keeps_selector_out_of_result_queries() {
    let bridge = RecordedBridge::new();
    for operation in ["get", "set", "infer-struct"] {
        for batch in [false, true] {
            bridge.requests.lock().unwrap().clear();
            let mut args = vec![
                "function",
                "var",
                operation,
                "main",
                "--var",
                "value",
                "--where",
                "kind=local",
                "--program",
                "B",
            ];
            if operation == "set" {
                args.extend(["--name", "length", "--fields", "after"]);
            } else if operation == "infer-struct" {
                args.extend(["--with-accesses", "--max-accesses", "0x1"]);
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
            } else if operation == "infer-struct" {
                assert_eq!(receipt["variable"]["name"], "value");
                assert_eq!(receipt["structure"]["components"][0]["offset"], 16);
                assert_eq!(receipt["accesses_status"]["truncated"], true);
                assert_eq!(receipt["accesses"].as_array().unwrap().len(), 1);
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
            assert!(operations.iter().all(|r| r["program"] == "B"));
            assert_eq!(operations[0]["command"], "function_var_list");
            assert_eq!(
                operations[1]["command"],
                format!("function_var_{}", operation.replace('-', "_"))
            );
            assert_eq!(operations[1]["args"]["var_name"], "value");
            assert_eq!(
                operations[1]["args"]["selection"],
                json!({
                    "project": {"location": "/projects", "name": "project"},
                    "program": "B", "function_address": "0x1000", "modification": "42",
                    "variable": {"name": "value", "kind": "local", "type": "int", "storage": "Stack[-0x8]:4", "ordinal": null, "first_use": "0x1010"},
                })
            );
            assert_eq!(operations[1]["args"]["timeout_secs"], 0);
            if operation == "infer-struct" {
                assert_eq!(operations[1]["args"]["with_accesses"], true);
                assert_eq!(operations[1]["args"]["max_accesses"], 1);
            }
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
                "function", "var", "set", "main", "--var", "value", "--where", filter, "--name",
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
            "function",
            "set-signature",
            "main",
            "--signature",
            "void main(void)",
            "--bind-type",
            "Bad-Name",
            "/Recovered/Profile",
        ],
        vec![
            "function",
            "call-signature",
            "set",
            "main",
            "--at",
            "0x1010",
            "--signature",
            "void callback(void)",
            "--bind-type",
            "Profile",
            "Recovered/Profile",
        ],
        vec![
            "function",
            "set-signature",
            "main",
            "--signature",
            "void main(void)",
            "--bind-type",
            "Profile",
            "/Recovered/",
        ],
        vec![
            "function", "var", "set", "main", "--var", "value", "--where", "invalid", "--name",
            "length",
        ],
        vec![
            "function",
            "var",
            "infer-struct",
            "main",
            "--var",
            "value",
            "--where",
            "invalid",
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
