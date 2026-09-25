use super::super::{batch_arguments, call_graph_fixture, call_rows_fixture, RecordedBridge};
use serde_json::{json, Value};

pub(crate) fn flow_fixture(high: bool, program: &str) -> Value {
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
