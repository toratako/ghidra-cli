use super::{batch_arguments, call_graph_fixture, call_rows_fixture, RecordedBridge};
use serde_json::{json, Value};

#[test]
fn graph_calls_queries_select_nodes_and_keep_outgoing_edges_in_standalone_and_batch() {
    let bridge = RecordedBridge::new();
    let all = call_graph_fixture();
    let graph = |nodes: &[usize], edges: &[usize]| {
        json!([{
            "nodes": nodes.iter().map(|&i| all["nodes"][i].clone()).collect::<Vec<_>>(),
            "edges": edges.iter().map(|&i| all["edges"][i].clone()).collect::<Vec<_>>(),
            "node_count": nodes.len(),
            "edge_count": edges.len(),
        }])
    };
    let mut projected = graph(&[1, 2], &[1, 2, 3]);
    projected[0]["nodes"] = json!([{"name": "alpha"}, {"name": "beta"}]);
    for (flags, expected, fetch_limit) in [
        (vec![], graph(&[0], &[0]), json!(1)),
        (vec!["--limit", "0"], json!([all]), Value::Null),
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
                bridge.run(&["batch", "batch.txt"])[0]["results"][0]["result"].clone()
            } else {
                bridge.run(&args)
            };
            let expected = if batch && args.len() == 2 {
                &expected[0]
            } else {
                &expected
            };
            assert_eq!(&result, expected, "{args:?}, batch={batch}");
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
                "function", "edit-var", "main", "--var", "param_1", "--name", "input",
            ],
            "function_edit_var",
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
            let actual = &batch[0]["results"][0]["result"];
            if args.len() == 5 {
                assert_eq!(actual["calls"], expected);
                assert_eq!(actual["count"], 1);
            } else {
                assert_eq!(*actual, expected, "{args:?}: {batch}");
            }
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
                bridge.run(&["batch", "batch.txt"])[0]["results"][0]["result"].clone()
            } else {
                bridge.run(&args)[0].clone()
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
