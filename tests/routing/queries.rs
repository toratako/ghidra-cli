use super::{api_list_fixture, batch_arguments, RecordedBridge};
use serde_json::{json, Value};

#[test]
fn bounded_queries_reject_oversized_limits_before_bridge_work() {
    let bridge = RecordedBridge::new();
    for args in [
        vec!["symbol", "externals"],
        vec!["symbol", "entry-points"],
        vec!["tag", "list"],
        vec!["graph", "calls"],
        vec!["graph", "callers", "main"],
        vec!["graph", "callees", "main"],
        vec!["find", "instruction", "CALL"],
    ] {
        for limit in ["2147483648", "4294967297"] {
            for selection in [vec![], vec!["--filter", "name~item"], vec!["--count"]] {
                let output = bridge
                    .command()
                    .args(&args)
                    .args(["--limit", limit])
                    .args(&selection)
                    .output()
                    .unwrap();
                assert!(
                    !output.status.success(),
                    "{args:?}, {selection:?}: {output:?}"
                );
                let error: Value = serde_json::from_slice(&output.stderr).unwrap();
                assert!(
                    error["message"]
                        .as_str()
                        .unwrap()
                        .contains("--limit must be between 0 and 2147483647"),
                    "{error}"
                );
                assert!(bridge.requests.lock().unwrap().is_empty());
            }
        }
    }
    for subcommand in ["callers", "callees"] {
        let output = bridge
            .command()
            .args(["graph", subcommand, "main", "--depth", "4294967297"])
            .output()
            .unwrap();
        assert!(!output.status.success());
        let error: Value = serde_json::from_slice(&output.stderr).unwrap();
        assert!(
            error["message"]
                .as_str()
                .unwrap()
                .contains("--depth must be between 0 and 2147483647"),
            "{error}"
        );
        assert!(bridge.requests.lock().unwrap().is_empty());
    }
}

#[test]
fn bounded_query_defaults_respect_count_and_explicit_unlimited() {
    let bridge = RecordedBridge::new();
    std::fs::write(
        bridge.root.path().join("config.yaml"),
        "default_limit: 2147483648\n",
    )
    .unwrap();
    for selection in [vec![], vec!["--filter", "name~a"]] {
        let output = bridge
            .command()
            .args(["graph", "calls"])
            .args(selection)
            .output()
            .unwrap();
        assert!(!output.status.success());
        let error: Value = serde_json::from_slice(&output.stderr).unwrap();
        assert!(
            error["message"]
                .as_str()
                .unwrap()
                .contains("--limit must be between 0 and 2147483647"),
            "{error}"
        );
        assert!(bridge.requests.lock().unwrap().is_empty());
    }
    assert_eq!(bridge.run(&["graph", "calls", "--count"]), 4);
    for limit in ["0", "2147483647"] {
        let result = bridge.run(&["graph", "calls", "--limit", limit]);
        assert_eq!(result["node_count"], 4);
    }
    // The list planner already supports checked 64-bit paging; keep that contract.
    bridge.run(&["function", "list", "--limit", "2147483648"]);
    let requests = bridge.requests.lock().unwrap();
    let list = requests
        .iter()
        .find(|request| request["command"] == "list_functions")
        .unwrap();
    assert_eq!(list["args"]["limit"], 2147483648_u64);
}

#[test]
fn external_symbols_and_entry_points_paginate_after_fetching_for_queries_and_batches() {
    let bridge = RecordedBridge::new();
    let command = "symbol";
    for kind in ["externals", "entry-points"] {
        let args = [command, kind, "--skip", "1", "--limit", "1"];
        assert_eq!(bridge.run(&args), json!([{"name": "second"}]));
        std::fs::write(bridge.root.path().join("batch.txt"), args.join(" ")).unwrap();
        assert_eq!(
            bridge.run(&["batch", "batch.txt"])["results"][0]["result"]["data"],
            json!([{"name": "second"}])
        );
        assert_eq!(bridge.run(&[command, kind, "--count"]), json!(2));
    }
}

#[test]
fn default_limit_is_applied_after_client_row_selection_for_standalone_and_batch() {
    let bridge = RecordedBridge::new();
    let command = ["function", "list"];
    for (flags, expected) in [
        (
            vec!["--filter", "size>0"],
            json!([{"name": "small", "size": 10}]),
        ),
        (vec!["--sort=-size"], json!([{"name": "large", "size": 30}])),
        (vec!["--skip", "1"], json!([{"name": "small", "size": 10}])),
        (
            vec!["--filter", "size>0", "--sort=-size", "--skip", "1"],
            json!([{"name": "medium", "size": 20}]),
        ),
        (
            vec![
                "--filter",
                "size>0",
                "--sort=-size",
                "--skip",
                "1",
                "--limit",
                "0",
            ],
            json!([{"name": "medium", "size": 20}, {"name": "small", "size": 10}]),
        ),
        (vec!["--filter", "size>0", "--count"], json!(3)),
    ] {
        let args: Vec<_> = command.iter().chain(flags.iter()).copied().collect();
        for batch in [false, true] {
            bridge.requests.lock().unwrap().clear();
            let result = if batch {
                std::fs::write(bridge.root.path().join("batch.txt"), args.join(" ")).unwrap();
                bridge.run(&["batch", "batch.txt"])["results"][0]["result"]["data"].clone()
            } else {
                bridge.run(&args)
            };
            assert_eq!(result, expected, "{args:?}, batch={batch}");
            let requests = bridge.requests.lock().unwrap();
            let lists: Vec<_> = requests
                .iter()
                .filter(|r| r["command"] == "list_functions")
                .collect();
            assert_eq!(lists.len(), 1);
            if flags == ["--skip", "1"] {
                assert_eq!(lists[0]["args"]["offset"], 1);
                assert_eq!(lists[0]["args"]["limit"], 1);
            } else {
                assert!(lists[0]["args"]["limit"].is_null(), "{lists:?}");
            }
        }
    }
}

#[test]
fn contains_and_offset_share_one_plan_for_standalone_and_batch() {
    let bridge = RecordedBridge::new();
    let command = ["function", "list"];
    for (flags, expected, server_limit, server_offset) in [
        (
            vec!["--filter", "name~L", "--skip", "1"],
            json!([{"name":"small", "size":10}]),
            json!(1),
            json!(1),
        ),
        (
            vec!["--filter", "name~L", "--skip", "1", "--limit", "0"],
            json!([{"name":"small", "size":10}, {"name":"large", "size":30}]),
            json!(null),
            json!(1),
        ),
        (
            vec![
                "--filter",
                "name~L",
                "--skip",
                "1",
                "--exclude-fields",
                "size",
            ],
            json!([{"name":"small"}]),
            json!(1),
            json!(1),
        ),
        (
            vec!["--filter", "name~L", "--skip", "1", "--count"],
            json!(2),
            json!(null),
            json!(null),
        ),
        (
            vec![
                "--filter",
                "name~L",
                "--sort=-size",
                "--fields",
                "name",
                "--skip",
                "1",
            ],
            json!([{"name":"small"}]),
            json!(null),
            json!(null),
        ),
    ] {
        let args: Vec<_> = command.iter().chain(flags.iter()).copied().collect();
        for batch in [false, true] {
            bridge.requests.lock().unwrap().clear();
            let actual = if batch {
                std::fs::write(bridge.root.path().join("batch.txt"), args.join(" ")).unwrap();
                bridge.run(&["batch", "batch.txt"])["results"][0]["result"]["data"].clone()
            } else {
                bridge.run(&args)
            };
            assert_eq!(actual, expected, "{args:?}, batch={batch}");
            let requests = bridge.requests.lock().unwrap();
            let list = requests
                .iter()
                .find(|r| r["command"] == "list_functions")
                .unwrap();
            assert_eq!(list["args"]["filter"], "L");
            assert_eq!(list["args"]["limit"], server_limit);
            assert_eq!(list["args"]["offset"], server_offset);
        }
    }
}

#[test]
fn unsupported_list_offset_fetches_enough_rows() {
    let bridge = RecordedBridge::new();
    for command in [vec!["symbol", "externals"], vec!["symbol", "entry-points"]] {
        let args: Vec<_> = command
            .into_iter()
            .chain(["--skip", "1", "--limit", "1"])
            .collect();
        assert_eq!(bridge.run(&args), json!([{"name":"second"}]));
    }
    for list in bridge
        .requests
        .lock()
        .unwrap()
        .iter()
        .filter(|r| r["command"] == "symbol_externals" || r["command"] == "symbol_entry_points")
    {
        assert!(list["args"]["limit"].is_null());
    }
}

#[test]
fn client_only_queries_apply_defaults_with_and_without_query_flags() {
    let bridge = RecordedBridge::new();
    for (configured, cap) in [("2", 2), ("0", 3), ("null", 3)] {
        std::fs::write(
            bridge.root.path().join("config.yaml"),
            format!("default_limit: {configured}\n"),
        )
        .unwrap();
        let (command, wire) = (vec!["memory", "map"], "memory_map");
        for (flags, count, first) in [
            (vec![], cap, "first"),
            (vec!["--json"], cap, "first"),
            (vec!["--format", "json"], cap, "first"),
            (vec!["--fields", "name"], cap, "first"),
            (vec!["--limit", "0"], 3, "first"),
            (vec!["--limit", "1"], 1, "first"),
            (vec!["--sort=-name"], cap, "third"),
            (vec!["--skip", "1"], 2, "second"),
            (vec!["--filter", "name=third"], 1, "third"),
            (vec!["--count"], 3, ""),
            (vec!["--count", "--skip", "1", "--limit", "1"], 1, ""),
        ] {
            for batch in [false, true] {
                let mut args = command.clone();
                args.extend(&flags);
                let result = if batch {
                    std::fs::write(bridge.root.path().join("batch.txt"), batch_arguments(&args))
                        .unwrap();
                    bridge.run(&["batch", "batch.txt"])["results"][0]["result"]["data"].clone()
                } else {
                    bridge.run(&args)
                };
                if flags.contains(&"--count") {
                    assert_eq!(result, count);
                } else {
                    let rows = &result;
                    assert_eq!(
                        rows.as_array().unwrap().len(),
                        count,
                        "{args:?}, default={configured}, batch={batch}"
                    );
                    assert_eq!(rows[0]["name"], first);
                }
            }
        }
        let requests = bridge.requests.lock().unwrap();
        assert!(requests
            .iter()
            .filter(|r| r["command"] == wire)
            .all(|r| r["args"]["limit"].is_null()));
    }
}

#[test]
fn api_lists_fetch_all_rows_before_standalone_and_batch_queries() {
    let bridge = RecordedBridge::new();
    for (command, wire, field) in [
        (vec!["bookmark", "list"], "bookmark_list", "comment"),
        (
            vec!["bookmark", "get", "overlay:0x1000"],
            "bookmark_get",
            "comment",
        ),
        (
            vec!["program", "list-relocations"],
            "program_list_relocations",
            "symbol_name",
        ),
        (
            vec!["function", "list-calling-conventions"],
            "function_list_calling_conventions",
            "name",
        ),
    ] {
        let (_key, rows) = api_list_fixture(wire);
        let filter = format!("{field}=beta");
        for (flags, expected) in [
            (vec![], json!([rows[0]])),
            (vec!["--limit", "0"], json!(rows)),
            (vec!["--limit", "2"], json!([rows[0], rows[1]])),
            (vec!["--filter", &filter], json!([rows[2]])),
            (vec!["--skip", "1"], json!([rows[1]])),
            (vec!["--sort", field], json!([rows[1]])),
            (vec!["--count"], json!(3)),
            (vec!["--filter", &filter, "--count"], json!(1)),
            (vec!["--skip", "1", "--limit", "1", "--count"], json!(1)),
            (
                vec![
                    "--sort", field, "--skip", "1", "--limit", "1", "--fields", field,
                ],
                json!([{field: "beta"}]),
            ),
        ] {
            let args: Vec<_> = command
                .iter()
                .copied()
                .chain(["--program", "B"])
                .chain(flags.iter().copied())
                .collect();
            for batch in [false, true] {
                bridge.requests.lock().unwrap().clear();
                let actual = if batch {
                    std::fs::write(bridge.root.path().join("batch.txt"), batch_arguments(&args))
                        .unwrap();
                    bridge.run(&["batch", "batch.txt"])["results"][0]["result"]["data"].clone()
                } else {
                    bridge.run(&args)
                };
                let expected = expected.clone();
                assert_eq!(actual, expected, "{args:?}, batch={batch}");
                let requests = bridge.requests.lock().unwrap();
                let domain: Vec<_> = requests
                    .iter()
                    .filter(|r| r["command"] != "bridge_info")
                    .collect();
                assert_eq!(domain.len(), 1, "{domain:?}");
                assert_eq!(domain[0]["program"], "B");
                assert_eq!(domain[0]["command"], wire);
                if wire == "bookmark_get" {
                    assert_eq!(domain[0]["args"], json!({"address": "overlay:0x1000"}));
                } else {
                    assert!(domain[0].get("args").is_none());
                }
            }
        }
        let output = bridge
            .command()
            .args(command)
            .args(["--format", "compact", "--limit", "0"])
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(
            text.contains("zeta") && text.contains("alpha") && text.contains("beta"),
            "{text}"
        );
    }
}
