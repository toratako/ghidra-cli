use super::{batch_arguments, run_envelope, RecordedBridge};
use serde_json::{json, Value};

pub(crate) fn category_list_fixture(args: &Value) -> Value {
    let path = args["path"].as_str().unwrap();
    let categories = if path == "/Empty" {
        vec![]
    } else {
        [("zeta", 0), ("alpha", 2), ("beta", 1)]
            .into_iter()
            .map(|(name, type_count)| {
                json!({
                    "name": name, "path": format!("{}/{name}", path.trim_end_matches('/')),
                    "type_count": type_count,
                })
            })
            .collect()
    };
    json!({"path": path, "categories": categories})
}

pub(crate) fn uses_fixture(args: &Value) -> Value {
    let mut rows = if args["type_name"] == "/Unused" {
        vec![]
    } else if args["kind"] == "variable" {
        vec![
            json!({"kind":"variable", "role":"parameter", "function":"process", "name":"ctx", "address":"0x1000"}),
            json!({"kind":"variable", "role":"local", "function":"process", "name":"zeta", "address":"0x1000"}),
            json!({"kind":"variable", "role":"local", "function":"process", "name":"alpha", "address":"0x1000"}),
        ]
    } else {
        vec![
            json!({"kind":"data", "name":"zeta", "address":"0x2000"}),
            json!({"kind":"data", "name":"alpha", "address":"0x2040"}),
            json!({"kind":"signature", "role":"return", "function":"process", "name":"result", "address":"0x1000"}),
            json!({"kind":"signature", "role":"parameter", "function":"process", "name":"ctx", "address":"0x1000"}),
        ]
    };
    if let Some(kind) = args["kind"].as_str() {
        rows.retain(|row| row["kind"] == kind);
    }
    let count = rows.len();
    if let Some(limit) = args["limit"].as_u64().filter(|limit| *limit != 0) {
        rows.truncate(limit as usize);
    }
    let complete = rows.len() == count;
    let mut result = json!({"uses":rows, "target_type_path":args["type_name"],
        "kinds":args["kind"].as_str().map_or(json!(["data", "signature"]), |kind| json!([kind])),
        "scan":{"complete":complete, "stop_reason":if complete { Value::Null } else { json!("limit") }}});
    if args["kind"] == "variable" {
        result["scope"] = semantic_scope(args);
    }
    result
}

fn semantic_scope(args: &Value) -> Value {
    args["function"].as_str().map_or(
        Value::Null,
        |function| json!({"function":function, "address":"0x1000"}),
    )
}

pub(crate) fn field_uses_fixture(args: &Value) -> Value {
    let mut uses = vec![
        json!({"function":"process", "instruction_address":"0x1010", "access":"read"}),
        json!({"function":"process", "instruction_address":"0x1020", "access":"write"}),
        json!({"function":"process", "instruction_address":"0x1030", "access":"address"}),
    ];
    let count = uses.len();
    if let Some(limit) = args["limit"].as_u64().filter(|limit| *limit != 0) {
        uses.truncate(limit as usize);
    }
    let complete = uses.len() == count;
    json!({"uses":uses, "target_type_path":args["type_name"],
        "target_field":{"name":"flags", "offset":16, "ordinal":2},
        "scope":semantic_scope(args),
        "scan":{"complete":complete, "stop_reason":if complete { Value::Null } else { json!("limit") }}})
}

#[test]
fn type_uses_queries_preserve_scope_completion_and_standalone_batch_results() {
    let outer = RecordedBridge::new();
    let selected = RecordedBridge::new();
    for (query, expected, fetch_limit, kind) in [
        (
            vec!["--limit", "1", "--fields", "name"],
            json!([{"name":"zeta"}]),
            json!(1),
            Value::Null,
        ),
        (
            vec![
                "--filter",
                "kind=signature AND role=parameter",
                "--limit",
                "1",
                "--fields",
                "name",
            ],
            json!([{"name":"ctx"}]),
            Value::Null,
            Value::Null,
        ),
        (
            vec![
                "--kind", "data", "--sort", "name", "--skip", "1", "--limit", "1", "--fields",
                "name",
            ],
            json!([{"name":"zeta"}]),
            Value::Null,
            json!("data"),
        ),
        (
            vec!["--kind", "signature", "--count"],
            json!(2),
            Value::Null,
            json!("signature"),
        ),
        (
            vec![
                "--kind",
                "signature",
                "--skip",
                "1",
                "--limit",
                "1",
                "--count",
            ],
            json!(1),
            Value::Null,
            json!("signature"),
        ),
        (
            vec!["--filter", "name=absent"],
            json!([]),
            Value::Null,
            Value::Null,
        ),
    ] {
        let mut standalone = Value::Null;
        for batch in [false, true] {
            selected.requests.lock().unwrap().clear();
            let mut args = vec!["type", "uses", "/Widget"];
            args.extend(query.iter().copied());
            args.extend([
                "--project",
                selected.project.to_str().unwrap(),
                "--program",
                "B",
            ]);
            let output = run_envelope(&outer, &args, batch);
            assert_eq!(output["data"], expected, "{args:?}: {output}");
            assert_eq!(output["meta"]["target_type_path"], "/Widget");
            assert_eq!(output["meta"]["scan"]["complete"], fetch_limit.is_null());
            assert_eq!(
                output["meta"]["kinds"],
                kind.as_str()
                    .map_or(json!(["data", "signature"]), |kind| json!([kind]))
            );
            if batch {
                assert_eq!(output, standalone);
            } else {
                standalone = output;
            }
            let requests = selected.requests.lock().unwrap();
            let domain: Vec<_> = requests
                .iter()
                .filter(|r| r["command"] != "bridge_info")
                .collect();
            assert_eq!(domain.len(), 1);
            assert_eq!(domain[0]["program"], "B");
            assert_eq!(domain[0]["command"], "type_uses");
            assert_eq!(
                domain[0]["args"],
                json!({"type_name":"/Widget", "kind":kind, "limit":fetch_limit})
            );
        }
    }
    let empty = run_envelope(&selected, &["type", "uses", "/Unused"], false);
    assert_eq!(empty["data"], json!([]));
    assert_eq!(empty["meta"]["scan"]["complete"], true);
    for format in ["compact", "full"] {
        let output = selected
            .command()
            .args([
                "type", "uses", "/Widget", "--limit", "1", "--format", format,
            ])
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(
            text.contains("Type uses: /Widget (data, signature)"),
            "{text}"
        );
        assert!(text.contains("Scan stopped at the result limit"), "{text}");
    }
    let ndjson = selected
        .command()
        .args([
            "type",
            "uses",
            "/Widget",
            "--kind",
            "signature",
            "--limit",
            "0",
            "--format",
            "ndjson",
            "--fields",
            "name",
        ])
        .output()
        .unwrap();
    assert!(ndjson.status.success(), "{ndjson:?}");
    assert_eq!(
        String::from_utf8(ndjson.stdout)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>(),
        vec![json!({"name":"result"}), json!({"name":"ctx"})]
    );
}

#[test]
fn semantic_type_queries_preserve_scope_pagination_and_batch_results() {
    let outer = RecordedBridge::new();
    let selected = RecordedBridge::new();
    for (command, wire, fields, filter, sort, expected_filtered) in [
        (
            vec!["type", "uses", "/Widget", "--kind", "variable"],
            "type_uses",
            "name",
            "role=local",
            "name",
            json!([{"name":"zeta"}]),
        ),
        (
            vec!["type", "field", "uses", "/Widget", "--field", "flags"],
            "type_field_uses",
            "access",
            "access!=address",
            "-instruction_address",
            json!([{"access":"read"}]),
        ),
    ] {
        let first = if wire == "type_uses" {
            json!([{"name":"ctx"}])
        } else {
            json!([{"access":"read"}])
        };
        for (query, expected, fetch_limit) in [
            (vec!["--limit", "1", "--fields", fields], first, json!(1)),
            (
                vec![
                    "--filter", filter, "--sort", sort, "--skip", "1", "--limit", "1", "--fields",
                    fields,
                ],
                expected_filtered,
                Value::Null,
            ),
            (vec!["--count"], json!(3), Value::Null),
            (
                vec!["--skip", "1", "--limit", "1", "--count"],
                json!(1),
                Value::Null,
            ),
        ] {
            let mut standalone = Value::Null;
            for batch in [false, true] {
                selected.requests.lock().unwrap().clear();
                let mut args = command.clone();
                args.extend(query.iter().copied());
                args.extend([
                    "--function",
                    "process",
                    "--project",
                    selected.project.to_str().unwrap(),
                    "--program",
                    "B",
                ]);
                let output = run_envelope(&outer, &args, batch);
                assert_eq!(output["data"], expected, "{args:?}: {output}");
                assert_eq!(output["meta"]["target_type_path"], "/Widget");
                assert_eq!(
                    output["meta"]["scope"],
                    json!({"function":"process", "address":"0x1000"})
                );
                assert_eq!(output["meta"]["scan"]["complete"], fetch_limit.is_null());
                if wire == "type_uses" {
                    assert_eq!(output["meta"]["kinds"], json!(["variable"]));
                } else {
                    assert_eq!(
                        output["meta"]["target_field"],
                        json!({"name":"flags", "offset":16, "ordinal":2})
                    );
                }
                if batch {
                    assert_eq!(output, standalone);
                } else {
                    standalone = output;
                }
                let requests = selected.requests.lock().unwrap();
                let requests: Vec<_> = requests
                    .iter()
                    .filter(|r| r["command"] != "bridge_info")
                    .collect();
                assert_eq!(requests.len(), 1);
                assert_eq!(requests[0]["program"], "B");
                assert_eq!(requests[0]["command"], wire);
                let mut expected_args = json!({"type_name":"/Widget", "function":"process", "limit":fetch_limit, "timeout_secs":0});
                if wire == "type_uses" {
                    expected_args["kind"] = json!("variable");
                } else {
                    expected_args["field"] = json!("flags");
                    expected_args["offset"] = Value::Null;
                    expected_args["ordinal"] = Value::Null;
                }
                assert_eq!(requests[0]["args"], expected_args);
            }
        }
    }
}

#[test]
fn semantic_type_queries_use_native_timeout_and_preserve_field_selectors() {
    let bridge = RecordedBridge::new();
    for (args, wire, selector) in [
        (
            vec!["type", "uses", "/Widget", "--kind", "variable"],
            "type_uses",
            None,
        ),
        (
            vec!["type", "field", "uses", "/Widget", "--offset", "0x10"],
            "type_field_uses",
            Some(("offset", 16)),
        ),
        (
            vec!["type", "field", "uses", "/Widget", "--ordinal", "02"],
            "type_field_uses",
            Some(("ordinal", 2)),
        ),
    ] {
        bridge.requests.lock().unwrap().clear();
        let output = bridge
            .command()
            .env("GHIDRA_CLI_DECOMPILE_TIMEOUT", "47")
            .args(&args)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let result: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(result["meta"]["scope"], Value::Null);
        let requests = bridge.requests.lock().unwrap();
        let request = requests.iter().find(|r| r["command"] == wire).unwrap();
        assert_eq!(request["args"]["timeout_secs"], 47);
        assert_eq!(request["args"]["function"], Value::Null);
        if let Some((key, expected)) = selector {
            assert_eq!(request["args"][key], expected);
        }
        drop(requests);
        bridge.requests.lock().unwrap().clear();
        let output = bridge
            .command()
            .env("GHIDRA_CLI_DECOMPILE_TIMEOUT", "invalid")
            .args(&args)
            .output()
            .unwrap();
        assert!(!output.status.success(), "{output:?}");
        assert!(bridge
            .requests
            .lock()
            .unwrap()
            .iter()
            .all(|r| r["command"] != wire));
    }
    let output = bridge
        .command()
        .env("GHIDRA_CLI_DECOMPILE_TIMEOUT", "invalid")
        .args(["type", "uses", "/Widget"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
}

#[test]
fn database_type_uses_reject_function_scope_before_bridge_work() {
    let bridge = RecordedBridge::new();
    for kind in ["data", "signature"] {
        let args = [
            "type",
            "uses",
            "/Widget",
            "--kind",
            kind,
            "--function",
            "process",
        ];
        for batch in [false, true] {
            let output = if batch {
                std::fs::write(bridge.root.path().join("batch.txt"), batch_arguments(&args))
                    .unwrap();
                bridge
                    .command()
                    .args(["batch", "batch.txt"])
                    .output()
                    .unwrap()
            } else {
                bridge.command().args(args).output().unwrap()
            };
            assert!(!output.status.success(), "{args:?}: {output:?}");
            if batch {
                let result: Value = serde_json::from_slice(&output.stdout).unwrap();
                assert_eq!(result["data"]["commands_executed"], 0);
            } else {
                assert!(String::from_utf8(output.stderr)
                    .unwrap()
                    .contains("--function requires --kind variable"));
            }
            assert!(bridge.requests.lock().unwrap().is_empty());
        }
    }
}
