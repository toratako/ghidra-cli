use super::{batch_arguments, RecordedBridge};
use serde_json::{json, Value};

pub(super) fn fixture(args: &Value) -> Value {
    let mut calls: Vec<_> = ["table_value", "table_type", "slot_offset", "table_value"]
        .into_iter()
        .enumerate()
        .map(|(i, evidence)| {
            json!({
                "caller":"dispatch", "caller_address":"0x1000",
                "call_site":format!("0x{:x}", 0x1010 + i * 16),
                "slot_offset":8, "slot_index":1, "slot_address":"0x2008",
                "evidence":evidence,
            })
        })
        .collect();
    if args["function"] == "unused" {
        calls.clear();
    }
    let count = calls.len();
    if let Some(limit) = args["limit"].as_u64().filter(|limit| *limit != 0) {
        calls.truncate(limit as usize);
    }
    let partial = args["function"] == "partially_scanned";
    let complete = calls.len() == count && !partial;
    let slots = if count == 0 {
        json!([])
    } else {
        json!([{"index":1, "offset":8, "address":"0x2008", "target_address":"0x3000",
            "function":{"name":"Widget::draw", "address":"0x3000"}, "match":"direct"}])
    };
    json!({
        "target":{"function":args["function"], "address":"0x3000"},
        "vtable":{"address":"0x2000", "abi":args["abi"], "encoding":"absolute",
            "pointer_size":8, "entry_size":8, "requested_entries":args["entries"],
            "read_entries":args["entries"], "complete":true, "header":{"type_info":"0x4000"},
            "entries":slots},
        "slots":slots,
        "scope":args["within"].as_str().map(|function| json!({"function":function, "address":"0x1000"})),
        "scan":{"complete":complete, "stop_reason":if partial { json!("decompile_failed") } else if complete { Value::Null } else { json!("limit") },
            "total_functions":if partial { 2 } else { 1 }, "visited_functions":if partial { 2 } else { 1 }, "successful_functions":1,
            "failed_functions":if partial { json!([{"function":"broken", "address":"0x5000", "reason":"decompile_failed"}]) } else { json!([]) },
            "warnings":if partial { json!([{"function":"dispatch", "address":"0x1000", "warnings":["Recoverable decompiler warning"]}]) } else { json!([]) },
            "unvisited_functions":0, "omitted_calls":count - calls.len(),
            "unresolved":if partial { json!([{"caller":"dispatch", "call_site":"0x1080", "reason":"multiple_table_origins"}]) } else { json!([]) }},
        "calls":calls,
    })
}

fn command() -> Vec<&'static str> {
    vec![
        "find",
        "virtual-callers",
        "Widget::draw",
        "--vtable",
        "overlay:0x2000",
        "--entries",
        "0x4",
        "--abi",
        "itanium",
    ]
}

fn run_envelope(bridge: &RecordedBridge, args: &[&str], batch: bool) -> Value {
    let output = if batch {
        std::fs::write(
            bridge.root.path().join("virtual.txt"),
            batch_arguments(args),
        )
        .unwrap();
        bridge
            .command()
            .args(["batch", "virtual.txt"])
            .output()
            .unwrap()
    } else {
        bridge.command().args(args).output().unwrap()
    };
    assert!(
        output.status.success(),
        "{args:?}, batch={batch}: {output:?}"
    );
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    if batch {
        result["data"]["results"][0]["result"].clone()
    } else {
        result
    }
}

#[test]
fn virtual_caller_queries_preserve_evidence_context_and_standalone_batch_equivalence() {
    let outer = RecordedBridge::new();
    let selected = RecordedBridge::new();
    for within in [None, Some("dispatch")] {
        for (flags, expected, fetch_limit, offset, limit) in [
            (
                vec![],
                json!([{"call_site":"0x1010"}]),
                json!(1),
                0,
                json!(1),
            ),
            (
                vec!["--limit", "0"],
                json!([
                    {"call_site":"0x1010"}, {"call_site":"0x1020"},
                    {"call_site":"0x1030"}, {"call_site":"0x1040"}
                ]),
                Value::Null,
                0,
                Value::Null,
            ),
            (vec!["--count"], json!(4), Value::Null, 0, Value::Null),
            (
                vec!["--filter", "evidence=slot_offset"],
                json!([{"call_site":"0x1030"}]),
                Value::Null,
                0,
                json!(1),
            ),
            (
                vec!["--sort=-call_site"],
                json!([{"call_site":"0x1040"}]),
                Value::Null,
                0,
                json!(1),
            ),
            (
                vec!["--skip", "1", "--limit", "2"],
                json!([{"call_site":"0x1020"}, {"call_site":"0x1030"}]),
                Value::Null,
                1,
                json!(2),
            ),
            (
                vec![
                    "--filter",
                    "evidence!=slot_offset",
                    "--sort=-call_site",
                    "--skip",
                    "1",
                    "--limit",
                    "1",
                ],
                json!([{"call_site":"0x1020"}]),
                Value::Null,
                1,
                json!(1),
            ),
            (
                vec!["--count", "--skip", "1", "--limit", "2"],
                json!(2),
                Value::Null,
                1,
                json!(2),
            ),
        ] {
            let mut standalone = Value::Null;
            for batch in [false, true] {
                selected.requests.lock().unwrap().clear();
                let mut args = command();
                args.extend([
                    "--fields",
                    "call_site",
                    "--project",
                    selected.project.to_str().unwrap(),
                    "--program",
                    "B",
                ]);
                if let Some(within) = within {
                    args.extend(["--within", within]);
                }
                args.extend(flags.iter().copied());
                let result = run_envelope(&outer, &args, batch);
                assert_eq!(result["data"], expected, "{args:?}, batch={batch}");
                assert_eq!(
                    result["meta"]["target"],
                    json!({"function":"Widget::draw", "address":"0x3000"})
                );
                assert_eq!(
                    result["meta"]["scope"],
                    within
                        .map(|function| json!({"function":function, "address":"0x1000"}))
                        .unwrap_or(Value::Null)
                );
                assert_eq!(result["meta"]["slots"][0]["match"], "direct");
                assert_eq!(result["meta"]["vtable"]["entries"], result["meta"]["slots"]);
                assert_eq!(
                    result["meta"]["vtable"]["header"],
                    json!({"type_info":"0x4000"})
                );
                assert_eq!(result["meta"]["scan"]["complete"], fetch_limit.is_null());
                assert_eq!(
                    result["meta"]["scan"]["omitted_calls"],
                    if fetch_limit.is_null() { 0 } else { 3 }
                );
                assert_eq!(result["meta"]["scan"]["unresolved"], json!([]));
                assert_eq!(result["meta"]["offset"], offset);
                assert_eq!(result["meta"]["limit"], limit);
                if flags.contains(&"--count") {
                    assert!(result["meta"].get("returned").is_none());
                } else {
                    assert_eq!(
                        result["meta"]["returned"],
                        expected.as_array().unwrap().len()
                    );
                }
                if batch {
                    assert_eq!(result, standalone);
                } else {
                    standalone = result;
                }
                let requests = selected.requests.lock().unwrap();
                let domain: Vec<_> = requests
                    .iter()
                    .filter(|r| r["command"] != "bridge_info")
                    .collect();
                assert_eq!(domain.len(), 1);
                assert_eq!(domain[0]["program"], "B");
                assert_eq!(domain[0]["command"], "find_virtual_callers");
                assert_eq!(
                    domain[0]["args"],
                    json!({
                        "function":"Widget::draw", "vtable":"overlay:0x2000", "entries":4,
                        "abi":"itanium", "within":within, "limit":fetch_limit, "timeout_secs":0,
                    })
                );
            }
        }
    }
    assert!(outer.requests.lock().unwrap().is_empty());
}

#[test]
fn virtual_caller_empty_rows_keep_table_and_scan_metadata() {
    let bridge = RecordedBridge::new();
    for flags in [vec![], vec!["--count"]] {
        let mut args = command();
        args[2] = "unused";
        args.extend(flags.iter().copied());
        let standalone = run_envelope(&bridge, &args, false);
        assert_eq!(standalone, run_envelope(&bridge, &args, true));
        assert_eq!(
            standalone["data"],
            if flags.is_empty() {
                json!([])
            } else {
                json!(0)
            }
        );
        assert_eq!(standalone["meta"]["slots"], json!([]));
        assert_eq!(standalone["meta"]["scope"], Value::Null);
        assert_eq!(standalone["meta"]["scan"]["complete"], true);
        assert_eq!(standalone["meta"]["vtable"]["encoding"], "absolute");
    }
}

#[test]
fn virtual_caller_queries_retain_partial_scan_diagnostics() {
    let bridge = RecordedBridge::new();
    for flags in [
        vec!["--fields", "call_site", "--limit", "0"],
        vec!["--count"],
    ] {
        let mut args = command();
        args[2] = "partially_scanned";
        args.extend(flags.iter().copied());
        let result = run_envelope(&bridge, &args, false);
        assert_eq!(result, run_envelope(&bridge, &args, true));
        let scan = &result["meta"]["scan"];
        assert_eq!(scan["complete"], false);
        assert_eq!(scan["stop_reason"], "decompile_failed");
        assert_eq!(
            scan["failed_functions"],
            json!([{"function":"broken", "address":"0x5000", "reason":"decompile_failed"}])
        );
        assert_eq!(
            scan["warnings"],
            json!([{"function":"dispatch", "address":"0x1000", "warnings":["Recoverable decompiler warning"]}])
        );
        assert_eq!(
            scan["unresolved"],
            json!([{"caller":"dispatch", "call_site":"0x1080", "reason":"multiple_table_origins"}])
        );
        if flags.contains(&"--count") {
            assert_eq!(result["data"], 4);
        }
    }
}

#[test]
fn virtual_callers_routes_native_timeout_abi_and_exact_subjects() {
    let bridge = RecordedBridge::new();
    for batch in [false, true] {
        bridge.requests.lock().unwrap().clear();
        let args = [
            "find",
            "virtual-callers",
            "Namespace::draw",
            "--vtable",
            "table with spaces",
            "--entries",
            "03",
            "--abi",
            "msvc",
            "--within",
            "caller with spaces",
        ];
        let mut cli = bridge.command();
        cli.env("GHIDRA_CLI_DECOMPILE_TIMEOUT", "47");
        if batch {
            std::fs::write(
                bridge.root.path().join("virtual.txt"),
                batch_arguments(&args),
            )
            .unwrap();
            cli.args(["batch", "virtual.txt"]);
        } else {
            cli.args(args);
        }
        let output = cli.output().unwrap();
        assert!(output.status.success(), "{output:?}");
        let requests = bridge.requests.lock().unwrap();
        let request = requests
            .iter()
            .find(|r| r["command"] == "find_virtual_callers")
            .unwrap();
        assert_eq!(
            request["args"],
            json!({
                "function":"Namespace::draw", "vtable":"table with spaces", "entries":3,
                "abi":"msvc", "within":"caller with spaces", "limit":1, "timeout_secs":47,
            })
        );
    }
    bridge.requests.lock().unwrap().clear();
    let output = bridge
        .command()
        .env("GHIDRA_CLI_DECOMPILE_TIMEOUT", "invalid")
        .args(command())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(bridge
        .requests
        .lock()
        .unwrap()
        .iter()
        .all(|r| r["command"] == "bridge_info"));
}

#[test]
fn invalid_virtual_caller_inputs_fail_before_any_bridge_work_including_batch() {
    let bridge = RecordedBridge::new();
    for (argument, invalid) in [(6, "0"), (6, "65537"), (2, " "), (4, "")] {
        let mut args = command();
        args[argument] = invalid;
        for batch in [false, true] {
            let output = if batch {
                std::fs::write(
                    bridge.root.path().join("virtual.txt"),
                    batch_arguments(&args),
                )
                .unwrap();
                bridge
                    .command()
                    .args(["batch", "virtual.txt"])
                    .output()
                    .unwrap()
            } else {
                bridge.command().args(&args).output().unwrap()
            };
            assert!(!output.status.success(), "{args:?}, batch={batch}");
            if batch {
                let result: Value = serde_json::from_slice(&output.stdout).unwrap();
                assert_eq!(result["data"]["commands_executed"], 0);
                assert_eq!(result["data"]["validation_failed"], true);
            }
            assert!(bridge.requests.lock().unwrap().is_empty());
        }
    }
}

#[test]
fn virtual_caller_ndjson_projects_only_call_rows() {
    let bridge = RecordedBridge::new();
    let mut args = command();
    args.extend(["--limit", "0", "--fields", "evidence", "--format", "ndjson"]);
    let output = bridge.command().args(&args).output().unwrap();
    assert!(output.status.success(), "{output:?}");
    let rows: Vec<Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(
        rows,
        vec![
            json!({"evidence":"table_value"}),
            json!({"evidence":"table_type"}),
            json!({"evidence":"slot_offset"}),
            json!({"evidence":"table_value"})
        ]
    );
}
