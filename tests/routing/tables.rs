use super::{batch_arguments, RecordedBridge};
use serde_json::{json, Value};

pub(super) fn vtable_fixture(args: &Value, program: &str) -> Value {
    let entry_size = if args["encoding"] == "relative32" {
        4
    } else {
        8
    };
    let entries: Vec<_> = (0..args["entries"].as_u64().unwrap())
        .map(|index| {
            json!({
                "index": index,
                "offset": index * entry_size,
                "address": format!("bank1:0x{:x}", 0x4000 + index * entry_size),
                "target_address": format!("bank1:0x{:x}", 0x1000 + index * 16),
                "readable": true,
            })
        })
        .collect();
    json!({
        "address": "bank1:0x4000", "abi": args["abi"], "encoding": args["encoding"],
        "pointer_size": 8, "entry_size": entry_size, "endian": "little",
        "requested_entries": entries.len(), "read_entries": entries.len(),
        "complete": true, "entries": entries, "observed_program": program,
    })
}

pub(super) fn address_tables_fixture(args: &Value) -> Value {
    let mut rows: Vec<_> = [4, 6, 8]
        .into_iter()
        .enumerate()
        .map(|(index, entries)| {
            let address = 0x1000 + index * 0x1000;
            json!({
                "address": format!("bank1:0x{address:x}"),
                "end": format!("bank1:0x{:x}", address + entries * 8 - 1),
                "entry_count": entries, "byte_length": entries * 8,
            })
        })
        .collect();
    let limited = args["limit"].as_u64().is_some_and(|limit| {
        if limit > 0 && limit < rows.len() as u64 {
            rows.truncate(limit as usize);
            true
        } else {
            false
        }
    });
    let scan = if limited {
        json!({"complete": false, "stop_reason": "limit"})
    } else {
        json!({"complete": true})
    };
    json!({
        "results": rows, "count": rows.len(),
        "detector": "ghidra-address-table", "scope": "candidate-starts",
        "ranges": [{"start": "bank1:0x1000", "end": "bank1:0x7000"}],
        "pointer_size": 8, "endian": "little", "pointer_shift": 0,
        "min_entries": args["min_entries"],
        "alignment": args["alignment"].as_u64().unwrap_or(1),
        "scan": scan,
    })
}

fn run(bridge: &RecordedBridge, args: &[&str], batched: bool) -> Value {
    let output = if batched {
        std::fs::write(bridge.root.path().join("batch.txt"), batch_arguments(args)).unwrap();
        bridge
            .command()
            .args(["batch", "batch.txt"])
            .output()
            .unwrap()
    } else {
        bridge.command().args(args).output().unwrap()
    };
    assert!(
        output.status.success(),
        "{args:?}, batch={batched}: {output:?}"
    );
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    if batched {
        assert_eq!(result["data"]["failed"], 0);
        result["data"]["results"][0]["result"].clone()
    } else {
        result
    }
}

#[test]
fn vtable_reads_preserve_targets_and_nested_slots_in_standalone_and_batch() {
    let outer = RecordedBridge::new();
    let selected = RecordedBridge::new();
    for (target, abi, encoding) in [
        ("bank1:0x4000", "itanium", None),
        ("Widget::vftable", "msvc", Some("absolute")),
        ("relative_slots", "itanium", Some("relative32")),
    ] {
        let expected_args = json!({
            "target": target, "entries": 3, "abi": abi,
            "encoding": encoding.unwrap_or("absolute"),
        });
        for batched in [false, true] {
            for project_fields in [false, true] {
                outer.requests.lock().unwrap().clear();
                selected.requests.lock().unwrap().clear();
                let mut args = vec![
                    "vtable",
                    "read",
                    target,
                    "--entries",
                    "0x3",
                    "--abi",
                    abi,
                    "--project",
                    selected.project.to_str().unwrap(),
                    "--program",
                    "B",
                ];
                if let Some(encoding) = encoding {
                    args.extend(["--encoding", encoding]);
                }
                if project_fields {
                    args.extend(["--fields", "address,entries,observed_program"]);
                }
                let result = run(&outer, &args, batched);
                let expected = vtable_fixture(&expected_args, "B");
                if project_fields {
                    assert_eq!(
                        result,
                        json!({"data": {
                            "address": expected["address"], "entries": expected["entries"],
                            "observed_program": "B",
                        }})
                    );
                } else {
                    assert_eq!(result, json!({"data": expected}));
                }
                // The configured default limit is one; it must not truncate an object.
                assert_eq!(result["data"]["entries"].as_array().unwrap().len(), 3);
                assert!(outer
                    .requests
                    .lock()
                    .unwrap()
                    .iter()
                    .all(|request| request["command"] == "bridge_info"));
                let requests = selected.requests.lock().unwrap();
                let domain: Vec<_> = requests
                    .iter()
                    .filter(|request| request["command"] != "bridge_info")
                    .collect();
                assert_eq!(domain.len(), 2, "{requests:?}");
                assert_eq!(domain[0]["command"], "open_program");
                assert_eq!(domain[0]["args"], json!({"program": "B"}));
                assert_eq!(domain[1]["command"], "vtable_read");
                assert_eq!(domain[1]["args"], expected_args);
            }
        }
    }
}

#[test]
fn address_table_queries_keep_detector_context_and_fetch_before_selection() {
    let bridge = RecordedBridge::new();
    let all_args = json!({"min_entries": 4, "alignment": 8});
    let fixture = address_tables_fixture(&all_args);
    let all = &fixture["results"];
    for (flags, expected, fetch_limit, offset, page_limit) in [
        (vec![], json!([all[0]]), json!(1), 0, json!(1)),
        (
            vec!["--limit", "0"],
            all.clone(),
            Value::Null,
            0,
            Value::Null,
        ),
        (
            vec!["--fields", "address"],
            json!([{"address": "bank1:0x1000"}]),
            json!(1),
            0,
            json!(1),
        ),
        (
            vec![
                "--filter",
                "entry_count>=6",
                "--sort=-address",
                "--skip",
                "1",
                "--limit",
                "1",
                "--fields",
                "address,entry_count",
            ],
            json!([{"address": "bank1:0x2000", "entry_count": 6}]),
            Value::Null,
            1,
            json!(1),
        ),
        (vec!["--count"], json!(3), Value::Null, 0, Value::Null),
        (
            vec!["--filter", "entry_count>8"],
            json!([]),
            Value::Null,
            0,
            json!(1),
        ),
    ] {
        for batched in [false, true] {
            bridge.requests.lock().unwrap().clear();
            let args: Vec<_> = [
                "find",
                "address-tables",
                "--start",
                "bank1:0x1000",
                "--end",
                "upper_bound",
                "--min-entries",
                "0x4",
                "--alignment",
                "08",
                "--program",
                "B",
            ]
            .into_iter()
            .chain(flags.iter().copied())
            .collect();
            let result = run(&bridge, &args, batched);
            assert_eq!(result["data"], expected, "{args:?}, batch={batched}");
            for key in [
                "detector",
                "scope",
                "ranges",
                "pointer_size",
                "endian",
                "pointer_shift",
                "min_entries",
                "alignment",
            ] {
                assert_eq!(result["meta"][key], fixture[key], "{key}: {result}");
            }
            assert_eq!(result["meta"]["offset"], offset);
            assert_eq!(result["meta"]["limit"], page_limit);
            assert_eq!(
                result["meta"]["scan"],
                if fetch_limit.is_null() {
                    json!({"complete": true})
                } else {
                    json!({"complete": false, "stop_reason": "limit"})
                }
            );
            if let Some(rows) = expected.as_array() {
                assert_eq!(result["meta"]["returned"], rows.len());
            } else {
                assert!(result["meta"].get("returned").is_none());
            }
            let requests = bridge.requests.lock().unwrap();
            let domain: Vec<_> = requests
                .iter()
                .filter(|request| request["command"] != "bridge_info")
                .collect();
            assert_eq!(domain.len(), 2, "{requests:?}");
            assert_eq!(domain[0]["command"], "open_program");
            assert_eq!(domain[0]["args"], json!({"program": "B"}));
            assert_eq!(domain[1]["command"], "find_address_tables");
            assert_eq!(
                domain[1]["args"],
                json!({
                    "start": "bank1:0x1000", "end": "upper_bound", "min_entries": 4,
                    "alignment": 8, "limit": fetch_limit,
                })
            );
        }
    }
}

#[test]
fn address_table_human_output_preserves_scope_and_scan_completion() {
    let bridge = RecordedBridge::new();
    for format in ["compact", "full"] {
        for (flags, complete, empty) in [
            (vec!["--quiet", "--fields", "address"], false, false),
            (vec!["--limit", "0"], true, false),
            (vec!["--sort=-address", "--limit", "1"], true, false),
            (vec!["--filter", "entry_count>8"], true, true),
        ] {
            let output = bridge
                .command()
                .args(["find", "address-tables", "--format", format])
                .args(&flags)
                .output()
                .unwrap();
            assert!(output.status.success(), "{output:?}");
            assert!(output.stderr.is_empty(), "{output:?}");
            let text = String::from_utf8(output.stdout).unwrap();
            assert!(
                text.contains("Candidate start ranges: bank1:0x1000 .. bank1:0x7000"),
                "{text}"
            );
            assert_eq!(text.contains("Scan complete"), complete, "{text}");
            assert_eq!(
                text.contains("Scan stopped at the result limit"),
                !complete,
                "{text}"
            );
            assert_eq!(text.contains("--limit 0"), !complete, "{text}");
            assert_eq!(text.contains("No results"), empty, "{text}");
        }
        let output = bridge
            .command()
            .args(["find", "address-tables", "--count", "--format", format])
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert_eq!(String::from_utf8(output.stdout).unwrap(), "3\n");
    }
}

#[test]
fn incompatible_vtable_layout_fails_before_program_selection_and_batch_execution() {
    let bridge = RecordedBridge::new();
    let args = [
        "vtable",
        "read",
        "bank1:0x4000",
        "--entries",
        "4",
        "--abi",
        "msvc",
        "--encoding",
        "relative32",
        "--program",
        "must-not-open",
    ];
    let output = bridge.command().args(args).output().unwrap();
    assert!(!output.status.success(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("--encoding relative32 requires --abi itanium"),
        "{output:?}"
    );
    std::fs::write(
        bridge.root.path().join("batch.txt"),
        format!("program info\n{}", batch_arguments(&args)),
    )
    .unwrap();
    let output = bridge
        .command()
        .args(["batch", "batch.txt"])
        .output()
        .unwrap();
    assert!(!output.status.success(), "{output:?}");
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["data"]["commands_executed"], 0);
    assert_eq!(result["data"]["validation_failed"], true);
    assert!(result["data"]["validation_errors"][0]["error"]
        .as_str()
        .unwrap()
        .contains("--encoding relative32 requires --abi itanium"));
    assert!(bridge.requests.lock().unwrap().is_empty());
}
