use super::{batch_arguments, RecordedBridge};
use serde_json::{json, Value};

#[test]
fn constant_queries_preserve_values_and_apply_selection_in_standalone_and_batch() {
    let bridge = RecordedBridge::new();
    let all = bridge.run(&["find", "constant", "1", "--limit", "0"]);
    for (selection, expected_selection) in [
        (
            vec!["0xffffffffffffffff"],
            json!({"value": "0xffffffffffffffff"}),
        ),
        (
            vec!["-0x1", "--bits", "32"],
            json!({"value": "-0x1", "bits": 32}),
        ),
        (
            vec!["--min", "-1", "--max", "500"],
            json!({"min": "-1", "max": "500"}),
        ),
    ] {
        for (flags, expected, fetch_limit) in [
            (vec![], json!([all[0]]), json!(1)),
            (vec!["--limit", "0"], all.clone(), Value::Null),
            (vec!["--count"], json!(4), Value::Null),
            (
                vec![
                    "--filter",
                    "bits >= 16",
                    "--sort=-address",
                    "--offset",
                    "1",
                    "--limit",
                    "1",
                    "--fields",
                    "address,bits",
                ],
                json!([{"address": "0x1002", "bits": 32}]),
                Value::Null,
            ),
        ] {
            let args: Vec<_> = ["find", "constant"]
                .into_iter()
                .chain(selection.iter().copied())
                .chain(["--start", "0x1000", "--end", "0x2000", "--program", "B"])
                .chain(flags.iter().copied())
                .collect();
            for batch in [false, true] {
                bridge.requests.lock().unwrap().clear();
                let result = if batch {
                    std::fs::write(bridge.root.path().join("batch.txt"), batch_arguments(&args))
                        .unwrap();
                    bridge.run(&["batch", "batch.txt"])[0]["results"][0]["result"].clone()
                } else {
                    bridge.run(&args)
                };
                let expected = if batch && flags.is_empty() {
                    json!({"results": expected, "count": 1})
                } else {
                    expected.clone()
                };
                assert_eq!(result, expected, "{args:?}, batch={batch}");
                let requests = bridge.requests.lock().unwrap();
                let request = requests
                    .iter()
                    .find(|r| r["command"] == "find_constant")
                    .unwrap();
                for key in ["value", "min", "max", "bits"] {
                    assert_eq!(request["args"][key], expected_selection[key], "{args:?}");
                }
                assert_eq!(request["args"]["start"], "0x1000");
                assert_eq!(request["args"]["end"], "0x2000");
                assert_eq!(request["args"]["limit"], fetch_limit);
                assert!(requests
                    .iter()
                    .any(|r| r["command"] == "open_program" && r["args"]["program"] == "B"));
            }
        }
    }
}

#[test]
fn invalid_constant_ranges_fail_before_program_selection_or_search() {
    let bridge = RecordedBridge::new();
    for selection in [
        vec!["--min", "500", "--max", "400"],
        vec!["--min", "-1", "--max", "0xffffffffffffffff"],
    ] {
        let args: Vec<_> = ["find", "constant"]
            .into_iter()
            .chain(selection)
            .chain(["--program", "B"])
            .collect();
        for batch in [false, true] {
            bridge.requests.lock().unwrap().clear();
            let output = if batch {
                std::fs::write(bridge.root.path().join("batch.txt"), batch_arguments(&args))
                    .unwrap();
                bridge
                    .command()
                    .args(["batch", "batch.txt"])
                    .output()
                    .unwrap()
            } else {
                bridge.command().args(&args).output().unwrap()
            };
            assert!(!output.status.success(), "{args:?}, batch={batch}");
            assert!(bridge
                .requests
                .lock()
                .unwrap()
                .iter()
                .all(|r| r["command"] == "bridge_info"));
        }
    }
}

#[test]
fn search_queries_use_planned_limits_without_truncating_selection() {
    let bridge = RecordedBridge::new();
    for (command, wire) in [
        (vec!["find", "string", "needle"], "find_string"),
        (vec!["find", "text", "needle"], "find_text"),
        (vec!["find", "bytes", "90"], "find_bytes"),
        (
            vec!["find", "bytes", "--regex", r"\x90.{2}"],
            "find_bytes_regex",
        ),
    ] {
        for (flags, expected_len, first, fetch_limit) in [
            (vec![], 1, "0x0000", json!(1)),
            (vec!["--fields", "address"], 1, "0x0000", json!(1)),
            (vec!["--limit", "0"], 160, "0x0000", Value::Null),
            (vec!["--limit", "120"], 120, "0x0000", json!(120)),
            (
                vec!["--filter", "address='0x009f'"],
                1,
                "0x009f",
                Value::Null,
            ),
            (vec!["--sort=-address"], 1, "0x009f", Value::Null),
            (
                vec!["--offset", "100", "--limit", "2"],
                2,
                "0x0064",
                Value::Null,
            ),
            (vec!["--count"], 160, "", Value::Null),
            (
                vec!["--count", "--offset", "100", "--limit", "2"],
                2,
                "",
                Value::Null,
            ),
        ] {
            for batch in [false, true] {
                let mut args = command.clone();
                args.extend(&flags);
                bridge.requests.lock().unwrap().clear();
                let result = if batch {
                    std::fs::write(bridge.root.path().join("batch.txt"), batch_arguments(&args))
                        .unwrap();
                    bridge.run(&["batch", "batch.txt"])[0]["results"][0]["result"].clone()
                } else {
                    bridge.run(&args)
                };
                if flags.contains(&"--count") {
                    assert_eq!(result, expected_len, "{args:?}, batch={batch}");
                } else {
                    let rows = if batch && flags.is_empty() {
                        assert_eq!(result["count"], expected_len);
                        &result["results"]
                    } else {
                        &result
                    };
                    assert_eq!(
                        rows.as_array().unwrap().len(),
                        expected_len,
                        "{args:?}, batch={batch}"
                    );
                    assert_eq!(rows[0]["address"], first);
                }
                let requests = bridge.requests.lock().unwrap();
                let sent: Vec<_> = requests.iter().filter(|r| r["command"] == wire).collect();
                assert_eq!(sent.len(), 1);
                let server_page = wire == "find_string"
                    && flags.contains(&"--offset")
                    && !flags.contains(&"--count");
                assert_eq!(
                    sent[0]["args"]["limit"],
                    if server_page {
                        json!(2)
                    } else {
                        fetch_limit.clone()
                    },
                    "{args:?}"
                );
                assert_eq!(
                    sent[0]["args"]["offset"],
                    if server_page { json!(100) } else { Value::Null },
                    "{args:?}"
                );
            }
        }
    }
}

#[test]
fn string_search_pages_after_pattern_and_filter_in_standalone_and_batch() {
    let bridge = RecordedBridge::new();
    let rows = json!([
        {"value":"needle_115", "char_length":10, "byte_length":11},
        {"value":"needle_125", "char_length":10, "byte_length":11}
    ]);
    for (flags, expected, fetch_filter, fetch_offset, fetch_limit) in [
        (
            vec!["--filter", "value~'5'", "--offset", "1", "--limit", "2"],
            rows.clone(),
            json!("5"),
            json!(1),
            json!(2),
        ),
        (
            vec![
                "--filter",
                "value~'5' AND byte_length>10",
                "--offset",
                "1",
                "--limit",
                "2",
            ],
            rows.clone(),
            Value::Null,
            Value::Null,
            Value::Null,
        ),
        (
            vec![
                "--filter",
                "value~'5'",
                "--sort=-value",
                "--offset",
                "12",
                "--limit",
                "2",
            ],
            json!([rows[1], rows[0]]),
            json!("5"),
            Value::Null,
            Value::Null,
        ),
        (
            vec![
                "--filter",
                "value~'5'",
                "--offset",
                "1",
                "--limit",
                "2",
                "--count",
            ],
            json!(2),
            json!("5"),
            Value::Null,
            Value::Null,
        ),
        (
            vec!["--filter", "value~'5'", "--count"],
            json!(15),
            json!("5"),
            Value::Null,
            Value::Null,
        ),
    ] {
        let args: Vec<_> = [
            "find",
            "string",
            "NEEDLE_1",
            "--fields",
            "value,char_length,byte_length",
        ]
        .into_iter()
        .chain(flags)
        .collect();
        for batch in [false, true] {
            bridge.requests.lock().unwrap().clear();
            let actual = if batch {
                std::fs::write(bridge.root.path().join("batch.txt"), batch_arguments(&args))
                    .unwrap();
                bridge.run(&["batch", "batch.txt"])[0]["results"][0]["result"].clone()
            } else {
                bridge.run(&args)
            };
            assert_eq!(actual, expected, "{args:?}, batch={batch}");
            let requests = bridge.requests.lock().unwrap();
            let sent = requests
                .iter()
                .find(|r| r["command"] == "find_string")
                .unwrap();
            assert_eq!(
                sent["args"],
                json!({
                    "pattern":"NEEDLE_1", "filter":fetch_filter,
                    "offset":fetch_offset, "limit":fetch_limit,
                }),
                "{args:?}, batch={batch}"
            );
        }
    }
}

#[test]
fn byte_regex_preserves_pattern_and_program_in_standalone_and_batch() {
    let bridge = RecordedBridge::new();
    let pattern = r"\x00(?:A B|'quote')\xff.{2,4}";
    let args = [
        "find",
        "bytes",
        "--regex",
        pattern,
        "--program",
        "B",
        "--limit",
        "2",
    ];
    for batch in [false, true] {
        bridge.requests.lock().unwrap().clear();
        if batch {
            std::fs::write(bridge.root.path().join("batch.txt"), batch_arguments(&args)).unwrap();
            bridge.run(&["batch", "batch.txt"]);
        } else {
            bridge.run(&args);
        }
        let requests = bridge.requests.lock().unwrap();
        let search = requests
            .iter()
            .find(|r| r["command"] == "find_bytes_regex")
            .unwrap();
        assert_eq!(search["args"], json!({"pattern": pattern, "limit": 2}));
        assert!(requests
            .iter()
            .any(|r| r["command"] == "open_program" && r["args"]["program"] == "B"));
        assert!(!requests.iter().any(|r| r["command"] == "find_bytes"));
    }
}

#[test]
fn text_search_routes_encoding_text_and_program_in_standalone_and_batch() {
    let bridge = RecordedBridge::new();
    for encoding in [None, Some("utf-16le"), Some("shift_jis")] {
        for batch in [false, true] {
            bridge.requests.lock().unwrap().clear();
            let mut args = vec![
                "find",
                "text",
                "日本 text",
                "--program",
                "B",
                "--limit",
                "1",
            ];
            if let Some(encoding) = encoding {
                args.extend(["--encoding", encoding]);
            }
            if batch {
                std::fs::write(bridge.root.path().join("text.txt"), batch_arguments(&args))
                    .unwrap();
                bridge.run(&["batch", "text.txt"]);
            } else {
                bridge.run(&args);
            }
            let requests = bridge.requests.lock().unwrap();
            assert!(requests
                .iter()
                .any(|r| r["command"] == "open_program" && r["args"]["program"] == "B"));
            let sent: Vec<_> = requests
                .iter()
                .filter(|r| r["command"] == "find_text")
                .collect();
            assert_eq!(sent.len(), 1);
            assert_eq!(
                sent[0]["args"],
                json!({"text": "日本 text", "encoding": encoding.unwrap_or("utf-8"), "limit": 1})
            );
        }
    }
}

#[test]
fn string_reference_queries_process_rows_in_standalone_and_batch_results() {
    let bridge = RecordedBridge::new();
    let all = json!([
        {"from": "0x1000", "from_function": "main", "string_value": "needle"},
        {"from": "0x2000", "from_function": "helper", "string_value": "needle"},
    ]);
    for (pattern, flags, expected) in [
        ("needle", vec!["--limit", "0"], all.clone()),
        ("needle", vec!["--count"], json!(2)),
        ("absent", vec!["--count"], json!(0)),
        ("absent", vec!["--limit", "0"], json!([])),
        (
            "needle",
            vec!["--fields", "from", "--limit", "0"],
            json!([{"from": "0x1000"}, {"from": "0x2000"}]),
        ),
        (
            "needle",
            vec!["--filter", "from_function=main"],
            json!([all[0].clone()]),
        ),
        (
            "needle",
            vec!["--sort", "-from", "--offset", "1", "--limit", "1"],
            json!([all[0].clone()]),
        ),
    ] {
        let args: Vec<_> = ["string", "refs", pattern]
            .into_iter()
            .chain(flags)
            .collect();
        assert_eq!(bridge.run(&args), expected, "{args:?}");
        std::fs::write(bridge.root.path().join("batch.txt"), args.join(" ")).unwrap();
        let report = bridge.run(&["batch", "batch.txt"]);
        assert_eq!(
            report[0]["results"][0]["result"], expected,
            "batch {args:?}"
        );
    }
}
