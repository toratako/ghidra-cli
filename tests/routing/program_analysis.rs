use super::{batch_arguments, RecordedBridge};
use serde_json::{json, Value};

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
fn context_and_rebase_route_targets_and_arguments_in_standalone_and_batch() {
    let first = RecordedBridge::new();
    let selected = RecordedBridge::new();
    for (mut args, wire, expected_args, is_list) in [
        (
            vec!["program", "context", "list"],
            "program_context_list",
            Value::Null,
            true,
        ),
        (
            vec![
                "program",
                "context",
                "get",
                "TMode",
                "--start",
                "overlay:0x1000",
            ],
            "program_context_get",
            json!({"register": "TMode", "start": "overlay:0x1000"}),
            true,
        ),
        (
            vec![
                "program",
                "context",
                "get",
                "TMode",
                "--start",
                "overlay:0x1000",
                "--end",
                "overlay:0x100f",
            ],
            "program_context_get",
            json!({"register": "TMode", "start": "overlay:0x1000", "end": "overlay:0x100f"}),
            true,
        ),
        (
            vec![
                "program",
                "context",
                "set",
                "TMode",
                "--value",
                "0x1",
                "--start",
                "overlay:0x1000",
                "--end",
                "overlay:0x100f",
            ],
            "program_context_set",
            json!({"register": "TMode", "value": "0x1", "start": "overlay:0x1000", "end": "overlay:0x100f"}),
            false,
        ),
        (
            vec![
                "program",
                "context",
                "clear",
                "TMode",
                "--start",
                "overlay:0x1000",
                "--end",
                "overlay:0x100f",
            ],
            "program_context_clear",
            json!({"register": "TMode", "start": "overlay:0x1000", "end": "overlay:0x100f"}),
            false,
        ),
        (
            vec!["program", "rebase", "--base", "ram:0x80000000"],
            "program_rebase",
            json!({"base": "ram:0x80000000"}),
            false,
        ),
    ] {
        args.extend([
            "--project",
            selected.project.to_str().unwrap(),
            "--program",
            "B",
        ]);
        let mut standalone = Value::Null;
        for batched in [false, true] {
            first.requests.lock().unwrap().clear();
            selected.requests.lock().unwrap().clear();
            let result = run(&first, &args, batched);
            assert_eq!(result["data"].is_array(), is_list, "{args:?}: {result}");
            if batched {
                assert_eq!(result, standalone, "{args:?}");
            } else {
                standalone = result;
            }
            assert!(first
                .requests
                .lock()
                .unwrap()
                .iter()
                .all(|r| r["command"] == "bridge_info"));
            let requests = selected.requests.lock().unwrap();
            let domain: Vec<_> = requests
                .iter()
                .filter(|r| r["command"] != "bridge_info")
                .collect();
            assert_eq!(domain.len(), 1, "{domain:?}");
            assert_eq!(domain[0]["program"], "B");
            assert_eq!(domain[0]["command"], wire);
            assert_eq!(domain[0]["args"], expected_args, "{args:?}");
        }
    }
}

#[test]
fn context_lists_apply_queries_and_keep_range_metadata_in_standalone_and_batch() {
    let bridge = RecordedBridge::new();
    for batched in [false, true] {
        assert_eq!(
            run(&bridge, &["program", "context", "list"], batched),
            json!({"data": [{"name": "ITState", "bit_length": 8}], "meta": {"offset": 0, "limit": 1, "returned": 1}})
        );
        assert_eq!(
            run(
                &bridge,
                &[
                    "program",
                    "context",
                    "list",
                    "--filter",
                    "bit_length>1",
                    "--sort",
                    "name",
                    "--skip",
                    "1",
                    "--limit",
                    "1",
                    "--fields",
                    "name",
                ],
                batched
            ),
            json!({"data": [{"name": "contextreg"}], "meta": {"offset": 1, "limit": 1, "returned": 1}})
        );
        assert_eq!(
            run(&bridge, &["program", "context", "list", "--count"], batched)["data"],
            3
        );
        let point = run(
            &bridge,
            &[
                "program",
                "context",
                "get",
                "TMode",
                "--start",
                "overlay:0x1000",
            ],
            batched,
        );
        assert_eq!(point["data"].as_array().unwrap().len(), 1);
        assert_eq!(point["meta"]["start"], "overlay:0x1000");
        assert_eq!(point["meta"]["end"], "overlay:0x1000");

        let range = [
            "program",
            "context",
            "get",
            "TMode",
            "--start",
            "overlay:0x1000",
            "--end",
            "overlay:0x100f",
        ];
        let args: Vec<_> = range
            .into_iter()
            .chain([
                "--sort=-start",
                "--skip",
                "1",
                "--limit",
                "1",
                "--fields",
                "start,end,stored,effective",
            ])
            .collect();
        assert_eq!(
            run(&bridge, &args, batched),
            json!({
                "data": [{
                    "start": "overlay:0x1004", "end": "overlay:0x1007",
                    "stored": {"value": "0x0", "mask": "0x0"},
                    "effective": {"value": "0x0", "mask": "0x1"},
                }],
                "meta": {
                    "register": "TMode", "bit_length": 1,
                    "start": "overlay:0x1000", "end": "overlay:0x100f",
                    "offset": 1, "limit": 1, "returned": 1,
                },
            })
        );
        let args: Vec<_> = range.into_iter().chain(["--count"]).collect();
        let count = run(&bridge, &args, batched);
        assert_eq!(count["data"], 3);
        assert_eq!(count["meta"]["register"], "TMode");
        assert_eq!(count["meta"]["start"], "overlay:0x1000");
        assert_eq!(count["meta"]["end"], "overlay:0x100f");
        assert!(count["meta"].get("returned").is_none());
    }
}

#[test]
fn context_edits_and_rebase_keep_nested_receipts_with_object_projection() {
    let bridge = RecordedBridge::new();
    for batched in [false, true] {
        for (operation, expected_status) in [("set", "set"), ("clear", "cleared")] {
            let mut args = vec!["program", "context", operation, "TMode"];
            if operation == "set" {
                args.extend(["--value", "1"]);
            }
            args.extend(["--start", "overlay:0x1000", "--end", "overlay:0x100f"]);
            for projected in [false, true] {
                let mut args = args.clone();
                if projected {
                    args.extend(["--fields", "status,ranges"]);
                }
                let result = run(&bridge, &args, batched);
                let receipt = &result["data"];
                assert_eq!(receipt["status"], expected_status);
                assert_eq!(receipt.get("register").is_some(), !projected);
                let ranges = receipt["ranges"].as_array().unwrap();
                assert_eq!(ranges.len(), 1);
                assert_eq!(ranges[0]["start"], "overlay:0x1000");
                assert_eq!(ranges[0]["end"], "overlay:0x100f");
                assert_eq!(
                    ranges[0]["stored"]["mask"],
                    if operation == "set" { "0x1" } else { "0x0" }
                );
                assert_eq!(ranges[0]["default"]["mask"], "0x1");
                assert!(result.get("meta").is_none());
            }
        }
        for projected in [false, true] {
            let mut args = vec!["program", "rebase", "--base", "0x80000000"];
            if projected {
                args.extend(["--fields", "new_base,moved_blocks,unchanged_blocks"]);
            }
            let result = run(&bridge, &args, batched);
            let receipt = &result["data"];
            assert_eq!(receipt["new_base"], "0x80000000");
            assert_eq!(receipt.get("old_base").is_some(), !projected);
            assert_eq!(receipt["moved_blocks"][0]["old_start"], "0x00001000");
            assert_eq!(receipt["moved_blocks"][0]["new_start"], "0x80000000");
            assert_eq!(receipt["unchanged_blocks"][0]["reason"], "overlay");
            assert!(result.get("meta").is_none());
        }
    }
}
