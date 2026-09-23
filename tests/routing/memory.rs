use super::{batch_arguments, RecordedBridge};
use serde_json::{json, Value};

pub(super) fn file_mappings_fixture(args: &Value, program: &str) -> Value {
    let file_offset = args["file_offset"].as_str().map(|text| {
        if let Some(digits) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
            i64::from_str_radix(digits, 16).unwrap()
        } else {
            text.parse::<i64>().unwrap()
        }
    });
    let rows: Vec<_> = if file_offset == Some(999) {
        vec![]
    } else {
        ["ram:0x1000", "bank1:0x1000", "ram:0x2000"]
            .into_iter()
            .map(|address| {
                json!({
                    "address": address, "end": address,
                    "file_offset": file_offset.unwrap_or(512),
                    "size": if file_offset.is_some() { 1 } else { 16 },
                    "source_at": "ram:0x1000", "observed_program": program,
                })
            })
            .collect()
    };
    let mut result = json!({
        "mappings": rows,
        "unsupported_mappings": [{
            "address": "ram:0x3000", "end": "ram:0x30ff", "block_start": "ram:0x3000",
            "reason": "Indirect bit/byte memory mapping",
        }],
    });
    if let Some(offset) = file_offset {
        result["file_offset"] = json!(offset);
    }
    if let Some(source_at) = args.get("source_at") {
        result["source_at"] = source_at.clone();
    }
    result
}

pub(super) fn block_receipt_fixture(command: &str, args: &Value, program: &str) -> Value {
    let before = json!({"name": ".ram", "start": args["block_start"], "permissions": "rw"});
    let after = json!({
        "name": args.get("name").cloned().unwrap_or(json!(".ram")),
        "start": args.get("start").unwrap_or(&args["block_start"]),
        "permissions": args.get("permissions").cloned().unwrap_or(json!("rw")),
    });
    let mut result = json!({
        "changed": true,
        "before": if command == "memory_block_create" { Value::Null } else { before },
        "after": if command == "memory_block_delete" { Value::Null } else { after },
        "observed_program": program,
    });
    if command == "memory_block_delete" {
        result["overlay_removed"] = json!(true);
    }
    result
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
fn memory_commands_route_exact_targets_and_receipts_in_standalone_and_batch() {
    let first = RecordedBridge::new();
    let selected = RecordedBridge::new();
    for (mut args, wire, expected_args, is_list) in [
        (
            vec!["memory", "file-mappings"],
            "memory_file_mappings",
            json!({}),
            true,
        ),
        (
            vec![
                "memory",
                "file-mappings",
                "--file-offset",
                "0x205",
                "--source-at",
                "bank1:0x1005",
            ],
            "memory_file_mappings",
            json!({"file_offset": "0x205", "source_at": "bank1:0x1005"}),
            true,
        ),
        (
            vec![
                "memory",
                "block",
                "create",
                ".mmio",
                "--start",
                "ram:0x40000000",
                "--size",
                "4096",
                "--uninitialized",
                "--permissions",
                "wr",
                "--volatile",
            ],
            "memory_block_create",
            json!({"name": ".mmio", "start": "ram:0x40000000", "size": 4096, "uninitialized": true, "permissions": "rw", "volatile": true}),
            false,
        ),
        (
            vec![
                "memory",
                "block",
                "create",
                ".bank",
                "--start",
                "ram:0x1000",
                "--size",
                "256",
                "--fill",
                "0xff",
                "--permissions",
                "rx",
                "--overlay",
                "bank1",
            ],
            "memory_block_create",
            json!({"name": ".bank", "start": "ram:0x1000", "size": 256, "uninitialized": false, "fill": 255, "permissions": "rx", "volatile": false, "overlay": "bank1"}),
            false,
        ),
        (
            vec!["memory", "block", "rename", "bank1:0x1000", ".renamed"],
            "memory_block_rename",
            json!({"block_start": "bank1:0x1000", "name": ".renamed"}),
            false,
        ),
        (
            vec![
                "memory",
                "block",
                "set-permissions",
                "bank1:0x1000",
                "--permissions",
                "none",
            ],
            "memory_block_set_permissions",
            json!({"block_start": "bank1:0x1000", "permissions": "none"}),
            false,
        ),
        (
            vec![
                "memory",
                "block",
                "set-volatile",
                "bank1:0x1000",
                "--value",
                "false",
            ],
            "memory_block_set_volatile",
            json!({"block_start": "bank1:0x1000", "value": false}),
            false,
        ),
        (
            vec![
                "memory",
                "block",
                "move",
                "ram:0x1234:0x10",
                "ram:0x1234:0x20",
            ],
            "memory_block_move",
            json!({"block_start": "ram:0x1234:0x10", "start": "ram:0x1234:0x20"}),
            false,
        ),
        (
            vec!["memory", "block", "delete", "word:0x1000.1"],
            "memory_block_delete",
            json!({"block_start": "word:0x1000.1"}),
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
            if !is_list {
                assert_eq!(result["data"]["changed"], true);
                assert_eq!(result["data"]["observed_program"], "B");
                assert!(result["data"].get("before").is_some());
                assert!(result["data"].get("after").is_some());
                assert!(result.get("meta").is_none());
            }
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
            assert_eq!(domain.len(), 1, "{requests:?}");
            assert_eq!(domain[0]["program"], "B");
            assert_eq!(domain[0]["command"], wire);
            assert_eq!(domain[0]["args"], expected_args);
        }
    }
}

#[test]
fn file_mapping_queries_preserve_exclusions_after_projection_paging_and_count() {
    let bridge = RecordedBridge::new();
    for batched in [false, true] {
        let defaults = run(&bridge, &["memory", "file-mappings"], batched);
        assert_eq!(defaults["data"].as_array().unwrap().len(), 1);
        assert_eq!(defaults["meta"]["limit"], 1);
        assert!(defaults["meta"].get("file_offset").is_none());
        assert!(defaults["meta"].get("source_at").is_none());
        let all = run(
            &bridge,
            &["memory", "file-mappings", "--limit", "0"],
            batched,
        );
        assert_eq!(all["data"].as_array().unwrap().len(), 3);
        assert!(all["meta"]["limit"].is_null());
        let base = [
            "memory",
            "file-mappings",
            "--file-offset",
            "0x205",
            "--source-at",
            "bank1:0x1005",
        ];
        let selected: Vec<_> = base
            .into_iter()
            .chain([
                "--filter",
                "address^\"ram:\"",
                "--sort=-address",
                "--skip",
                "1",
                "--limit",
                "1",
                "--fields",
                "address",
            ])
            .collect();
        assert_eq!(
            run(&bridge, &selected, batched),
            json!({
                "data": [{"address": "ram:0x1000"}],
                "meta": {
                    "file_offset": 517, "source_at": "bank1:0x1005",
                    "unsupported_mappings": defaults["meta"]["unsupported_mappings"],
                    "offset": 1, "limit": 1, "returned": 1,
                },
            })
        );
        let count = run(
            &bridge,
            &base.into_iter().chain(["--count"]).collect::<Vec<_>>(),
            batched,
        );
        assert_eq!(count["data"], 3);
        assert_eq!(
            count["meta"]["unsupported_mappings"],
            defaults["meta"]["unsupported_mappings"]
        );
        assert!(count["meta"].get("returned").is_none());
        let empty = run(
            &bridge,
            &["memory", "file-mappings", "--file-offset", "999"],
            batched,
        );
        assert_eq!(empty["data"], json!([]));
        assert_eq!(empty["meta"]["returned"], 0);
        assert_eq!(
            empty["meta"]["unsupported_mappings"],
            defaults["meta"]["unsupported_mappings"]
        );
    }
    for request in bridge
        .requests
        .lock()
        .unwrap()
        .iter()
        .filter(|r| r["command"] == "memory_file_mappings")
    {
        let args = request["args"].as_object().unwrap();
        assert!(
            args.keys()
                .all(|key| key == "file_offset" || key == "source_at"),
            "{request}"
        );
    }
}

#[test]
fn invalid_memory_addresses_fail_before_program_selection_including_batch_preflight() {
    let bridge = RecordedBridge::new();
    for args in [
        vec!["memory", "file-mappings", "--source-at", "main"],
        vec![
            "memory",
            "block",
            "create",
            ".ram",
            "--start",
            "ram:1000",
            "--size",
            "16",
            "--fill",
            "0",
            "--permissions",
            "rw",
        ],
        vec!["memory", "block", "rename", ".ram", ".renamed"],
        vec!["memory", "block", "move", "ram:0x1000", "entry"],
    ] {
        let args: Vec<_> = args
            .into_iter()
            .chain(["--program", "must-not-open"])
            .collect();
        let output = bridge.command().args(&args).output().unwrap();
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("Invalid address"),
            "{output:?}"
        );
        std::fs::write(bridge.root.path().join("batch.txt"), batch_arguments(&args)).unwrap();
        let output = bridge
            .command()
            .args(["batch", "batch.txt"])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        let report: Value = crate::json_output::from_slice(&output.stdout).unwrap();
        assert_eq!(report["commands_executed"], 0);
        assert_eq!(report["validation_failed"], true);
        assert!(report["validation_errors"][0]["error"]
            .as_str()
            .unwrap()
            .contains("Invalid address"));
        assert!(bridge.requests.lock().unwrap().is_empty());
    }
}
