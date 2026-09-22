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
        "unsupported_mappings": [{"address": "ram:0x3000", "reason": "byte_mapped"}],
    });
    if let Some(offset) = file_offset {
        result["file_offset"] = json!(offset);
    }
    if let Some(source_at) = args.get("source_at") {
        result["source_at"] = source_at.clone();
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
                "--offset",
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
                    "unsupported_mappings": [{"address": "ram:0x3000", "reason": "byte_mapped"}],
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
