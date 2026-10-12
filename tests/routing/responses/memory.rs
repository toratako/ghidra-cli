//! Recorded memory response fixtures.

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
