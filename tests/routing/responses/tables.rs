//! Recorded tables response fixtures.

use serde_json::{json, Value};

pub(crate) fn vtable_fixture(args: &Value, program: &str) -> Value {
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

pub(crate) fn address_tables_fixture(args: &Value) -> Value {
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
