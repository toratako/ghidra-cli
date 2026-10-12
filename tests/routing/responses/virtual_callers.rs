//! Recorded virtual callers response fixtures.

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
