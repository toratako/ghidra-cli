//! Recorded function candidates response fixtures.

use serde_json::{json, Value};

pub(crate) fn fixture(args: &Value) -> Value {
    let mut rows: Vec<_> = [1, 3, 3, 8]
        .into_iter()
        .enumerate()
        .map(|(index, calls)| {
            let evidence: Vec<_> = (0..calls.min(5))
                .map(|site| {
                    json!({
                        "from": format!("bank1:0x{:x}", 0x8000 + index * 0x100 + site * 5),
                        "caller": "dispatch", "caller_address": "bank1:0x8000",
                        "type": "UNCONDITIONAL_CALL", "source": "ANALYSIS", "operand": 0,
                    })
                })
                .collect();
            json!({
                "address": format!("bank1:0x{:x}", 0x1000 + index * 0x1000),
                "block": if index == 0 { ".plt" } else { ".text" },
                "instruction": "RET", "call_count": calls,
                "evidence": evidence, "evidence_omitted": calls - evidence.len(),
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
    json!({
        "results": rows, "count": rows.len(), "scope": "candidate-starts",
        "ranges": [{"start": "bank1:0x1000", "end": "bank1:0x7000"}],
        "scan": if limited {
            json!({"complete": false, "stop_reason": "limit"})
        } else {
            json!({"complete": true})
        },
    })
}
