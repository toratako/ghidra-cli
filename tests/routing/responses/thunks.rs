//! Recorded thunks response fixtures.

use serde_json::{json, Value};

pub(crate) fn receipt_fixture(set: bool) -> Value {
    let before = json!({
        "name": "wrapper", "address": "overlay:0x1000", "namespace": "app",
        "is_thunk": false, "signature": "int wrapper(int first, int second)",
        "calling_convention": "__cdecl",
        "signature_details": {
            "storage_mode": "dynamic", "source": "USER_DEFINED", "variadic": false,
            "thunk_function": null, "thunk_address": null,
            "effective_function": "wrapper", "effective_address": "overlay:0x1000",
            "return": {"type": "int", "type_path": "/int", "size": 4, "storage": "EAX:4", "forced_indirect": false},
            "params": [
                {"ordinal": 0, "name": "first", "type": "int", "type_path": "/int", "size": 4, "storage": "Stack[0x4]:4", "forced_indirect": false, "auto_parameter": null},
                {"ordinal": 1, "name": "second", "type": "int", "type_path": "/int", "size": 4, "storage": "Stack[0x8]:4", "forced_indirect": false, "auto_parameter": null},
            ],
        },
    });
    let mut after = before.clone();
    if set {
        after["is_thunk"] = json!(true);
        after["signature_details"]["thunk_function"] = json!("dispatch");
        after["signature_details"]["thunk_address"] = json!("overlay:0x2000");
        after["signature_details"]["effective_function"] = json!("implementation");
        after["signature_details"]["effective_address"] = json!("overlay:0x3000");
    }
    json!({
        "status": if set { "updated" } else { "unchanged" },
        "function": "wrapper", "address": "overlay:0x1000", "before": before, "after": after,
    })
}
