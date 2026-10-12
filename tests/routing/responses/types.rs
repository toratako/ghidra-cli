//! Recorded types response fixtures.

use serde_json::{json, Value};

pub(crate) fn gdt_candidates_fixture(args: &Value) -> Value {
    let types: Vec<_> = ["zeta", "alpha", "beta"]
        .into_iter()
        .enumerate()
        .map(|(i, name)| {
            json!({"name": name, "path": format!("/Protocol/{name}"), "category": "/Protocol",
            "kind": "struct", "size": i + 1, "universal_id": format!("900719925474099{}", i + 1),
            "source_archive": {"id": "9007199254740999", "name": "sdk", "kind": "FILE"}})
        })
        .collect();
    json!({"types": types, "archive": {"path": args["file"], "id": "9007199254740999", "name": "sdk"},
        "source": {"kind": if args["file"].is_string() {"archive"} else {"program"},
            "file": args["file"], "stamp": "9007199254740999", "nested": {"opaque": true}}})
}

pub(super) fn gdt_transfer_fixture(command: &str, args: &Value) -> Value {
    let roots = if args["all"] == true {
        json!(["/Protocol/zeta", "/Protocol/alpha", "/Protocol/beta"])
    } else {
        args["paths"].clone()
    };
    json!({"status": if command == "type_import_gdt" {"imported"} else {"exported"},
        "roots": roots, "dependencies": ["/Dependency"], "changed": true,
        "source": args["source"], "archive": {"path": args["file"]}})
}

pub(super) fn category_list_fixture(args: &Value) -> Value {
    let path = args["path"].as_str().unwrap();
    let categories = if path == "/Empty" {
        vec![]
    } else {
        [("zeta", 0), ("alpha", 2), ("beta", 1)]
            .into_iter()
            .map(|(name, type_count)| {
                json!({
                    "name": name, "path": format!("{}/{name}", path.trim_end_matches('/')),
                    "type_count": type_count,
                })
            })
            .collect()
    };
    json!({"path": path, "categories": categories})
}

pub(super) fn uses_fixture(args: &Value) -> Value {
    let mut rows = if args["type_name"] == "/Unused" {
        vec![]
    } else if args["kind"] == "variable" {
        vec![
            json!({"kind":"variable", "role":"parameter", "function":"process", "name":"ctx", "address":"0x1000"}),
            json!({"kind":"variable", "role":"local", "function":"process", "name":"zeta", "address":"0x1000"}),
            json!({"kind":"variable", "role":"local", "function":"process", "name":"alpha", "address":"0x1000"}),
        ]
    } else {
        vec![
            json!({"kind":"data", "name":"zeta", "address":"0x2000"}),
            json!({"kind":"data", "name":"alpha", "address":"0x2040"}),
            json!({"kind":"signature", "role":"return", "function":"process", "name":"result", "address":"0x1000"}),
            json!({"kind":"signature", "role":"parameter", "function":"process", "name":"ctx", "address":"0x1000"}),
        ]
    };
    if let Some(kind) = args["kind"].as_str() {
        rows.retain(|row| row["kind"] == kind);
    }
    let count = rows.len();
    if let Some(limit) = args["limit"].as_u64().filter(|limit| *limit != 0) {
        rows.truncate(limit as usize);
    }
    let complete = rows.len() == count;
    let mut result = json!({"uses":rows, "target_type_path":args["type_name"],
        "kinds":args["kind"].as_str().map_or(json!(["data", "signature"]), |kind| json!([kind])),
        "scan":{"complete":complete, "stop_reason":if complete { Value::Null } else { json!("limit") }}});
    if args["kind"] == "variable" {
        result["scope"] = semantic_scope(args);
    }
    result
}

fn semantic_scope(args: &Value) -> Value {
    args["function"].as_str().map_or(
        Value::Null,
        |function| json!({"function":function, "address":"0x1000"}),
    )
}

pub(super) fn field_uses_fixture(args: &Value) -> Value {
    let mut uses = vec![
        json!({"function":"process", "instruction_address":"0x1010", "access":"read"}),
        json!({"function":"process", "instruction_address":"0x1020", "access":"write"}),
        json!({"function":"process", "instruction_address":"0x1030", "access":"address"}),
    ];
    let count = uses.len();
    if let Some(limit) = args["limit"].as_u64().filter(|limit| *limit != 0) {
        uses.truncate(limit as usize);
    }
    let complete = uses.len() == count;
    json!({"uses":uses, "target_type_path":args["type_name"],
        "target_field":{"name":"flags", "offset":16, "ordinal":2},
        "scope":semantic_scope(args),
        "scan":{"complete":complete, "stop_reason":if complete { Value::Null } else { json!("limit") }}})
}
