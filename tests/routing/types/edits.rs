use super::RecordedBridge;
use serde_json::{json, Value};

#[test]
fn type_import_reads_code_files_and_stdin_in_the_client() {
    let bridge = RecordedBridge::new();
    let code = "// 日本語\nstruct Header { int size; };\n";
    std::fs::write(bridge.root.path().join("recovered types.h"), code).unwrap();
    for (args, input) in [
        (
            vec![
                "type",
                "import-c",
                "--code",
                code,
                "--category",
                "/Recovered",
            ],
            None,
        ),
        (
            vec![
                "type",
                "import-c",
                "--file",
                "recovered types.h",
                "--category",
                "/Recovered",
            ],
            None,
        ),
        (
            vec!["type", "import-c", "--stdin", "--category", "/Recovered"],
            Some(code),
        ),
    ] {
        let mut command = bridge.command();
        command.args(args);
        if let Some(input) = input {
            command.write_stdin(input);
        }
        command.assert().success();
        let mut requests = bridge.requests.lock().unwrap();
        let imports: Vec<_> = requests
            .iter()
            .filter(|r| r["command"] == "type_import_c")
            .collect();
        assert_eq!(imports.len(), 1);
        assert_eq!(
            imports[0]["args"],
            json!({"code": code, "category": "/Recovered"})
        );
        requests.clear();
    }
    for file in ["missing.h", "empty.h", "invalid.h"] {
        if file == "empty.h" {
            std::fs::write(bridge.root.path().join(file), " \n").unwrap();
        }
        if file == "invalid.h" {
            std::fs::write(bridge.root.path().join(file), [0xff]).unwrap();
        }
        bridge
            .command()
            .args(["type", "import-c", "--file", file])
            .assert()
            .failure();
    }
    bridge
        .command()
        .args(["type", "import-c", "--stdin"])
        .write_stdin(" ")
        .assert()
        .failure();
    assert!(!bridge
        .requests
        .lock()
        .unwrap()
        .iter()
        .any(|r| r["command"] == "type_import_c"));
}

#[test]
fn field_edits_route_offsets_and_preserve_omitted_attributes() {
    let bridge = RecordedBridge::new();
    for (offset, flags, name, field_type, comment, size) in [
        (
            "0x1c",
            vec![
                "--name",
                "hook",
                "--type",
                "Hook *",
                "--comment",
                "callback",
            ],
            json!("hook"),
            json!("Hook *"),
            json!("callback"),
            Value::Null,
        ),
        (
            "28",
            vec!["--name", "hook"],
            json!("hook"),
            Value::Null,
            Value::Null,
            Value::Null,
        ),
        (
            "0X1C",
            vec!["--type", "Hook *"],
            Value::Null,
            json!("Hook *"),
            Value::Null,
            Value::Null,
        ),
        (
            "28",
            vec!["--comment", ""],
            Value::Null,
            Value::Null,
            json!(""),
            Value::Null,
        ),
        (
            "0x1c",
            vec!["--type", "string", "--size", "8"],
            Value::Null,
            json!("string"),
            Value::Null,
            json!(8),
        ),
    ] {
        let mut args = vec![
            "type",
            "field",
            "set",
            "/Recovered/Manager",
            "--offset",
            offset,
            "--program",
            "B",
        ];
        args.extend(flags);
        bridge.run(&args);
        let mut requests = bridge.requests.lock().unwrap();
        let edits: Vec<_> = requests
            .iter()
            .filter(|r| r["command"] == "type_field_set")
            .collect();
        assert_eq!(edits.len(), 1);
        assert_eq!(
            edits[0]["args"],
            json!({
                "type_name": "/Recovered/Manager", "offset": 28, "ordinal": null, "field": null,
                "field_name": name, "field_type": field_type, "comment": comment, "size": size,
                "bit_size": null,
            })
        );
        assert!(requests
            .iter()
            .filter(|r| r["command"] != "bridge_info")
            .all(|r| r["program"] == "B"));
        requests.clear();
    }
    bridge.run(&[
        "type",
        "field",
        "clear",
        "/Recovered/Manager",
        "--offset",
        "0x1c",
        "--program",
        "B",
    ]);
    {
        let mut requests = bridge.requests.lock().unwrap();
        let edits: Vec<_> = requests
            .iter()
            .filter(|r| r["command"] == "type_field_clear")
            .collect();
        assert_eq!(edits.len(), 1);
        assert_eq!(
            edits[0]["args"],
            json!({"type_name": "/Recovered/Manager", "offset": 28, "field": null, "ordinal": null})
        );
        assert!(requests
            .iter()
            .filter(|r| r["command"] != "bridge_info")
            .all(|r| r["program"] == "B"));
        requests.clear();
    }
    bridge.run(&[
        "type", "field", "append", "Manager", "--name", "hook", "--type", "Hook *",
    ]);
    let requests = bridge.requests.lock().unwrap();
    let added = requests
        .iter()
        .find(|r| r["command"] == "type_field_append")
        .unwrap();
    assert_eq!(
        added["args"],
        json!({
            "type_name": "Manager", "field_name": "hook", "field_type": "Hook *", "size": null,
        })
    );
}

#[test]
fn variable_edits_send_one_request_with_only_requested_attributes() {
    let bridge = RecordedBridge::new();
    for (flags, name, data_type) in [
        (
            vec!["--name", "header", "--type", "Header *"],
            json!("header"),
            json!("Header *"),
        ),
        (vec!["--name", "header"], json!("header"), Value::Null),
        (vec!["--type", "Header *"], Value::Null, json!("Header *")),
    ] {
        let mut args = vec![
            "function",
            "var",
            "set",
            "parse_header",
            "--var",
            "local_10",
            "--program",
            "B",
        ];
        args.extend(flags);
        bridge.run(&args);
        let mut requests = bridge.requests.lock().unwrap();
        let edits: Vec<_> = requests
            .iter()
            .filter(|r| r["command"] == "function_var_set")
            .collect();
        assert_eq!(edits.len(), 1);
        assert_eq!(
            edits[0]["args"],
            json!({
                "target": "parse_header", "var_name": "local_10", "new_name": name, "type_name": data_type,
                "timeout_secs": 0,
            })
        );
        assert!(requests
            .iter()
            .filter(|r| r["command"] != "bridge_info")
            .all(|r| r["program"] == "B"));
        requests.clear();
    }
}
