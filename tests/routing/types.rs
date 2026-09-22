use super::{batch_arguments, RecordedBridge};
use serde_json::{json, Value};

#[test]
fn type_operations_preserve_wire_requests_and_targets_in_standalone_and_batch() {
    let outer = RecordedBridge::new();
    let selected = RecordedBridge::new();
    for (mut args, wire, expected) in [
        (
            vec!["type", "create", "struct", "Header"],
            "type_create",
            json!({"definition": "Header"}),
        ),
        (
            vec!["type", "create", "union", "Payload"],
            "type_create_union",
            json!({"name": "Payload"}),
        ),
        (
            vec![
                "type",
                "create",
                "enum",
                "Mode",
                "--values",
                "Read=1,Write=2",
            ],
            "type_create_enum",
            json!({"name": "Mode", "values": "Read=1,Write=2", "size": 4}),
        ),
        (
            vec![
                "type", "create", "enum", "WideMode", "--values", "Read=1", "--size", "8",
            ],
            "type_create_enum",
            json!({"name": "WideMode", "values": "Read=1", "size": 8}),
        ),
        (
            vec!["type", "create", "typedef", "HeaderPointer", "Header *"],
            "type_typedef",
            json!({"name": "HeaderPointer", "base_type": "Header *"}),
        ),
        (
            vec![
                "type",
                "enum",
                "member",
                "delete",
                "/Recovered/Mode",
                "--name",
                "Read",
            ],
            "type_enum_member_delete",
            json!({"type_name": "/Recovered/Mode", "member_name": "Read"}),
        ),
        (
            vec![
                "type",
                "field",
                "set",
                "/Recovered/Payload",
                "--ordinal",
                "1",
                "--name",
                "flags",
                "--type",
                "uint",
                "--comment",
                "",
            ],
            "type_field_set",
            json!({"type_name": "/Recovered/Payload", "offset": null, "ordinal": 1, "field": null,
                "field_name": "flags", "field_type": "uint", "comment": "", "size": null}),
        ),
        (
            vec![
                "type",
                "field",
                "delete",
                "/Recovered/Payload",
                "--ordinal",
                "0",
            ],
            "type_field_delete",
            json!({"type_name": "/Recovered/Payload", "offset": null, "field": null, "ordinal": 0}),
        ),
        (
            vec![
                "type",
                "field",
                "delete",
                "/Recovered/Payload",
                "--field",
                "flags",
            ],
            "type_field_delete",
            json!({"type_name": "/Recovered/Payload", "offset": null, "field": "flags", "ordinal": null}),
        ),
        (
            vec![
                "type",
                "field",
                "append",
                "/Recovered/Header",
                "--name",
                "flags",
                "--type",
                "uint",
            ],
            "type_field_append",
            json!({"type_name": "/Recovered/Header", "field_name": "flags", "field_type": "uint", "size": null}),
        ),
        (
            vec![
                "type",
                "field",
                "set",
                "/Recovered/Header",
                "--field",
                "flags",
                "--name",
                "options",
            ],
            "type_field_set",
            json!({"type_name": "/Recovered/Header", "field": "flags", "offset": null, "ordinal": null,
                "field_name": "options", "field_type": null, "comment": null, "size": null}),
        ),
        (
            vec![
                "type",
                "field",
                "clear",
                "/Recovered/Header",
                "--field",
                "flags",
            ],
            "type_field_clear",
            json!({"type_name": "/Recovered/Header", "field": "flags", "offset": null}),
        ),
        (
            vec![
                "type",
                "field",
                "delete",
                "/Recovered/Header",
                "--offset",
                "0x10",
            ],
            "type_field_delete",
            json!({"type_name": "/Recovered/Header", "field": null, "offset": 16, "ordinal": null}),
        ),
    ] {
        args.extend([
            "--project",
            selected.project.to_str().unwrap(),
            "--program",
            "B",
        ]);
        for batch in [false, true] {
            outer.requests.lock().unwrap().clear();
            selected.requests.lock().unwrap().clear();
            let result = if batch {
                std::fs::write(outer.root.path().join("batch.txt"), batch_arguments(&args))
                    .unwrap();
                let report = outer.run(&["batch", "batch.txt"]);
                assert_eq!(report["failed"], 0, "{args:?}: {report}");
                report["results"][0]["result"]["data"].clone()
            } else {
                outer.run(&args)
            };
            assert_eq!(result["observed_program"], "B", "{args:?}: {result}");
            let requests = selected.requests.lock().unwrap();
            let domain: Vec<_> = requests
                .iter()
                .filter(|request| request["command"] != "bridge_info")
                .collect();
            assert_eq!(domain.len(), 2, "{args:?}: {domain:?}");
            assert_eq!(domain[0]["command"], "open_program");
            assert_eq!(domain[0]["args"]["program"], "B");
            assert_eq!(domain[1]["command"], wire);
            assert_eq!(domain[1]["args"], expected, "{args:?}");
            assert!(outer
                .requests
                .lock()
                .unwrap()
                .iter()
                .all(|request| request["command"] == "bridge_info"));
        }
    }
}

#[test]
fn type_import_reads_code_files_and_stdin_in_the_client() {
    let bridge = RecordedBridge::new();
    let code = "// 日本語\nstruct Header { int size; };\n";
    std::fs::write(bridge.root.path().join("recovered types.h"), code).unwrap();
    for (args, input) in [
        (
            vec!["type", "import-c", code, "--category", "/Recovered"],
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
            })
        );
        assert!(requests
            .iter()
            .any(|r| r["command"] == "open_program" && r["args"]["program"] == "B"));
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
            json!({"type_name": "/Recovered/Manager", "offset": 28, "field": null})
        );
        assert!(requests
            .iter()
            .any(|r| r["command"] == "open_program" && r["args"]["program"] == "B"));
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
            "edit-var",
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
            .filter(|r| r["command"] == "function_edit_var")
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
            .any(|r| r["command"] == "open_program" && r["args"]["program"] == "B"));
        requests.clear();
    }
}
