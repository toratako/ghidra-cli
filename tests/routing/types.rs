use super::{batch_arguments, RecordedBridge};
use serde_json::{json, Value};

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

fn run_envelope(bridge: &RecordedBridge, args: &[&str], batch: bool) -> Value {
    let output = if batch {
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
        "{args:?}, batch={batch}: {output:?}"
    );
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    if batch {
        assert_eq!(result["data"]["failed"], 0);
        result["data"]["results"][0]["result"].clone()
    } else {
        result
    }
}

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
                "type", "create", "enum", "Mode", "--member", "Read", "1", "--member", "Write", "2",
            ],
            "type_create_enum",
            json!({"name": "Mode", "members": [{"name": "Read", "value": "1"}, {"name": "Write", "value": "2"}], "size": 4}),
        ),
        (
            vec![
                "type", "create", "enum", "WideMode", "--member", "Read", "1", "--size", "8",
            ],
            "type_create_enum",
            json!({"name": "WideMode", "members": [{"name": "Read", "value": "1"}], "size": 8}),
        ),
        (
            vec!["type", "create", "typedef", "HeaderPointer", "Header *"],
            "type_typedef",
            json!({"name": "HeaderPointer", "base_type": "Header *"}),
        ),
        (
            vec![
                "type",
                "clone",
                "/Protocol/Header",
                "HeaderV2",
                "--category",
                "/Draft",
            ],
            "type_clone",
            json!({"type_name": "/Protocol/Header", "new_name": "HeaderV2", "category": "/Draft"}),
        ),
        (
            vec!["type", "clone", "/Protocol/Header", "HeaderV2"],
            "type_clone",
            json!({"type_name": "/Protocol/Header", "new_name": "HeaderV2", "category": null}),
        ),
        (
            vec!["type", "resize", "/Draft/HeaderV2", "0x40"],
            "type_resize",
            json!({"type_name": "/Draft/HeaderV2", "size": 64}),
        ),
        (
            vec!["type", "resize", "/Draft/Empty", "0"],
            "type_resize",
            json!({"type_name": "/Draft/Empty", "size": 0}),
        ),
        (
            vec!["type", "move", "/Header", "/Protocol"],
            "type_move",
            json!({"type_name": "/Header", "category": "/Protocol"}),
        ),
        (
            vec!["type", "category", "create", "/Draft/Headers"],
            "type_category_create",
            json!({"path": "/Draft/Headers"}),
        ),
        (
            vec!["type", "category", "delete", "/Draft/Headers"],
            "type_category_delete",
            json!({"path": "/Draft/Headers"}),
        ),
        (
            vec![
                "type",
                "field",
                "create-bitfield",
                "/Flags",
                "--offset",
                "0x10",
                "--storage-size",
                "4",
                "--bit-offset",
                "0",
                "--bit-size",
                "3",
                "--type",
                "uint32_t",
                "--name",
                "mode",
                "--comment",
                "recovered",
            ],
            "type_field_create_bitfield",
            json!({"type_name": "/Flags", "offset": 16, "storage_size": 4,
                "bit_offset": 0, "bit_size": 3, "field_type": "uint32_t", "field_name": "mode", "comment": "recovered"}),
        ),
        (
            vec![
                "type",
                "field",
                "create-bitfield",
                "/Flags",
                "--offset",
                "0",
                "--storage-size",
                "1",
                "--bit-offset",
                "3",
                "--bit-size",
                "1",
                "--type",
                "byte",
            ],
            "type_field_create_bitfield",
            json!({"type_name": "/Flags", "offset": 0, "storage_size": 1,
                "bit_offset": 3, "bit_size": 1, "field_type": "byte", "field_name": null, "comment": null}),
        ),
        (
            vec![
                "type",
                "enum",
                "member",
                "delete",
                "/Recovered/Mode",
                "--member",
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
                "field_name": "flags", "field_type": "uint", "comment": "", "size": null, "bit_size": null}),
        ),
        (
            vec![
                "type",
                "field",
                "set",
                "/Flags",
                "--field",
                "mode",
                "--bit-size",
                "4",
            ],
            "type_field_set",
            json!({"type_name": "/Flags", "offset": null, "ordinal": null, "field": "mode",
                "field_name": null, "field_type": null, "comment": null, "size": null, "bit_size": 4}),
        ),
        (
            vec![
                "type",
                "field",
                "set",
                "/Flags",
                "--ordinal",
                "1",
                "--comment",
                "recovered flags",
            ],
            "type_field_set",
            json!({"type_name": "/Flags", "offset": null, "ordinal": 1, "field": null,
                "field_name": null, "field_type": null, "comment": "recovered flags", "size": null, "bit_size": null}),
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
                "field_name": "options", "field_type": null, "comment": null, "size": null, "bit_size": null}),
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
            json!({"type_name": "/Recovered/Header", "field": "flags", "offset": null, "ordinal": null}),
        ),
        (
            vec!["type", "field", "clear", "/Flags", "--ordinal", "1"],
            "type_field_clear",
            json!({"type_name": "/Flags", "field": null, "offset": null, "ordinal": 1}),
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
        let mut standalone = Value::Null;
        for batch in [false, true] {
            outer.requests.lock().unwrap().clear();
            selected.requests.lock().unwrap().clear();
            let result = run_envelope(&outer, &args, batch);
            assert!(result["data"].is_object(), "{args:?}: {result}");
            assert!(result.get("meta").is_none(), "{args:?}: {result}");
            assert_eq!(
                result["data"]["observed_program"], "B",
                "{args:?}: {result}"
            );
            if batch {
                assert_eq!(result, standalone, "{args:?}");
            } else {
                standalone = result;
            }
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
fn category_queries_keep_path_context_and_apply_query_options_in_the_client() {
    let outer = RecordedBridge::new();
    let selected = RecordedBridge::new();
    for batch in [false, true] {
        for (path, query, expected) in [
            (
                "/Protocol",
                vec![
                    "--filter",
                    "type_count>0",
                    "--sort",
                    "name",
                    "--offset",
                    "1",
                    "--limit",
                    "1",
                    "--fields",
                    "path,type_count",
                ],
                json!({"data": [{"path": "/Protocol/beta", "type_count": 1}],
                    "meta": {"path": "/Protocol", "offset": 1, "limit": 1, "returned": 1}}),
            ),
            (
                "/",
                vec!["--sort", "name", "--limit", "0"],
                json!({"data": [
                    {"name": "alpha", "path": "/alpha", "type_count": 2},
                    {"name": "beta", "path": "/beta", "type_count": 1},
                    {"name": "zeta", "path": "/zeta", "type_count": 0}],
                    "meta": {"path": "/", "offset": 0, "limit": null, "returned": 3}}),
            ),
            (
                "/Protocol",
                vec!["--filter", "type_count>0", "--count", "--limit", "0"],
                json!({"data": 2, "meta": {"path": "/Protocol", "offset": 0, "limit": null}}),
            ),
            (
                "/Empty",
                vec!["--limit", "0"],
                json!({"data": [], "meta": {"path": "/Empty", "offset": 0, "limit": null, "returned": 0}}),
            ),
        ] {
            selected.requests.lock().unwrap().clear();
            let mut args = vec!["type", "category", "list", path];
            args.extend(query);
            args.extend([
                "--project",
                selected.project.to_str().unwrap(),
                "--program",
                "B",
            ]);
            assert_eq!(run_envelope(&outer, &args, batch), expected);
            let requests = selected.requests.lock().unwrap();
            let domain: Vec<_> = requests
                .iter()
                .filter(|r| r["command"] != "bridge_info")
                .collect();
            assert_eq!(domain.len(), 2);
            assert_eq!(domain[0]["command"], "open_program");
            assert_eq!(domain[0]["args"], json!({"program": "B"}));
            assert_eq!(domain[1]["command"], "type_category_list");
            assert_eq!(domain[1]["args"], json!({"path": path}));
        }
    }
    for (path, expected_rows) in [("/", 3), ("/Empty", 0)] {
        let output = selected
            .command()
            .args([
                "type", "category", "list", path, "--format", "ndjson", "--fields", "path",
                "--limit", "0",
            ])
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let rows: Vec<Value> = String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .map(|row| serde_json::from_str(row).unwrap())
            .collect();
        assert_eq!(rows.len(), expected_rows);
        assert!(rows
            .iter()
            .all(|row| row.as_object().unwrap().len() == 1 && row["path"].is_string()));
    }
}

#[test]
fn new_type_edit_receipts_keep_nested_fields_and_support_projection() {
    let bridge = RecordedBridge::new();
    for batch in [false, true] {
        for mut args in [
            vec!["type", "clone", "/Header", "Draft"],
            vec!["type", "resize", "/Header", "64"],
            vec!["type", "move", "/Header", "/Protocol"],
            vec!["type", "category", "create", "/Draft"],
            vec!["type", "category", "delete", "/Draft"],
            vec![
                "type",
                "field",
                "create-bitfield",
                "/Flags",
                "--offset",
                "0",
                "--storage-size",
                "4",
                "--bit-offset",
                "0",
                "--bit-size",
                "3",
                "--type",
                "uint",
            ],
        ] {
            args.extend(["--fields", "changed,before,after"]);
            assert_eq!(
                run_envelope(&bridge, &args, batch),
                json!({"data": {
                    "changed": true,
                    "before": {"fields": [{"name": "flags", "bit_size": 3}]},
                    "after": {"fields": [{"name": "flags", "bit_size": 4}]},
                }})
            );
        }
    }
}

#[test]
fn invalid_type_bounds_and_queries_fail_before_standalone_or_batch_bridge_work() {
    let bridge = RecordedBridge::new();
    for args in [
        vec!["type", "resize", "/Header", "2147483648"],
        vec![
            "type",
            "field",
            "set",
            "/Flags",
            "--ordinal",
            "1",
            "--bit-size",
            "0",
        ],
        vec![
            "type",
            "field",
            "create-bitfield",
            "/Flags",
            "--offset",
            "0",
            "--storage-size",
            "0",
            "--bit-offset",
            "0",
            "--bit-size",
            "3",
            "--type",
            "uint",
        ],
        vec!["type", "category", "list", "/", "--filter", "invalid"],
    ] {
        let args: Vec<_> = args
            .into_iter()
            .chain(["--program", "must-not-open"])
            .collect();
        let output = bridge.command().args(&args).output().unwrap();
        assert!(!output.status.success(), "{args:?}: {output:?}");
        std::fs::write(
            bridge.root.path().join("batch.txt"),
            format!("program info\n{}", batch_arguments(&args)),
        )
        .unwrap();
        let output = bridge
            .command()
            .args(["batch", "batch.txt"])
            .output()
            .unwrap();
        assert!(!output.status.success(), "{args:?}: {output:?}");
        let result: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(result["data"]["commands_executed"], 0);
        assert!(bridge.requests.lock().unwrap().is_empty(), "{args:?}");
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
                "bit_size": null,
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
            json!({"type_name": "/Recovered/Manager", "offset": 28, "field": null, "ordinal": null})
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
            .any(|r| r["command"] == "open_program" && r["args"]["program"] == "B"));
        requests.clear();
    }
}
