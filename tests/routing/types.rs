use super::{batch_arguments, RecordedBridge};
use serde_json::{json, Value};

pub(super) fn gdt_candidates_fixture(args: &Value) -> Value {
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

#[test]
fn gdt_transfers_select_uncapped_roots_and_forward_the_source_guard() {
    let outer = RecordedBridge::new();
    let selected = RecordedBridge::new();
    std::fs::write(outer.root.path().join("sdk 日本語's types.gdt"), "archive").unwrap();
    for (command, wire, file) in [
        ("import-gdt", "type_import_gdt", "sdk 日本語's types.gdt"),
        ("export-gdt", "type_export_gdt", "new 日本語's types.gdt"),
    ] {
        let absolute = outer.root.path().join(file);
        for all in [false, true] {
            for batch in [false, true] {
                selected.requests.lock().unwrap().clear();
                let mut args = vec![
                    "type",
                    command,
                    file,
                    "--project",
                    selected.project.to_str().unwrap(),
                    "--program",
                    "B",
                ];
                if all {
                    args.push("--all");
                } else {
                    args.extend(["--where", "category=\"/Protocol\""]);
                }
                args.extend(["--fields", "roots,dependencies"]);
                let output = run_envelope(&outer, &args, batch);
                assert_eq!(
                    output,
                    json!({"data": {
                        "roots": ["/Protocol/zeta", "/Protocol/alpha", "/Protocol/beta"],
                        "dependencies": ["/Dependency"],
                    }})
                );
                let requests = selected.requests.lock().unwrap();
                let domain: Vec<_> = requests
                    .iter()
                    .filter(|r| r["command"] != "bridge_info")
                    .collect();
                assert_eq!(domain.len(), if all { 1 } else { 2 }, "{domain:?}");
                assert!(domain.iter().all(|r| r["program"] == "B"));
                let edit = domain.last().unwrap();
                assert_eq!(edit["command"], wire);
                let expected = if all {
                    json!({"file": absolute, "all": true})
                } else {
                    let candidate_args = if command == "import-gdt" {
                        json!({"file": absolute})
                    } else {
                        json!({})
                    };
                    assert_eq!(domain[0]["command"], "type_gdt_candidates");
                    assert_eq!(domain[0]["args"], candidate_args);
                    json!({"file": absolute,
                        "paths": ["/Protocol/zeta", "/Protocol/alpha", "/Protocol/beta"],
                        "source": gdt_candidates_fixture(&candidate_args)["source"]})
                };
                assert_eq!(edit["args"], expected);
            }
        }
    }
    assert!(outer.requests.lock().unwrap().is_empty());
}

#[test]
fn gdt_selection_errors_never_send_a_mutation() {
    let bridge = RecordedBridge::new();
    std::fs::write(bridge.root.path().join("sdk.gdt"), "archive").unwrap();
    for (expression, error, candidate_expected) in [
        ("invalid", "invalid --where", false),
        ("name=absent", "No types match --where", true),
        ("size=wrong", "Cannot compare number", true),
    ] {
        for batch in [false, true] {
            bridge.requests.lock().unwrap().clear();
            let args = ["type", "import-gdt", "sdk.gdt", "--where", expression];
            let output = if batch {
                std::fs::write(bridge.root.path().join("batch.txt"), batch_arguments(&args))
                    .unwrap();
                bridge
                    .command()
                    .args(["batch", "batch.txt"])
                    .output()
                    .unwrap()
            } else {
                bridge.command().args(args).output().unwrap()
            };
            assert!(
                !output.status.success(),
                "{expression}, batch={batch}: {output:?}"
            );
            let diagnostics = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(diagnostics.contains(error), "{expression}: {diagnostics}");
            let requests = bridge.requests.lock().unwrap();
            if !candidate_expected {
                assert!(requests.is_empty(), "{requests:?}");
            } else {
                assert_eq!(
                    requests
                        .iter()
                        .filter(|r| r["command"] == "type_gdt_candidates")
                        .count(),
                    1
                );
            }
            assert!(!requests.iter().any(|r| r["command"] == "type_import_gdt"));
        }
    }
}

#[test]
fn gdt_archive_queries_retain_archive_context_and_query_all_rows() {
    let outer = RecordedBridge::new();
    let selected = RecordedBridge::new();
    std::fs::write(outer.root.path().join("sdk types.gdt"), "archive").unwrap();
    for (query, expected) in [
        (vec!["--fields", "name"], json!([{"name": "zeta"}])),
        (
            vec!["--filter", "name=beta", "--fields", "name"],
            json!([{"name": "beta"}]),
        ),
        (
            vec![
                "--sort", "name", "--skip", "1", "--limit", "1", "--fields", "name",
            ],
            json!([{"name": "beta"}]),
        ),
        (vec!["--count"], json!(3)),
        (vec!["--filter", "name=absent"], json!([])),
    ] {
        let mut standalone = Value::Null;
        for batch in [false, true] {
            selected.requests.lock().unwrap().clear();
            let mut args = vec![
                "type",
                "archive",
                "list",
                "sdk types.gdt",
                "--project",
                selected.project.to_str().unwrap(),
            ];
            args.extend(query.iter().copied());
            let output = run_envelope(&outer, &args, batch);
            assert_eq!(output["data"], expected);
            assert_eq!(
                output["meta"]["archive"],
                json!({"path": outer.root.path().join("sdk types.gdt"), "id": "9007199254740999", "name": "sdk"})
            );
            if batch {
                assert_eq!(output, standalone);
            } else {
                standalone = output;
            }
            let requests = selected.requests.lock().unwrap();
            let domain: Vec<_> = requests
                .iter()
                .filter(|r| r["command"] != "bridge_info")
                .collect();
            assert_eq!(domain.len(), 1);
            assert_eq!(domain[0]["command"], "type_archive_list");
            assert_eq!(
                domain[0]["args"],
                json!({"file": outer.root.path().join("sdk types.gdt")})
            );
            assert!(domain[0]["program"].is_null());
        }
    }
    assert!(outer.requests.lock().unwrap().is_empty());
}

#[test]
fn gdt_archive_inspection_ignores_default_and_inherited_program_without_changing_batch_intent() {
    let bridge = RecordedBridge::with_info(json!({"protocol_version": 4, "auto_save": true,
        "atomic_edits": true, "named_import": true, "explicit_addresses": true,
        "test_interleave_program": "concurrent"}));
    std::fs::write(bridge.root.path().join("sdk.gdt"), "archive").unwrap();
    std::fs::write(
        bridge.root.path().join("config.yaml"),
        "default_limit: 1\ndefault_program: configured\n",
    )
    .unwrap();
    run_envelope(&bridge, &["type", "archive", "list", "sdk.gdt"], false);
    {
        let mut requests = bridge.requests.lock().unwrap();
        assert!(
            requests.iter().all(|r| r["program"].is_null()),
            "{requests:?}"
        );
        requests.clear();
    }
    std::fs::write(
        bridge.root.path().join("batch.txt"),
        "program info\ntype archive list sdk.gdt\nprogram info\n",
    )
    .unwrap();
    bridge
        .command()
        .args(["batch", "batch.txt", "--program", "B"])
        .assert()
        .success();
    let requests = bridge.requests.lock().unwrap();
    let domain: Vec<_> = requests
        .iter()
        .filter(|r| r["command"] != "bridge_info")
        .collect();
    assert_eq!(domain.len(), 3);
    assert_eq!(domain[0]["program"], "B");
    assert_eq!(domain[1]["command"], "type_archive_list");
    assert!(domain[1]["program"].is_null());
    assert_eq!(domain[2]["program"], "B");
}

#[test]
fn gdt_archive_inspection_rejects_explicit_program_before_bridge_work() {
    let bridge = RecordedBridge::new();
    for batch in [false, true] {
        let args = ["--program", "B", "type", "archive", "list", "sdk.gdt"];
        if batch {
            std::fs::write(
                bridge.root.path().join("batch.txt"),
                format!("program info\n{}\n", batch_arguments(&args)),
            )
            .unwrap();
            bridge
                .command()
                .args(["batch", "batch.txt"])
                .assert()
                .failure();
        } else {
            bridge.command().args(args).assert().failure();
        }
        assert!(bridge.requests.lock().unwrap().is_empty());
    }
}

#[test]
fn gdt_paths_reject_invalid_input_and_existing_output_before_archive_requests() {
    let bridge = RecordedBridge::new();
    std::fs::write(bridge.root.path().join("existing.gdt"), "preserve").unwrap();
    std::fs::create_dir(bridge.root.path().join("directory.gdt")).unwrap();
    for args in [
        vec!["type", "import-gdt", "missing.gdt", "--all"],
        vec!["type", "archive", "list", "directory.gdt"],
        vec!["type", "export-gdt", "existing.gdt", "--all"],
        vec!["type", "export-gdt", "directory.gdt", "--all"],
        vec!["type", "export-gdt", "missing/new.gdt", "--all"],
        vec!["type", "export-gdt", "without-extension", "--all"],
    ] {
        bridge.requests.lock().unwrap().clear();
        bridge.command().args(&args).assert().failure();
        assert!(
            bridge
                .requests
                .lock()
                .unwrap()
                .iter()
                .all(|r| r["command"] == "bridge_info"),
            "{args:?}"
        );
    }
    assert_eq!(
        std::fs::read_to_string(bridge.root.path().join("existing.gdt")).unwrap(),
        "preserve"
    );
    assert!(!bridge.root.path().join("without-extension.gdt").exists());
}

#[cfg(unix)]
#[test]
fn gdt_paths_follow_parent_symlinks_and_reject_dangling_outputs() {
    use std::os::unix::fs::symlink;
    let bridge = RecordedBridge::new();
    std::fs::create_dir_all(bridge.root.path().join("real/nested")).unwrap();
    symlink("real/nested", bridge.root.path().join("alias")).unwrap();
    symlink("absent.gdt", bridge.root.path().join("dangling.gdt")).unwrap();
    bridge
        .command()
        .args(["type", "export-gdt", "dangling.gdt", "--all"])
        .assert()
        .failure();
    bridge.requests.lock().unwrap().clear();
    run_envelope(
        &bridge,
        &["type", "export-gdt", "alias/../created.gdt", "--all"],
        false,
    );
    {
        let requests = bridge.requests.lock().unwrap();
        let edit = requests
            .iter()
            .find(|r| r["command"] == "type_export_gdt")
            .unwrap();
        assert_eq!(
            edit["args"]["file"],
            json!(bridge.root.path().join("real/created.gdt"))
        );
    }
    std::fs::write(bridge.root.path().join("real/input.gdt"), "archive").unwrap();
    symlink("real/input.gdt", bridge.root.path().join("input.gdt")).unwrap();
    run_envelope(&bridge, &["type", "archive", "list", "input.gdt"], false);
    let requests = bridge.requests.lock().unwrap();
    let list = requests
        .iter()
        .find(|r| r["command"] == "type_archive_list")
        .unwrap();
    assert_eq!(
        list["args"]["file"],
        json!(bridge.root.path().join("real/input.gdt"))
    );
}

#[cfg(unix)]
#[test]
fn gdt_non_utf8_paths_fail_without_panicking_or_sending_archive_requests() {
    use std::os::unix::ffi::OsStringExt;
    let bridge = RecordedBridge::new();
    let file = std::ffi::OsString::from_vec(b"type-\xff.gdt".to_vec());
    for import in [false, true] {
        if import {
            std::fs::write(bridge.root.path().join(&file), "archive").unwrap();
        }
        let output = bridge
            .command()
            .args(["type", if import { "import-gdt" } else { "export-gdt" }])
            .arg(&file)
            .arg("--all")
            .output()
            .unwrap();
        assert!(!output.status.success());
        let diagnostics = String::from_utf8_lossy(&output.stderr);
        assert!(
            diagnostics.contains("cannot be represented as UTF-8"),
            "{diagnostics}"
        );
        assert!(!diagnostics.contains("panicked"));
        assert!(bridge
            .requests
            .lock()
            .unwrap()
            .iter()
            .all(|r| r["command"] == "bridge_info"));
    }
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

#[test]
fn type_uses_queries_preserve_scope_completion_and_standalone_batch_results() {
    let outer = RecordedBridge::new();
    let selected = RecordedBridge::new();
    for (query, expected, fetch_limit, kind) in [
        (
            vec!["--limit", "1", "--fields", "name"],
            json!([{"name":"zeta"}]),
            json!(1),
            Value::Null,
        ),
        (
            vec![
                "--filter",
                "kind=signature AND role=parameter",
                "--limit",
                "1",
                "--fields",
                "name",
            ],
            json!([{"name":"ctx"}]),
            Value::Null,
            Value::Null,
        ),
        (
            vec![
                "--kind", "data", "--sort", "name", "--skip", "1", "--limit", "1", "--fields",
                "name",
            ],
            json!([{"name":"zeta"}]),
            Value::Null,
            json!("data"),
        ),
        (
            vec!["--kind", "signature", "--count"],
            json!(2),
            Value::Null,
            json!("signature"),
        ),
        (
            vec![
                "--kind",
                "signature",
                "--skip",
                "1",
                "--limit",
                "1",
                "--count",
            ],
            json!(1),
            Value::Null,
            json!("signature"),
        ),
        (
            vec!["--filter", "name=absent"],
            json!([]),
            Value::Null,
            Value::Null,
        ),
    ] {
        let mut standalone = Value::Null;
        for batch in [false, true] {
            selected.requests.lock().unwrap().clear();
            let mut args = vec!["type", "uses", "/Widget"];
            args.extend(query.iter().copied());
            args.extend([
                "--project",
                selected.project.to_str().unwrap(),
                "--program",
                "B",
            ]);
            let output = run_envelope(&outer, &args, batch);
            assert_eq!(output["data"], expected, "{args:?}: {output}");
            assert_eq!(output["meta"]["target_type_path"], "/Widget");
            assert_eq!(output["meta"]["scan"]["complete"], fetch_limit.is_null());
            assert_eq!(
                output["meta"]["kinds"],
                kind.as_str()
                    .map_or(json!(["data", "signature"]), |kind| json!([kind]))
            );
            if batch {
                assert_eq!(output, standalone);
            } else {
                standalone = output;
            }
            let requests = selected.requests.lock().unwrap();
            let domain: Vec<_> = requests
                .iter()
                .filter(|r| r["command"] != "bridge_info")
                .collect();
            assert_eq!(domain.len(), 1);
            assert_eq!(domain[0]["program"], "B");
            assert_eq!(domain[0]["command"], "type_uses");
            assert_eq!(
                domain[0]["args"],
                json!({"type_name":"/Widget", "kind":kind, "limit":fetch_limit})
            );
        }
    }
    let empty = run_envelope(&selected, &["type", "uses", "/Unused"], false);
    assert_eq!(empty["data"], json!([]));
    assert_eq!(empty["meta"]["scan"]["complete"], true);
    for format in ["compact", "full"] {
        let output = selected
            .command()
            .args([
                "type", "uses", "/Widget", "--limit", "1", "--format", format,
            ])
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(
            text.contains("Type uses: /Widget (data, signature)"),
            "{text}"
        );
        assert!(text.contains("Scan stopped at the result limit"), "{text}");
    }
    let ndjson = selected
        .command()
        .args([
            "type",
            "uses",
            "/Widget",
            "--kind",
            "signature",
            "--limit",
            "0",
            "--format",
            "ndjson",
            "--fields",
            "name",
        ])
        .output()
        .unwrap();
    assert!(ndjson.status.success(), "{ndjson:?}");
    assert_eq!(
        String::from_utf8(ndjson.stdout)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>(),
        vec![json!({"name":"result"}), json!({"name":"ctx"})]
    );
}

#[test]
fn semantic_type_queries_preserve_scope_pagination_and_batch_results() {
    let outer = RecordedBridge::new();
    let selected = RecordedBridge::new();
    for (command, wire, fields, filter, sort, expected_filtered) in [
        (
            vec!["type", "uses", "/Widget", "--kind", "variable"],
            "type_uses",
            "name",
            "role=local",
            "name",
            json!([{"name":"zeta"}]),
        ),
        (
            vec!["type", "field", "uses", "/Widget", "--field", "flags"],
            "type_field_uses",
            "access",
            "access!=address",
            "-instruction_address",
            json!([{"access":"read"}]),
        ),
    ] {
        let first = if wire == "type_uses" {
            json!([{"name":"ctx"}])
        } else {
            json!([{"access":"read"}])
        };
        for (query, expected, fetch_limit) in [
            (vec!["--limit", "1", "--fields", fields], first, json!(1)),
            (
                vec![
                    "--filter", filter, "--sort", sort, "--skip", "1", "--limit", "1", "--fields",
                    fields,
                ],
                expected_filtered,
                Value::Null,
            ),
            (vec!["--count"], json!(3), Value::Null),
            (
                vec!["--skip", "1", "--limit", "1", "--count"],
                json!(1),
                Value::Null,
            ),
        ] {
            let mut standalone = Value::Null;
            for batch in [false, true] {
                selected.requests.lock().unwrap().clear();
                let mut args = command.clone();
                args.extend(query.iter().copied());
                args.extend([
                    "--function",
                    "process",
                    "--project",
                    selected.project.to_str().unwrap(),
                    "--program",
                    "B",
                ]);
                let output = run_envelope(&outer, &args, batch);
                assert_eq!(output["data"], expected, "{args:?}: {output}");
                assert_eq!(output["meta"]["target_type_path"], "/Widget");
                assert_eq!(
                    output["meta"]["scope"],
                    json!({"function":"process", "address":"0x1000"})
                );
                assert_eq!(output["meta"]["scan"]["complete"], fetch_limit.is_null());
                if wire == "type_uses" {
                    assert_eq!(output["meta"]["kinds"], json!(["variable"]));
                } else {
                    assert_eq!(
                        output["meta"]["target_field"],
                        json!({"name":"flags", "offset":16, "ordinal":2})
                    );
                }
                if batch {
                    assert_eq!(output, standalone);
                } else {
                    standalone = output;
                }
                let requests = selected.requests.lock().unwrap();
                let requests: Vec<_> = requests
                    .iter()
                    .filter(|r| r["command"] != "bridge_info")
                    .collect();
                assert_eq!(requests.len(), 1);
                assert_eq!(requests[0]["program"], "B");
                assert_eq!(requests[0]["command"], wire);
                let mut expected_args = json!({"type_name":"/Widget", "function":"process", "limit":fetch_limit, "timeout_secs":0});
                if wire == "type_uses" {
                    expected_args["kind"] = json!("variable");
                } else {
                    expected_args["field"] = json!("flags");
                    expected_args["offset"] = Value::Null;
                    expected_args["ordinal"] = Value::Null;
                }
                assert_eq!(requests[0]["args"], expected_args);
            }
        }
    }
}

#[test]
fn semantic_type_queries_use_native_timeout_and_preserve_field_selectors() {
    let bridge = RecordedBridge::new();
    for (args, wire, selector) in [
        (
            vec!["type", "uses", "/Widget", "--kind", "variable"],
            "type_uses",
            None,
        ),
        (
            vec!["type", "field", "uses", "/Widget", "--offset", "0x10"],
            "type_field_uses",
            Some(("offset", 16)),
        ),
        (
            vec!["type", "field", "uses", "/Widget", "--ordinal", "02"],
            "type_field_uses",
            Some(("ordinal", 2)),
        ),
    ] {
        bridge.requests.lock().unwrap().clear();
        let output = bridge
            .command()
            .env("GHIDRA_CLI_DECOMPILE_TIMEOUT", "47")
            .args(&args)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let result: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(result["meta"]["scope"], Value::Null);
        let requests = bridge.requests.lock().unwrap();
        let request = requests.iter().find(|r| r["command"] == wire).unwrap();
        assert_eq!(request["args"]["timeout_secs"], 47);
        assert_eq!(request["args"]["function"], Value::Null);
        if let Some((key, expected)) = selector {
            assert_eq!(request["args"][key], expected);
        }
        drop(requests);
        bridge.requests.lock().unwrap().clear();
        let output = bridge
            .command()
            .env("GHIDRA_CLI_DECOMPILE_TIMEOUT", "invalid")
            .args(&args)
            .output()
            .unwrap();
        assert!(!output.status.success(), "{output:?}");
        assert!(bridge
            .requests
            .lock()
            .unwrap()
            .iter()
            .all(|r| r["command"] != wire));
    }
    let output = bridge
        .command()
        .env("GHIDRA_CLI_DECOMPILE_TIMEOUT", "invalid")
        .args(["type", "uses", "/Widget"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
}

#[test]
fn database_type_uses_reject_function_scope_before_bridge_work() {
    let bridge = RecordedBridge::new();
    for kind in ["data", "signature"] {
        let args = [
            "type",
            "uses",
            "/Widget",
            "--kind",
            kind,
            "--function",
            "process",
        ];
        for batch in [false, true] {
            let output = if batch {
                std::fs::write(bridge.root.path().join("batch.txt"), batch_arguments(&args))
                    .unwrap();
                bridge
                    .command()
                    .args(["batch", "batch.txt"])
                    .output()
                    .unwrap()
            } else {
                bridge.command().args(args).output().unwrap()
            };
            assert!(!output.status.success(), "{args:?}: {output:?}");
            if batch {
                let result: Value = serde_json::from_slice(&output.stdout).unwrap();
                assert_eq!(result["data"]["commands_executed"], 0);
            } else {
                assert!(String::from_utf8(output.stderr)
                    .unwrap()
                    .contains("--function requires --kind variable"));
            }
            assert!(bridge.requests.lock().unwrap().is_empty());
        }
    }
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
            vec![
                "type",
                "create",
                "typedef",
                "HeaderPointer",
                "--type",
                "Header *",
            ],
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
            vec!["type", "resize", "/Draft/HeaderV2", "--size", "0x40"],
            "type_resize",
            json!({"type_name": "/Draft/HeaderV2", "size": 64}),
        ),
        (
            vec!["type", "resize", "/Draft/Empty", "--size", "0"],
            "type_resize",
            json!({"type_name": "/Draft/Empty", "size": 0}),
        ),
        (
            vec!["type", "move", "/Header", "--category", "/Protocol"],
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
            assert_eq!(domain.len(), 1, "{args:?}: {domain:?}");
            assert_eq!(domain[0]["program"], "B");
            assert_eq!(domain[0]["command"], wire);
            assert_eq!(domain[0]["args"], expected, "{args:?}");
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
                    "--skip",
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
            assert_eq!(domain.len(), 1);
            assert_eq!(domain[0]["program"], "B");
            assert_eq!(domain[0]["command"], "type_category_list");
            assert_eq!(domain[0]["args"], json!({"path": path}));
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
            vec!["type", "resize", "/Header", "--size", "64"],
            vec!["type", "move", "/Header", "--category", "/Protocol"],
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
        vec!["type", "resize", "/Header", "--size", "2147483648"],
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
