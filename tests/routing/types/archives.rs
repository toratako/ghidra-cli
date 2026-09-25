use super::{batch_arguments, run_envelope, RecordedBridge};
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

pub(crate) fn gdt_transfer_fixture(command: &str, args: &Value) -> Value {
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
        ("import", "type_import_gdt", "sdk 日本語's types.gdt"),
        ("export", "type_export_gdt", "new 日本語's types.gdt"),
    ] {
        let absolute = outer.root.path().join(file);
        for all in [false, true] {
            for batch in [false, true] {
                selected.requests.lock().unwrap().clear();
                let mut args = vec![
                    "type",
                    "archive",
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
                    let candidate_args = if command == "import" {
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
            let args = [
                "type", "archive", "import", "sdk.gdt", "--where", expression,
            ];
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
                "inspect",
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
    run_envelope(&bridge, &["type", "archive", "inspect", "sdk.gdt"], false);
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
        "program info\ntype archive inspect sdk.gdt\nprogram info\n",
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
        let args = ["--program", "B", "type", "archive", "inspect", "sdk.gdt"];
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
        vec!["type", "archive", "import", "missing.gdt", "--all"],
        vec!["type", "archive", "inspect", "directory.gdt"],
        vec!["type", "archive", "export", "existing.gdt", "--all"],
        vec!["type", "archive", "export", "directory.gdt", "--all"],
        vec!["type", "archive", "export", "missing/new.gdt", "--all"],
        vec!["type", "archive", "export", "without-extension", "--all"],
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
        .args(["type", "archive", "export", "dangling.gdt", "--all"])
        .assert()
        .failure();
    bridge.requests.lock().unwrap().clear();
    run_envelope(
        &bridge,
        &["type", "archive", "export", "alias/../created.gdt", "--all"],
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
    run_envelope(&bridge, &["type", "archive", "inspect", "input.gdt"], false);
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
fn gdt_non_utf8_missing_paths_fail_without_panicking_or_sending_archive_requests() {
    use std::os::unix::ffi::OsStringExt;
    let bridge = RecordedBridge::new();
    let file = std::ffi::OsString::from_vec(b"type-\xff.gdt".to_vec());
    for (command, diagnostic) in [
        ("export", "cannot be represented as UTF-8"),
        ("import", "Cannot resolve archive"),
    ] {
        assert_non_utf8_gdt_path_rejected(&bridge, command, &file, diagnostic);
    }
}

// macOS filesystems can reject non-UTF-8 names during fixture creation.
// Linux exercises the wire-path check after resolving an existing input file.
#[cfg(target_os = "linux")]
#[test]
fn gdt_non_utf8_existing_input_fails_without_panicking_or_sending_archive_requests() {
    use std::os::unix::ffi::OsStringExt;
    let bridge = RecordedBridge::new();
    let file = std::ffi::OsString::from_vec(b"type-\xff.gdt".to_vec());
    std::fs::write(bridge.root.path().join(&file), "archive").unwrap();
    assert_non_utf8_gdt_path_rejected(&bridge, "import", &file, "cannot be represented as UTF-8");
}

#[cfg(unix)]
fn assert_non_utf8_gdt_path_rejected(
    bridge: &RecordedBridge,
    command: &str,
    file: &std::ffi::OsStr,
    diagnostic: &str,
) {
    let output = bridge
        .command()
        .args(["type", "archive", command])
        .arg(file)
        .arg("--all")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let diagnostics = String::from_utf8_lossy(&output.stderr);
    assert!(diagnostics.contains(diagnostic), "{diagnostics}");
    assert!(!diagnostics.contains("panicked"));
    assert!(bridge
        .requests
        .lock()
        .unwrap()
        .iter()
        .all(|r| r["command"] == "bridge_info"));
}
