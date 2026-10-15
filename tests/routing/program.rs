use super::{batch_arguments, RecordedBridge};
use serde_json::{json, Value};

#[test]
fn running_bridge_operations_do_not_require_a_local_installation() {
    let bridge = RecordedBridge::new();
    for (runtime_variable, other_runtime_variable) in [
        ("GHIDRA_INSTALL_DIR", "GHIDRA_JAR"),
        ("GHIDRA_JAR", "GHIDRA_INSTALL_DIR"),
    ] {
        bridge.requests.lock().unwrap().clear();
        for args in [
            vec!["program", "info", "--program", "B"],
            vec![
                "comment",
                "set",
                "0x1000",
                "--text",
                "saved",
                "--program",
                "B",
            ],
        ] {
            let output = bridge
                .command()
                .env_remove(other_runtime_variable)
                .env(runtime_variable, bridge.root.path().join("removed-runtime"))
                .args(&args)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{runtime_variable} {args:?}: {output:?}"
            );
            let result: Value = crate::json_output::from_slice(&output.stdout).unwrap();
            assert_eq!(result["observed_program"], "B");
        }
        let requests = bridge.requests.lock().unwrap();
        let operations: Vec<_> = requests
            .iter()
            .filter(|request| request["command"] != "bridge_info")
            .collect();
        assert_eq!(operations.len(), 2, "{requests:?}");
        assert_eq!(operations[0]["command"], "program_info");
        assert_eq!(operations[1]["command"], "comment_set");
        assert!(operations.iter().all(|request| request["program"] == "B"));
    }
}

#[test]
fn stopped_bridge_operations_still_require_a_local_installation() {
    let bridge = RecordedBridge::new();
    let output = bridge
        .command()
        .env(
            "GHIDRA_INSTALL_DIR",
            bridge.root.path().join("removed-runtime"),
        )
        .args(["program", "info"])
        .arg("--project")
        .arg(bridge.root.path().join("stopped"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let diagnostic: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert!(diagnostic["message"]
        .as_str()
        .unwrap()
        .contains("removed-runtime"));
    assert!(bridge.requests.lock().unwrap().is_empty());
}

#[test]
fn batch_java_home_overrides_follow_line_and_nested_scope() {
    for command in ["program info", "program import binary --no-analyze"] {
        let temp = tempfile::tempdir().unwrap();
        let install = temp.path().join("installation");
        super::installation_fixture::write(&install);
        let project = temp.path().join("stopped");
        std::fs::write(project.with_added_extension("gpr"), "fixture").unwrap();
        std::fs::create_dir(project.with_added_extension("rep")).unwrap();
        std::fs::write(temp.path().join("binary"), "fixture").unwrap();
        let config = temp.path().join("config.yaml");
        std::fs::write(&config, "{}\n").unwrap();
        std::fs::write(
            temp.path().join("batch.txt"),
            format!(
                "{command} --java-home line-jdk\n{command}\nbatch nested.txt --java-home nested-jdk\n{command}\n"
            ),
        )
        .unwrap();
        std::fs::write(
            temp.path().join("nested.txt"),
            format!("{command}\n{command} --java-home inner-jdk\n{command}\n"),
        )
        .unwrap();
        let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
            .current_dir(temp.path())
            .env("GHIDRA_CLI_CONFIG", &config)
            .env("XDG_DATA_HOME", temp.path().join("data"))
            .env("XDG_CONFIG_HOME", temp.path().join("configuration"))
            .env_remove("GHIDRA_JAR")
            .env("GHIDRA_INSTALL_DIR", &install)
            .env("GHIDRA_CLI_JAVA_HOME", "environment-jdk")
            .arg("--project")
            .arg(&project)
            .args(["--java-home", "outer-jdk", "batch", "batch.txt"])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1), "{command}: {output:?}");
        let report: Value = crate::json_output::from_slice(&output.stdout).unwrap();
        assert_eq!(report["commands_executed"], 4, "{command}: {report}");
        for (index, expected) in [(0, "line-jdk"), (1, "outer-jdk"), (3, "outer-jdk")] {
            let error = report["results"][index]["error"].as_str().unwrap();
            assert!(error.contains(expected), "{command} {index}: {error}");
        }
        let nested = &report["results"][2]["detail"];
        assert_eq!(nested["commands_executed"], 3, "{command}: {nested}");
        for (index, expected) in [(0, "nested-jdk"), (1, "inner-jdk"), (2, "nested-jdk")] {
            let error = nested["results"][index]["error"].as_str().unwrap();
            assert!(
                error.contains(expected),
                "{command} nested {index}: {error}"
            );
        }
        assert_eq!(std::fs::read_to_string(config).unwrap(), "{}\n");
    }
}

#[test]
fn empty_project_targets_do_not_edit_the_project_directory() {
    let bridge = RecordedBridge::new();
    let old_port = super::bridge::port_file_path(&bridge.project).unwrap();
    let old_pid = super::bridge::pid_file_path(&bridge.project).unwrap();
    std::fs::create_dir_all(bridge.project.with_added_extension("rep")).unwrap();
    std::fs::rename(
        old_port,
        super::bridge::port_file_path(&bridge.project).unwrap(),
    )
    .unwrap();
    std::fs::rename(
        old_pid,
        super::bridge::pid_file_path(&bridge.project).unwrap(),
    )
    .unwrap();

    let output = bridge
        .command()
        .env("GHIDRA_PROJECT_DIR", &bridge.project)
        .args([
            "comment",
            "set",
            "0x1000",
            "--text",
            "must-not-edit",
            "--project",
            "",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let diagnostic: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert!(diagnostic["message"].as_str().unwrap().contains("empty"));
    assert!(bridge.requests.lock().unwrap().is_empty());
}

#[test]
fn listing_programs_does_not_select_a_context_program() {
    let bridge = RecordedBridge::new();
    std::fs::write(
        bridge.root.path().join("config.yaml"),
        "default_program: configured\n",
    )
    .unwrap();
    for args in [
        vec!["program", "list"],
        vec!["program", "list", "--program", "context"],
    ] {
        bridge.requests.lock().unwrap().clear();
        bridge.run(&args);
        let requests = bridge.requests.lock().unwrap();
        assert!(requests.iter().any(|r| r["command"] == "list_programs"));
        assert!(requests.iter().all(|r| r["command"] != "open_program"));
        assert!(requests.iter().all(|r| r.get("program").is_none()));
    }
}

#[test]
fn program_info_and_stats_support_projection_and_format_in_standalone_and_batch() {
    for (subcommand, wire_command) in [("info", "program_info"), ("stats", "stats")] {
        let bridge = RecordedBridge::new();
        let args = [
            "program",
            subcommand,
            "B",
            "--program",
            "ignored",
            "--fields",
            "observed_program",
            "--format",
            "json-compact",
        ];
        assert_eq!(bridge.run(&args), json!({"observed_program": "B"}));
        std::fs::write(bridge.root.path().join("batch.txt"), args.join(" ")).unwrap();
        assert_eq!(
            bridge.run(&["batch", "batch.txt"])["results"][0]["result"]["data"],
            json!({"observed_program": "B"})
        );
        assert_eq!(
            bridge
                .requests
                .lock()
                .unwrap()
                .iter()
                .filter(|r| r["command"] == wire_command)
                .count(),
            2
        );
    }
}

#[test]
fn tag_get_preserves_details_and_projection_in_standalone_and_batch() {
    let bridge = RecordedBridge::new();
    std::fs::write(
        bridge.root.path().join("config.yaml"),
        "default_limit: 2147483648\n",
    )
    .unwrap();
    for fields in [None, Some("comment,use_count")] {
        for batch in [false, true] {
            bridge.requests.lock().unwrap().clear();
            let mut args = vec![
                "function",
                "tag",
                "get",
                "review",
                "--program",
                "B",
                "--json",
            ];
            let mut expected = json!({"name": "review", "comment": "Review queue", "use_count": 2});
            if let Some(fields) = fields {
                args.extend(["--fields", fields, "--format", "json-compact"]);
                expected.as_object_mut().unwrap().remove("name");
            }
            let result = if batch {
                std::fs::write(bridge.root.path().join("batch.txt"), args.join(" ")).unwrap();
                bridge.run(&["batch", "batch.txt"])["results"][0]["result"]["data"].clone()
            } else {
                bridge.run(&args)
            };
            assert_eq!(result, expected);
            let requests = bridge.requests.lock().unwrap();
            let domain: Vec<_> = requests
                .iter()
                .filter(|r| r["command"] != "bridge_info")
                .collect();
            assert_eq!(domain.len(), 1, "{domain:?}");
            assert_eq!(domain[0]["program"], "B");
            assert_eq!(domain[0]["command"], "tag_get");
            assert_eq!(domain[0]["args"], json!({"name": "review"}));
        }
    }
}

#[test]
fn memory_read_preserves_bytes_and_pointers_with_output_options() {
    let bridge = RecordedBridge::new();
    for fields in [None, Some("size,hex,pointers")] {
        for batch in [false, true] {
            bridge.requests.lock().unwrap().clear();
            let mut args = vec![
                "memory",
                "read",
                "0x1000",
                "--size",
                "8",
                "--program",
                "B",
                "--json",
            ];
            if let Some(fields) = fields {
                args.extend(["--fields", fields, "--format", "json-compact"]);
            }
            let result = if batch {
                std::fs::write(bridge.root.path().join("batch.txt"), args.join(" ")).unwrap();
                bridge.run(&["batch", "batch.txt"])["results"][0]["result"]["data"].clone()
            } else {
                bridge.run(&args)
            };
            // Nested fields belong to the single result in both execution modes.
            let object = &result;
            assert_eq!(object["size"], 8);
            assert_eq!(object["hex"], "0000000001000000");
            assert_eq!(object["pointers"].as_array().unwrap().len(), 2);
            assert_eq!(object.get("address").is_some(), fields.is_none());
            let requests = bridge.requests.lock().unwrap();
            let domain: Vec<_> = requests
                .iter()
                .filter(|r| r["command"] != "bridge_info")
                .collect();
            assert_eq!(domain.len(), 1, "{domain:?}");
            assert_eq!(domain[0]["program"], "B");
            assert_eq!(domain[0]["command"], "read_memory");
            assert_eq!(
                domain[0]["args"],
                json!({"address": "0x1000", "size": 8, "source": "memory"})
            );
        }
    }
}

#[test]
fn memory_info_preserves_nested_details_and_projection_in_standalone_and_batch() {
    let bridge = RecordedBridge::new();
    for target in ["main", "overlay:0x1000"] {
        for fields in [None, Some("kind,instruction,data,function,memory")] {
            for batch in [false, true] {
                bridge.requests.lock().unwrap().clear();
                let mut args = vec!["memory", "info", target, "--program", "B"];
                if let Some(fields) = fields {
                    args.extend(["--fields", fields]);
                }
                let result = if batch {
                    std::fs::write(bridge.root.path().join("batch.txt"), batch_arguments(&args))
                        .unwrap();
                    bridge.run(&["batch", "batch.txt"])["results"][0]["result"]["data"].clone()
                } else {
                    bridge.run(&args)
                };
                let object = &result;
                assert_eq!(object["kind"], "instruction");
                assert_eq!(object["instruction"]["mnemonic"], "MOV");
                assert_eq!(object["data"], Value::Null);
                assert_eq!(object["function"]["name"], "main");
                assert_eq!(object["memory"]["permissions"], "rx");
                assert_eq!(object.get("address").is_some(), fields.is_none());
                let requests = bridge.requests.lock().unwrap();
                let domain: Vec<_> = requests
                    .iter()
                    .filter(|r| r["command"] != "bridge_info")
                    .collect();
                assert_eq!(domain.len(), 1, "{domain:?}");
                assert_eq!(domain[0]["program"], "B");
                assert_eq!(domain[0]["command"], "memory_info");
                assert_eq!(domain[0]["args"], json!({"address": target}));
            }
        }
    }
    let output = bridge
        .command()
        .args(["memory", "info", "main", "--format", "compact"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(
        text.contains("instruction") && text.contains("MOV") && text.contains("main"),
        "{text}"
    );
}

#[test]
fn memory_write_routes_hex_and_targets_in_standalone_and_batch() {
    let bridge = RecordedBridge::new();
    for batch in [false, true] {
        bridge.requests.lock().unwrap().clear();
        if batch {
            std::fs::write(
                bridge.root.path().join("batch.txt"),
                "memory write main --bytes '90 c3' --program B\n",
            )
            .unwrap();
            let result = bridge.run(&["batch", "batch.txt"]);
            assert_eq!(
                result["results"][0]["result"]["data"]["observed_program"],
                "B"
            );
        } else {
            let result = bridge.run(&[
                "memory",
                "write",
                "main",
                "--bytes",
                "90 c3",
                "--program",
                "B",
            ]);
            assert_eq!(result["observed_program"], "B");
        }
        let requests = bridge.requests.lock().unwrap();
        let write = requests
            .iter()
            .find(|r| r["command"] == "memory_write")
            .unwrap();
        assert_eq!(write["args"], json!({"address": "main", "hex": "90 c3"}));
        assert_eq!(write["program"], "B");
        assert_eq!(
            requests
                .iter()
                .filter(|r| r["command"] != "bridge_info")
                .count(),
            1
        );
    }
}

#[test]
fn api_reads_honor_project_overrides_in_standalone_and_batch() {
    let first = RecordedBridge::new();
    let selected = RecordedBridge::new();
    for (command, wire) in [
        (vec!["bookmark", "list"], "bookmark_list"),
        (vec!["bookmark", "get", "0x1000"], "bookmark_get"),
        (vec!["memory", "info", "main"], "memory_info"),
        (
            vec!["program", "list-relocations"],
            "program_list_relocations",
        ),
        (
            vec!["program", "list-calling-conventions"],
            "program_list_calling_conventions",
        ),
    ] {
        for batch in [false, true] {
            first.requests.lock().unwrap().clear();
            selected.requests.lock().unwrap().clear();
            let args: Vec<_> = command
                .iter()
                .copied()
                .chain([
                    "--project",
                    selected.project.to_str().unwrap(),
                    "--program",
                    "B",
                ])
                .collect();
            if batch {
                std::fs::write(first.root.path().join("batch.txt"), batch_arguments(&args))
                    .unwrap();
                first.run(&["batch", "batch.txt"]);
            } else {
                first.run(&args);
            }
            assert!(first
                .requests
                .lock()
                .unwrap()
                .iter()
                .all(|r| r["command"] == "bridge_info"));
            let requests = selected.requests.lock().unwrap();
            assert_eq!(requests.iter().filter(|r| r["command"] == wire).count(), 1);
            assert!(requests
                .iter()
                .filter(|r| r["command"] != "bridge_info")
                .all(|r| r["program"] == "B"));
        }
    }
}

#[test]
fn program_operands_bind_the_target_to_optional_program_operations() {
    let bridge = RecordedBridge::new();
    for (args, wire) in [
        (vec!["program", "close", "B"], "program_close"),
        (vec!["program", "save", "B"], "program_save"),
        (
            vec!["program", "list-relocations", "B"],
            "program_list_relocations",
        ),
        (
            vec!["program", "list-calling-conventions", "B"],
            "program_list_calling_conventions",
        ),
        (
            vec!["program", "rebase", "B", "--base", "0x80000000"],
            "program_rebase",
        ),
    ] {
        for batched in [false, true] {
            bridge.requests.lock().unwrap().clear();
            let args: Vec<_> = args
                .iter()
                .copied()
                .chain(["--program", "ignored"])
                .collect();
            if batched {
                std::fs::write(bridge.root.path().join("batch.txt"), batch_arguments(&args))
                    .unwrap();
                bridge.run(&["batch", "batch.txt"]);
            } else {
                bridge.run(&args);
            }
            let requests = bridge.requests.lock().unwrap();
            let domain: Vec<_> = requests
                .iter()
                .filter(|r| r["command"] != "bridge_info")
                .collect();
            assert_eq!(domain.len(), 1, "{args:?}: {domain:?}");
            assert_eq!(domain[0]["program"], "B");
            assert_eq!(domain[0]["command"], wire);
        }
    }
}

#[test]
fn open_and_delete_use_the_operand_without_a_context_selector() {
    let bridge = RecordedBridge::new();
    for (operation, wire) in [("open", "open_program"), ("delete", "program_delete")] {
        for batched in [false, true] {
            bridge.requests.lock().unwrap().clear();
            let args = ["program", operation, "B", "--program", "ignored"];
            if batched {
                std::fs::write(bridge.root.path().join("batch.txt"), batch_arguments(&args))
                    .unwrap();
                bridge.run(&["batch", "batch.txt"]);
            } else {
                bridge.run(&args);
            }
            let requests = bridge.requests.lock().unwrap();
            let operations: Vec<_> = requests
                .iter()
                .filter(|r| r["command"] != "bridge_info")
                .collect();
            assert_eq!(operations.len(), 1);
            assert_eq!(operations[0]["command"], wire);
            assert_eq!(operations[0]["args"]["program"], "B");
            assert!(operations[0].get("program").is_none());
        }
    }
}
