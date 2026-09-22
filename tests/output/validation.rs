use super::isolated_command;

#[test]
fn mutations_reject_query_and_bulk_options_before_loading_config() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("config.yaml"), "invalid: [yaml").unwrap();
    for args in [
        vec!["function", "rename", "old", "new", "--filter", "name=old"],
        vec!["function", "rename", "old", "new", "--all"],
        vec!["function", "delete", "main", "--filter", "name=other"],
        vec!["function", "delete", "main", "-f", "name=other"],
        vec!["function", "delete", "main", "--sort", "name"],
        vec!["function", "delete", "main", "--offset", "1"],
        vec!["function", "delete", "main", "--limit", "0"],
        vec!["function", "delete", "main", "--count"],
    ] {
        let output = isolated_command(&temp).args(&args).output().unwrap();
        assert_eq!(output.status.code(), Some(2), "{args:?}: {output:?}");
        assert!(output.stdout.is_empty());
        let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
        assert!(error["message"]
            .as_str()
            .unwrap()
            .contains("unexpected argument"));
    }
}

#[test]
fn batch_validation_precedes_configuration_loading_and_bridge_startup() {
    let temp = tempfile::tempdir().unwrap();
    let config = temp.path().join("config.yaml");
    let original = "invalid: [yaml";
    std::fs::write(&config, original).unwrap();
    std::fs::write(
        temp.path().join("batch.txt"),
        "config set default_project changed\ncomment set 0x1000 before\nfunction list --filter invalid\nfunction delete\n",
    )
    .unwrap();
    for flags in [vec![], vec!["--pretty"]] {
        let output = isolated_command(&temp)
            .current_dir(temp.path())
            .env_remove("GHIDRA_INSTALL_DIR")
            .args(["batch", "batch.txt"])
            .args(flags)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("Batch validation failed"), "{stderr}");
        assert!(stderr.contains("batch.txt:1"), "{stderr}");
        assert!(stderr.contains("batch.txt:3"), "{stderr}");
        assert!(stderr.contains("batch.txt:4"), "{stderr}");
        let report: serde_json::Value = crate::json_output::from_slice(&output.stdout).unwrap();
        assert_eq!(report["commands_executed"], 0);
        assert_eq!(report["not_executed"], 4);
        assert_eq!(report["validation_errors"].as_array().unwrap().len(), 3);
        assert_eq!(std::fs::read_to_string(&config).unwrap(), original);
        assert!(!temp.path().join("projects").exists());
    }
}

#[test]
fn batch_missing_root_file_reports_a_validation_failure_without_a_project() {
    let temp = tempfile::tempdir().unwrap();
    let output = isolated_command(&temp)
        .current_dir(temp.path())
        .args(["batch", "missing.txt"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let report: serde_json::Value = crate::json_output::from_slice(&output.stdout).unwrap();
    assert_eq!(report["validation_failed"], true);
    assert_eq!(report["commands_executed"], 0);
    assert_eq!(report["validation_errors"][0]["file"], "missing.txt");
    assert!(report["validation_errors"][0]["line"].is_null());
    assert!(!temp.path().join("projects").exists());
}

#[test]
fn type_import_requires_exactly_one_input_source() {
    let temp = tempfile::tempdir().unwrap();
    for args in [
        vec!["type", "import-c"],
        vec!["type", "import-c", "int x;", "--file", "types.h"],
        vec!["type", "import-c", "int x;", "--stdin"],
        vec!["type", "import-c", "--file", "types.h", "--stdin"],
    ] {
        let output = isolated_command(&temp).args(&args).output().unwrap();
        assert_eq!(output.status.code(), Some(2), "{args:?}: {output:?}");
        let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(error["exit_code"], 2);
    }
}

#[test]
fn field_edits_reject_invalid_offsets_and_incomplete_edits_before_loading_config() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("config.yaml"), "invalid: [yaml").unwrap();
    let mut cases = vec![
        vec!["type", "field", "delete", "Manager"],
        vec![
            "type", "field", "delete", "Manager", "--field", "hook", "--offset", "0",
        ],
        vec!["type", "field", "set", "Manager", "--field", "hook"],
        vec![
            "type", "field", "set", "Manager", "--field", "", "--name", "hook",
        ],
        vec!["type", "field", "set", "Manager", "--offset", "0x1c"],
        vec!["type", "field", "set", "Manager", "--name", "hook"],
        vec![
            "type", "field", "set", "Manager", "--offset", "0x1c", "--name", "",
        ],
        vec![
            "type", "field", "set", "Manager", "--offset", "0x1c", "--type", "",
        ],
        vec!["type", "field", "clear", "Manager"],
        vec![
            "type", "field", "set", "Manager", "--offset", "0", "--name", "hook", "--size", "8",
        ],
    ];
    for offset in [
        "",
        "-1",
        "+1",
        "1.5",
        "0x",
        "ff",
        "0xgg",
        "2147483648",
        "0x80000000",
    ] {
        for command in ["set", "clear", "delete"] {
            let mut args = vec!["type", "field", command, "Manager", "--offset", offset];
            if command == "set" {
                args.extend(["--name", "hook", "--type", "int"]);
            }
            cases.push(args);
        }
    }
    for args in cases {
        let output = isolated_command(&temp).args(&args).output().unwrap();
        assert_eq!(output.status.code(), Some(2), "{args:?}: {output:?}");
        assert!(output.stdout.is_empty());
        let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(error["exit_code"], 2);
    }
}

#[test]
fn variable_edit_rejects_missing_or_empty_edits() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("config.yaml"), "invalid: [yaml").unwrap();
    for args in [
        vec!["function", "edit-var", "main", "--var", "local_10"],
        vec!["function", "edit-var", "main", "--name", "header"],
        vec![
            "function", "edit-var", "main", "--var", "", "--name", "header",
        ],
        vec![
            "function", "edit-var", "main", "--var", "local_10", "--name", "",
        ],
        vec![
            "function", "edit-var", "main", "--var", "local_10", "--type", "",
        ],
    ] {
        let output = isolated_command(&temp).args(&args).output().unwrap();
        assert_eq!(output.status.code(), Some(2), "{args:?}: {output:?}");
        assert!(output.stdout.is_empty());
        let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(error["exit_code"], 2);
    }
}

#[test]
fn invalid_choices_list_valid_values_before_loading_config() {
    let temp = tempfile::tempdir().unwrap();
    // These argument errors must not depend on a usable config or bridge.
    std::fs::write(temp.path().join("config.yaml"), "invalid: [yaml").unwrap();
    for flags in [vec![], vec!["--json"], vec!["--pretty"]] {
        for (args, choices) in [
            (
                vec!["symbol", "externals", "--format", "potato"],
                "json, json-compact, ndjson",
            ),
            (vec!["function", "list", "-o", "auto"], "csv, tsv, table"),
        ] {
            let output = isolated_command(&temp)
                .args(&flags)
                .args(&args)
                .output()
                .unwrap();
            assert_eq!(
                output.status.code(),
                Some(2),
                "{flags:?} {args:?}: {output:?}"
            );
            assert!(output.stdout.is_empty(), "{output:?}");
            let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
            assert_eq!(error["status"], "error");
            assert_eq!(error["exit_code"], 2);
            let message = error["message"].as_str().unwrap();
            assert!(message.contains("possible values:"), "{message}");
            assert!(message.contains(choices), "{message}");
        }
    }
    assert_eq!(
        std::fs::read_to_string(temp.path().join("config.yaml")).unwrap(),
        "invalid: [yaml"
    );
}

#[test]
fn unknown_command_is_rejected_before_loading_config() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("config.yaml"), "invalid: [yaml").unwrap();
    let output = isolated_command(&temp)
        .arg("unknown-command")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(output.stdout.is_empty());
    let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["exit_code"], 2);
    assert_eq!(error["status"], "error");
    assert!(error["message"]
        .as_str()
        .unwrap()
        .contains("unrecognized subcommand"));
}
