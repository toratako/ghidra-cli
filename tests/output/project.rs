use super::{installation_fixture, isolated_command};

#[test]
fn project_lists_share_json_metadata_and_ndjson_row_semantics() {
    let temp = tempfile::tempdir().unwrap();
    let install = temp.path().join("installation");
    installation_fixture::write(&install);
    let projects = temp.path().join("projects");
    std::fs::create_dir(&projects).unwrap();
    let command = || {
        let mut cmd = isolated_command(&temp);
        cmd.env("GHIDRA_INSTALL_DIR", &install);
        cmd
    };
    std::fs::write(
        temp.path().join("config.yaml"),
        "default_output_format: ndjson\n",
    )
    .unwrap();
    let empty = command().args(["project", "list"]).output().unwrap();
    assert!(empty.status.success(), "{empty:?}");
    assert!(empty.stdout.is_empty());
    for name in ["A", "B"] {
        std::fs::write(projects.join(format!("{name}.gpr")), "descriptor").unwrap();
        std::fs::create_dir(projects.join(format!("{name}.rep"))).unwrap();
    }
    let rows = command().args(["project", "list"]).output().unwrap();
    assert!(rows.status.success(), "{rows:?}");
    assert_eq!(String::from_utf8(rows.stdout).unwrap(), "\"A\"\n\"B\"\n");
    for flag in ["--json", "--pretty"] {
        let result = command().args(["project", "list", flag]).output().unwrap();
        assert!(result.status.success(), "{result:?}");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&result.stdout).unwrap(),
            serde_json::json!({
                "data": ["A", "B"], "meta": {"returned": 2}
            })
        );
    }
    for (key, expected) in [
        ("default_output_format", serde_json::json!("ndjson")),
        ("default_program", serde_json::Value::Null),
    ] {
        let result = command()
            .args(["config", "get", key, "--json"])
            .output()
            .unwrap();
        assert!(result.status.success(), "{result:?}");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&result.stdout).unwrap(),
            serde_json::json!({"data": expected})
        );
    }
}

#[test]
fn project_management_honors_directory_override_and_lists_real_project_names() {
    let temp = tempfile::tempdir().unwrap();
    installation_fixture::write(&temp.path().join("unused-install"));
    let configured = temp.path().join("configured");
    let environment = temp.path().join("environment");
    let requested = temp.path().join("requested space's");
    std::fs::create_dir_all(&configured).unwrap();
    std::fs::create_dir_all(environment.join("target")).unwrap();
    std::fs::create_dir_all(&requested).unwrap();
    std::fs::write(
        temp.path().join("config.yaml"),
        serde_json::to_vec(&serde_json::json!({
            "ghidra_project_dir": configured,
        }))
        .unwrap(),
    )
    .unwrap();
    let command = || {
        let mut cmd = isolated_command(&temp);
        cmd.env("GHIDRA_PROJECT_DIR", &environment)
            .env("GHIDRA_INSTALL_DIR", temp.path().join("unused-install"))
            .arg("--projects-dir")
            .arg(&requested);
        cmd
    };
    // A bare directory is not a Ghidra project, even when empty.
    std::fs::create_dir(requested.join("target")).unwrap();
    assert!(requested.join("target").is_dir());
    assert!(!configured.join("target").exists());
    let info = command()
        .args(["project", "info", "target"])
        .output()
        .unwrap();
    assert!(info.status.success(), "{info:?}");
    let info: serde_json::Value = crate::json_output::from_slice(&info.stdout).unwrap();
    assert_eq!(info["path"], serde_json::json!(requested.join("target")));
    assert_eq!(info["exists"], false);
    std::fs::create_dir(configured.join("target")).unwrap();
    let output = command().args(["project", "list"]).output().unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        crate::json_output::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
        serde_json::json!([])
    );
    let output = command()
        .args(["project", "delete", "target"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        crate::json_output::from_slice::<serde_json::Value>(&output.stdout).unwrap()["deleted"],
        false
    );
    assert!(configured.join("target").is_dir());
    assert!(environment.join("target").is_dir());
    assert!(requested.join("target").is_dir());
    let info = command()
        .args(["project", "info", "target"])
        .output()
        .unwrap();
    assert!(info.status.success(), "{info:?}");
    assert_eq!(
        crate::json_output::from_slice::<serde_json::Value>(&info.stdout).unwrap()["exists"],
        false
    );

    // Listing materialized projects needs no Ghidra. Successful deletion must
    // acquire Ghidra's project lock and is covered by project_tests instead.
    std::fs::create_dir(requested.join("target.rep")).unwrap();
    std::fs::write(requested.join("target.gpr"), "descriptor").unwrap();
    std::fs::create_dir(requested.join("with-source")).unwrap();
    std::fs::write(requested.join("with-source/input.bin"), "source data").unwrap();
    // A source directory alone is neither listed nor recursively removed.
    let output = command().args(["project", "list"]).output().unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        crate::json_output::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
        serde_json::json!(["target"])
    );
    let output = command()
        .args(["project", "delete", "with-source"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        crate::json_output::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
        serde_json::json!({"project": "with-source", "deleted": false})
    );
    assert_eq!(
        std::fs::read_to_string(requested.join("with-source/input.bin")).unwrap(),
        "source data"
    );
    for (name, exists) in [("target", true), ("with-source", false)] {
        let info = command().args(["project", "info", name]).output().unwrap();
        assert!(info.status.success(), "{info:?}");
        assert_eq!(
            crate::json_output::from_slice::<serde_json::Value>(&info.stdout).unwrap()["exists"],
            exists
        );
    }
}

#[test]
fn project_info_resolves_positional_global_and_configured_targets() {
    let temp = tempfile::tempdir().unwrap();
    installation_fixture::write(&temp.path().join("unused-install"));
    let directory = temp.path().join("projects");
    for name in ["configured", "global", "positional"] {
        std::fs::create_dir_all(directory.join(format!("{name}.rep"))).unwrap();
    }
    std::fs::write(
        temp.path().join("config.yaml"),
        "default_project: configured\n",
    )
    .unwrap();
    for (args, expected) in [
        (vec!["project", "info"], "configured"),
        (vec!["--project", "global", "project", "info"], "global"),
        (
            vec!["--project", "global", "project", "info", "positional"],
            "positional",
        ),
    ] {
        let output = isolated_command(&temp)
            .env("GHIDRA_INSTALL_DIR", temp.path().join("unused-install"))
            .args(args)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let info: serde_json::Value = crate::json_output::from_slice(&output.stdout).unwrap();
        assert_eq!(info["project"], expected);
        assert_eq!(info["path"], serde_json::json!(directory.join(expected)));
        assert_eq!(info["exists"], true);
    }
    std::fs::write(temp.path().join("config.yaml"), "{}\n").unwrap();
    let output = isolated_command(&temp)
        .env("GHIDRA_INSTALL_DIR", temp.path().join("unused-install"))
        .args(["project", "info"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert!(error["message"]
        .as_str()
        .unwrap()
        .contains("No project specified"));
}

#[test]
fn project_directory_precedence_reaches_management_and_doctor() {
    let temp = tempfile::tempdir().unwrap();
    let configured = temp.path().join("configured");
    let environment = temp.path().join("environment");
    let requested = temp.path().join("requested space's");
    let config_path = temp.path().join("config.yaml");
    let content = serde_json::to_vec(&serde_json::json!({
        "ghidra_project_dir": configured,
    }))
    .unwrap();
    std::fs::write(&config_path, &content).unwrap();
    for (with_environment, with_flag, expected) in [
        (false, false, &configured),
        (true, false, &environment),
        (true, true, &requested),
    ] {
        let mut command = isolated_command(&temp);
        command.env_remove("GHIDRA_PROJECT_DIR");
        if with_environment {
            command.env("GHIDRA_PROJECT_DIR", &environment);
        }
        if with_flag {
            command.arg("--projects-dir").arg(&requested);
        }
        let output = command
            .args(["bridge", "status", "--project", "missing"])
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let status: serde_json::Value = crate::json_output::from_slice(&output.stdout).unwrap();
        assert_eq!(
            status["project"],
            serde_json::json!(expected.join("missing"))
        );
    }
    let output = isolated_command(&temp)
        .env("GHIDRA_PROJECT_DIR", &environment)
        .env("GHIDRA_INSTALL_DIR", temp.path().join("unused-install"))
        .env("XDG_CONFIG_HOME", temp.path().join("configuration"))
        .arg("--projects-dir")
        .arg(&requested)
        .arg("doctor")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let report: serde_json::Value = crate::json_output::from_slice(&output.stdout).unwrap();
    let projects = report["storage"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["name"] == "projects")
        .unwrap();
    assert_eq!(projects["path"], serde_json::json!(requested));
    assert_eq!(projects["ok"], true);
    assert_eq!(std::fs::read(config_path).unwrap(), content);
    assert!(!environment.exists());
}

#[test]
fn project_delete_without_ghidra_preserves_project_files() {
    let temp = tempfile::tempdir().unwrap();
    let requested = temp.path().join("requested");
    std::fs::create_dir_all(requested.join("target.rep")).unwrap();
    std::fs::create_dir(requested.join("target")).unwrap();
    let files = [
        ("target.gpr", "descriptor"),
        ("target.rep/program", "saved program"),
        ("target/input.bin", "source data"),
        ("target.lock", "external owner"),
        ("target.lock~", "external owner lock"),
    ];
    for (path, content) in files {
        std::fs::write(requested.join(path), content).unwrap();
    }
    let output = isolated_command(&temp)
        .env_remove("GHIDRA_PROJECT_DIR")
        .env("GHIDRA_INSTALL_DIR", temp.path().join("unused-install"))
        .arg("--projects-dir")
        .arg(&requested)
        .args(["project", "delete", "target"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["status"], "error");
    let message = error["message"].as_str().unwrap();
    assert!(
        message.contains("analyzeHeadless") && message.contains("unused-install"),
        "{error}"
    );
    for (path, content) in files {
        assert_eq!(
            std::fs::read_to_string(requested.join(path)).unwrap(),
            content,
            "{path}"
        );
    }
}
