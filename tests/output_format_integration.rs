//! CLI output format tests that do not require Ghidra or a JDK installation.

#[test]
fn test_format_detection_tty() {
    // Test that --help shows both --json and --pretty flags
    let mut cmd = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli");
    cmd.arg("--help");
    cmd.assert().success();

    let output = cmd.output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--json"), "Help should show --json flag");
    assert!(
        stdout.contains("--pretty"),
        "Help should show --pretty flag"
    );
}

#[test]
fn test_json_flag() {
    // Test --json flag is recognized
    let mut cmd = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli");
    cmd.arg("--json").arg("--help");
    cmd.assert().success();
}

#[test]
fn test_pretty_flag() {
    // Test --pretty flag is recognized
    let mut cmd = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli");
    cmd.arg("--pretty").arg("--help");
    cmd.assert().success();
}

fn isolated_command(temp: &tempfile::TempDir) -> assert_cmd::Command {
    let mut command = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli");
    command
        .env("GHIDRA_CLI_CONFIG", temp.path().join("config.yaml"))
        .env("XDG_DATA_HOME", temp.path().join("data"))
        .env("GHIDRA_PROJECT_DIR", temp.path().join("projects"));
    command
}

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
fn unknown_config_keys_fail_without_changing_the_file() {
    let temp = tempfile::tempdir().unwrap();
    let config_path = temp.path().join("config.yaml");
    let original = "default_output_format: minimal\n";
    std::fs::write(&config_path, original).unwrap();
    for (args, message) in [
        (
            vec!["config", "get", "unknown-config-key"],
            "Key not found: unknown-config-key",
        ),
        (
            vec!["config", "set", "unknown-config-key", "value"],
            "Unknown config key: unknown-config-key",
        ),
    ] {
        let output = isolated_command(&temp).args(&args).output().unwrap();
        assert!(!output.status.success(), "{args:?}: {output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(message),
            "{output:?}"
        );
        assert_eq!(std::fs::read_to_string(&config_path).unwrap(), original);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn unavailable_file_logging_does_not_prevent_commands() {
    let temp = tempfile::tempdir().unwrap();
    let not_a_directory = temp.path().join("not-a-directory");
    std::fs::write(&not_a_directory, "keep").unwrap();
    let output = isolated_command(&temp)
        .env("XDG_DATA_HOME", &not_a_directory)
        .args(["config", "list"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap();
    assert!(output.stderr.is_empty(), "{output:?}");
    assert_eq!(std::fs::read_to_string(not_a_directory).unwrap(), "keep");
}

#[test]
fn configured_json_default_and_explicit_flags_choose_presentation() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(
        temp.path().join("config.yaml"),
        "default_output_format: json\n",
    )
    .unwrap();
    for (flags, pretty) in [
        (vec![], true),
        (vec!["--json"], false),
        (vec!["--pretty"], true),
    ] {
        let output = isolated_command(&temp)
            .args(flags)
            .args(["config", "list"])
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap();
        assert_eq!(
            output.stdout.iter().filter(|&&c| c == b'\n').count() > 1,
            pretty,
            "{output:?}"
        );
    }
}

#[test]
fn project_management_honors_directory_override_and_lists_real_project_names() {
    let temp = tempfile::tempdir().unwrap();
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
    let info: serde_json::Value = serde_json::from_slice(&info.stdout).unwrap();
    assert_eq!(info["path"], serde_json::json!(requested.join("target")));
    assert_eq!(info["exists"], false);
    std::fs::create_dir(configured.join("target")).unwrap();
    let output = command().args(["project", "list"]).output().unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
        serde_json::json!([])
    );
    let output = command()
        .args(["project", "delete", "target"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()["deleted"],
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
        serde_json::from_slice::<serde_json::Value>(&info.stdout).unwrap()["exists"],
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
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
        serde_json::json!(["target"])
    );
    let output = command()
        .args(["project", "delete", "with-source"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
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
            serde_json::from_slice::<serde_json::Value>(&info.stdout).unwrap()["exists"],
            exists
        );
    }
}

#[test]
fn project_info_resolves_positional_global_and_configured_targets() {
    let temp = tempfile::tempdir().unwrap();
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
        let info: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
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
        let status: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
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
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
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

#[test]
fn launch_resolves_installation_from_environment_before_config() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(
        temp.path().join("config.yaml"),
        serde_json::to_vec(&serde_json::json!({
            "ghidra_install_dir": temp.path().join("config-install"),
        }))
        .unwrap(),
    )
    .unwrap();
    for args in [
        vec!["bridge", "start", "--project", "missing"],
        vec!["program", "info", "--project", "missing"],
    ] {
        let output = isolated_command(&temp)
            .env(
                "GHIDRA_INSTALL_DIR",
                temp.path().join("environment-install"),
            )
            .env("XDG_CONFIG_HOME", temp.path().join("config-data"))
            .args(args)
            .output()
            .unwrap();
        assert!(!output.status.success(), "{output:?}");
        let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
        assert!(
            error["message"]
                .as_str()
                .unwrap()
                .contains("environment-install"),
            "{error}"
        );
        assert!(
            !error["message"]
                .as_str()
                .unwrap()
                .contains("config-install"),
            "{error}"
        );
    }
}

#[test]
fn local_results_obey_json_modes() {
    let temp = tempfile::tempdir().unwrap();
    for flags in [vec![], vec!["--json"], vec!["--pretty"]] {
        for args in [
            vec!["config", "list"],
            vec!["config", "get", "default_limit"],
            vec!["bridge", "status", "--project", "missing"],
            vec!["bridge", "stop", "--project", "missing"],
            vec!["program", "save", "--project", "missing"],
        ] {
            let output = isolated_command(&temp)
                .args(&flags)
                .args(&args)
                .output()
                .unwrap();
            assert!(output.status.success(), "{flags:?} {args:?}: {output:?}");
            let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            if args[0] == "bridge" {
                assert_eq!(result["state"], "stopped", "{args:?}: {result}");
            }
            assert!(output.stderr.is_empty(), "{output:?}");
            let lines = output.stdout.iter().filter(|&&c| c == b'\n').count();
            if flags != ["--pretty"] {
                assert_eq!(lines, 1, "compact JSON must occupy one line: {output:?}");
            }
        }
    }
}

#[test]
fn failures_have_nonzero_status_and_json_diagnostics() {
    let temp = tempfile::tempdir().unwrap();
    for flags in [vec![], vec!["--json"], vec!["--pretty"]] {
        for (args, code) in [
            (vec!["config", "get", "unknown_key"], 1),
            (vec!["bridge", "ping", "--project", "missing"], 1),
            (vec!["job", "list", "--project", "missing"], 1),
            (vec!["job", "get", "42", "--project", "missing"], 1),
            (vec!["job", "cancel", "--project", "missing"], 1),
            (vec!["job", "cancel", "42", "--project", "missing"], 1),
            (vec!["--unknown-option"], 2),
            (vec!["config", "get"], 2),
            (vec!["function", "list", "--filter", "bad"], 1),
        ] {
            let output = isolated_command(&temp)
                .args(&flags)
                .args(&args)
                .output()
                .unwrap();
            assert_eq!(
                output.status.code(),
                Some(code),
                "{flags:?} {args:?}: {output:?}"
            );
            assert!(output.stdout.is_empty(), "{output:?}");
            let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
            assert_eq!(error["status"], "error");
            assert_eq!(error["exit_code"], code);
            assert!(!error["message"].as_str().unwrap().is_empty());
            if matches!(args[0], "bridge" | "job") {
                assert!(
                    error["message"]
                        .as_str()
                        .unwrap()
                        .contains("No bridge running"),
                    "{args:?}: {error}"
                );
            }
        }
    }
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
        vec!["type", "set-field", "Manager", "--offset", "0x1c"],
        vec!["type", "set-field", "Manager", "--name", "hook"],
        vec![
            "type",
            "set-field",
            "Manager",
            "--offset",
            "0x1c",
            "--name",
            "",
        ],
        vec![
            "type",
            "set-field",
            "Manager",
            "--offset",
            "0x1c",
            "--type",
            "",
        ],
        vec!["type", "clear-field", "Manager"],
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
        for command in ["set-field", "clear-field", "add-field"] {
            let mut args = vec!["type", command, "Manager", "--offset", offset];
            if command != "clear-field" {
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
                vec!["program", "imports", "--format", "potato"],
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
fn quiet_mutations_keep_results_and_apply_changes() {
    let temp = tempfile::tempdir().unwrap();
    let output = isolated_command(&temp)
        .args(["--quiet", "config", "set", "default_limit", "7"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["key"], "default_limit");
    assert!(temp.path().join("config.yaml").exists());

    let output = isolated_command(&temp)
        .args(["config", "get", "default_limit"])
        .output()
        .unwrap();
    assert_eq!(serde_json::from_slice::<usize>(&output.stdout).unwrap(), 7);
}

#[test]
fn doctor_failure_is_reported_in_both_result_and_exit_status() {
    let temp = tempfile::tempdir().unwrap();
    let output = isolated_command(&temp)
        .env("GHIDRA_INSTALL_DIR", temp.path().join("missing-ghidra"))
        .args(["--json", "doctor"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["ok"], false);
    assert!(!result["failures"].as_array().unwrap().is_empty());
    let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["exit_code"], 1);
}

#[cfg(unix)]
#[test]
fn closed_stdout_pipe_does_not_panic() {
    use std::os::{fd::OwnedFd, unix::net::UnixStream};
    use std::process::{Command, Stdio};
    let temp = tempfile::tempdir().unwrap();
    let (reader, writer) = UnixStream::pair().unwrap();
    drop(reader); // No reader exists before the child can attempt a write.
    let writer: OwnedFd = writer.into();
    let output = Command::new(assert_cmd::cargo::cargo_bin!("ghidra-cli"))
        .env("GHIDRA_CLI_CONFIG", temp.path().join("config.yaml"))
        .env("XDG_DATA_HOME", temp.path().join("data"))
        .args(["config", "list"])
        .stdout(Stdio::from(writer))
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
}

#[cfg(unix)]
#[test]
fn terminal_defaults_and_explicit_json_and_quiet() {
    use std::io::Read;
    use std::os::fd::FromRawFd;
    use std::process::{Command, Stdio};
    let temp = tempfile::tempdir().unwrap();
    for flags in [vec![], vec!["--json"], vec!["--pretty"], vec!["--quiet"]] {
        let mut master = -1;
        let mut slave = -1;
        // openpty initializes both descriptors; File takes sole ownership.
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            },
            0
        );
        let mut master = unsafe { std::fs::File::from_raw_fd(master) };
        let slave = unsafe { std::fs::File::from_raw_fd(slave) };
        let mut command = Command::new(assert_cmd::cargo::cargo_bin!("ghidra-cli"));
        command
            .env("GHIDRA_CLI_CONFIG", temp.path().join("config.yaml"))
            .env("XDG_DATA_HOME", temp.path().join("data"))
            .args(&flags)
            .args(["config", "set", "default_limit", "7"])
            .stdout(Stdio::from(slave))
            .stderr(Stdio::piped());
        let child = command.spawn().unwrap();
        drop(command); // Close the parent's copy of the slave so reads see EOF.
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success(), "{output:?}");
        let mut stdout = String::new();
        // Linux signals the final PTY close with EIO rather than EOF.
        if let Err(error) = master.read_to_string(&mut stdout) {
            assert_eq!(error.raw_os_error(), Some(libc::EIO));
        }
        if flags == ["--json"] || flags == ["--pretty"] {
            serde_json::from_str::<serde_json::Value>(&stdout).unwrap();
            assert!(output.stderr.is_empty());
            if flags == ["--pretty"] {
                assert!(stdout.contains("\n  \"key\""), "{stdout}");
            }
        } else {
            assert!(stdout.starts_with("Configuration updated"), "{stdout}");
            assert!(output.stderr.is_empty());
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn doctor_reports_unwritable_state_path_without_claiming_runtime_success() {
    let temp = tempfile::tempdir().unwrap();
    let blocked = temp.path().join("blocked");
    std::fs::write(&blocked, "retain").unwrap();
    let output = isolated_command(&temp)
        .env("XDG_DATA_HOME", &blocked)
        .env("XDG_CONFIG_HOME", temp.path().join("config"))
        .env("GHIDRA_INSTALL_DIR", temp.path().join("missing"))
        .args(["doctor", "--json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let state = result["storage"]
        .as_array()
        .unwrap()
        .iter()
        .find(|check| check["name"] == "bridge_state")
        .unwrap();
    assert_eq!(state["ok"], false);
    assert_eq!(state["detail"]["io_kind"], "not_a_directory");
    assert_eq!(state["path"], blocked.join("ghidra-cli").to_str().unwrap());
    assert_eq!(result["runtime"]["status"], "not_checked");
    assert_eq!(std::fs::read_to_string(blocked).unwrap(), "retain");
}

#[test]
fn config_io_failure_retains_operation_path_and_os_cause() {
    let temp = tempfile::tempdir().unwrap();
    let blocked = temp.path().join("blocked");
    std::fs::write(&blocked, "retain").unwrap();
    let path = blocked.join("config.yaml");
    let output = isolated_command(&temp)
        .env("GHIDRA_CLI_CONFIG", &path)
        .args(["config", "set", "default_limit", "7", "--json"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert!(
        error["detail"]["stage"]
            .as_str()
            .unwrap()
            .starts_with("config."),
        "{error}"
    );
    assert!(error["detail"]["path"]
        .as_str()
        .unwrap()
        .contains("blocked"));
    assert!(error["detail"]["cause"].is_string());
    assert!(error["detail"]["io_kind"].is_string());
    assert!(error["detail"]["os_error"].is_number());
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
