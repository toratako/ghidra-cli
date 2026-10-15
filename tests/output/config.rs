use super::isolated_command;

#[test]
fn numeric_config_values_persist_as_numbers_and_invalid_updates_preserve_the_file() {
    let temp = tempfile::tempdir().unwrap();
    let config_path = temp.path().join("config.yaml");
    std::fs::write(&config_path, "default_program: saved-program\n").unwrap();
    for (key, input, expected) in [
        ("default_limit", "0x25", 37),
        ("launch_timeout_secs", "0240", 240),
    ] {
        let output = isolated_command(&temp)
            .args(["config", "set", key, input])
            .output()
            .unwrap();
        assert!(output.status.success(), "{key}: {output:?}");
        let persisted: serde_json::Value =
            serde_yaml::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
        assert_eq!(persisted[key], expected);
        assert_eq!(persisted["default_program"], "saved-program");

        let output = isolated_command(&temp)
            .args(["config", "get", key])
            .output()
            .unwrap();
        assert!(output.status.success(), "{key}: {output:?}");
        assert_eq!(
            crate::json_output::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
            expected
        );

        let original = std::fs::read(&config_path).unwrap();
        for invalid in ["0x", "18446744073709551616"] {
            let output = isolated_command(&temp)
                .args(["config", "set", key, invalid])
                .output()
                .unwrap();
            assert!(!output.status.success(), "{key}={invalid}: {output:?}");
            assert_eq!(std::fs::read(&config_path).unwrap(), original);
        }
    }
}

#[test]
fn default_limit_rejects_values_above_the_cli_page_range() {
    let temp = tempfile::tempdir().unwrap();
    let config_path = temp.path().join("config.yaml");
    let original = "default_limit: 37\n";
    std::fs::write(&config_path, original).unwrap();

    let output = isolated_command(&temp)
        .args(["config", "set", "default_limit", "9223372036854775808"])
        .output()
        .unwrap();
    assert!(!output.status.success(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("Invalid limit value"),
        "{output:?}"
    );
    assert_eq!(std::fs::read_to_string(config_path).unwrap(), original);
}

#[test]
fn config_set_preserves_persisted_values_despite_invocation_overrides() {
    let temp = tempfile::tempdir().unwrap();
    let config_path = temp.path().join("config.yaml");
    let mut expected = ghidra_cli::config::Config {
        ghidra_project_dir: Some(temp.path().join("configured-projects")),
        java_home: Some(temp.path().join("configured-jdk")),
        default_project: Some("saved-project".into()),
        default_program: Some("saved-program".into()),
        default_limit: Some(37),
        launch_timeout_secs: Some(240),
        ..Default::default()
    };
    std::fs::write(&config_path, serde_yaml::to_string(&expected).unwrap()).unwrap();
    let requested = temp.path().join("saved project's directory");

    let output = isolated_command(&temp)
        .env(
            "GHIDRA_PROJECT_DIR",
            temp.path().join("environment-projects"),
        )
        .env("GHIDRA_CLI_JAVA_HOME", temp.path().join("environment-jdk"))
        .arg("--projects-dir")
        .arg(temp.path().join("invocation-projects"))
        .arg("--java-home")
        .arg(temp.path().join("invocation-jdk"))
        .args([
            "--project",
            "invocation-project",
            "--program",
            "invocation-program",
        ])
        .args(["config", "set", "ghidra_project_dir"])
        .arg(&requested)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let result: serde_json::Value = crate::json_output::from_slice(&output.stdout).unwrap();
    assert_eq!(result["key"], "ghidra_project_dir");

    expected.ghidra_project_dir = Some(requested.clone());
    let persisted: serde_json::Value =
        serde_yaml::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
    assert_eq!(persisted, serde_json::to_value(&expected).unwrap());

    // A fresh invocation must resolve the saved target, not a previous override.
    let output = isolated_command(&temp)
        .env_remove("GHIDRA_PROJECT_DIR")
        .args(["bridge", "status"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let status: serde_json::Value = crate::json_output::from_slice(&output.stdout).unwrap();
    assert_eq!(status["state"], "stopped");
    assert_eq!(
        status["project"],
        serde_json::json!(requested.join("saved-project"))
    );
}

#[test]
fn config_reset_recovers_malformed_yaml_without_saving_invocation_overrides() {
    let temp = tempfile::tempdir().unwrap();
    let config_path = temp.path().join("config.yaml");
    std::fs::write(
        &config_path,
        "default_program: saved-program\ndefault_limit: [\n",
    )
    .unwrap();

    let output = isolated_command(&temp)
        .env("GHIDRA_CLI_JAVA_HOME", temp.path().join("environment-jdk"))
        .arg("--projects-dir")
        .arg(temp.path().join("invocation-projects"))
        .arg("--java-home")
        .arg(temp.path().join("invocation-jdk"))
        .args(["config", "reset"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let result: serde_json::Value = crate::json_output::from_slice(&output.stdout).unwrap();
    assert_eq!(result["message"], "Configuration reset to defaults");

    let expected = serde_json::to_value(ghidra_cli::config::Config::default()).unwrap();
    let persisted: serde_json::Value =
        serde_yaml::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
    assert_eq!(persisted, expected);
    let output = isolated_command(&temp)
        .args(["config", "list"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        crate::json_output::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
        expected
    );
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

#[test]
fn config_updates_reject_directory_only_paths_without_changing_the_file() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("config.yaml");
    let original = "default_project: keep-me\ndefault_limit: 7\n";
    std::fs::write(&target, original).unwrap();
    for suffix in [
        std::path::MAIN_SEPARATOR.to_string(),
        format!("{}.", std::path::MAIN_SEPARATOR),
    ] {
        let mut requested = target.as_os_str().to_owned();
        requested.push(suffix);
        for args in [
            vec!["config", "set", "default_limit", "37"],
            vec!["config", "reset"],
        ] {
            let output = isolated_command(&temp)
                .env("GHIDRA_CLI_CONFIG", &requested)
                .args(&args)
                .output()
                .unwrap();
            assert!(!output.status.success(), "{args:?}: {output:?}");
            assert!(output.stdout.is_empty(), "{output:?}");
            let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
            assert!(error["message"]
                .as_str()
                .unwrap()
                .contains("Configuration path must name a file"));
            assert_eq!(std::fs::read_to_string(&target).unwrap(), original);
        }
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
    crate::json_output::from_slice::<serde_json::Value>(&output.stdout).unwrap();
    assert!(output.stderr.is_empty(), "{output:?}");
    assert_eq!(std::fs::read_to_string(not_a_directory).unwrap(), "keep");
}

// APFS can reject non-UTF-8 filenames, so these fixtures require Linux.
#[cfg(target_os = "linux")]
#[test]
fn non_unicode_config_environment_path_updates_only_the_requested_file() {
    use std::os::unix::ffi::OsStrExt;

    let temp = tempfile::tempdir().unwrap();
    let requested = temp
        .path()
        .join(std::ffi::OsStr::from_bytes(b"config-\xff.yaml"));
    std::fs::write(
        &requested,
        "default_program: requested-program\ndefault_limit: 7\n",
    )
    .unwrap();
    let platform_config = temp.path().join("platform-config");
    let fallback = platform_config.join("ghidra-cli").join("config.yaml");
    std::fs::create_dir_all(fallback.parent().unwrap()).unwrap();
    let original_fallback = "default_program: fallback-program\ndefault_limit: 11\n";
    std::fs::write(&fallback, original_fallback).unwrap();

    let output = isolated_command(&temp)
        .env("GHIDRA_CLI_CONFIG", &requested)
        .env("XDG_CONFIG_HOME", &platform_config)
        .args(["config", "set", "default_limit", "37"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let saved: serde_json::Value =
        serde_yaml::from_str(&std::fs::read_to_string(&requested).unwrap()).unwrap();
    assert_eq!(saved["default_limit"], 37);
    assert_eq!(saved["default_program"], "requested-program");
    assert_eq!(
        std::fs::read_to_string(&fallback).unwrap(),
        original_fallback
    );
}

#[cfg(target_os = "linux")]
#[test]
fn non_unicode_project_environment_path_selects_only_requested_projects() {
    use std::os::unix::ffi::OsStrExt;

    let temp = tempfile::tempdir().unwrap();
    let requested = temp
        .path()
        .join(std::ffi::OsStr::from_bytes(b"projects-\xff"));
    let configured = temp.path().join("configured-projects");
    std::fs::create_dir(&requested).unwrap();
    std::fs::create_dir(&configured).unwrap();
    std::fs::write(requested.join("requested.gpr"), "requested").unwrap();
    std::fs::write(configured.join("fallback.gpr"), "fallback").unwrap();
    let config = ghidra_cli::config::Config {
        ghidra_project_dir: Some(configured),
        ..Default::default()
    };
    std::fs::write(
        temp.path().join("config.yaml"),
        serde_yaml::to_string(&config).unwrap(),
    )
    .unwrap();

    let output = isolated_command(&temp)
        .env("GHIDRA_PROJECT_DIR", &requested)
        .args(["project", "list"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    assert_eq!(
        crate::json_output::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
        serde_json::json!(["requested"])
    );
}

#[cfg(target_os = "linux")]
#[test]
fn doctor_reports_non_unicode_storage_paths_without_changing_the_probed_path() {
    use std::os::unix::ffi::OsStrExt;

    for writable in [true, false] {
        let temp = tempfile::tempdir().unwrap();
        let requested = temp
            .path()
            .join(std::ffi::OsStr::from_bytes(b"projects-\xff"));
        let replacement = temp.path().join("projects-\u{fffd}");
        if writable {
            std::fs::create_dir(&requested).unwrap();
            std::fs::write(&replacement, "retain replacement").unwrap();
        } else {
            std::fs::write(&requested, "retain requested").unwrap();
            std::fs::create_dir(&replacement).unwrap();
        }

        let output = isolated_command(&temp)
            .env("GHIDRA_INSTALL_DIR", temp.path().join("missing-ghidra"))
            .env("XDG_CONFIG_HOME", temp.path().join("platform-config"))
            .env("GHIDRA_PROJECT_DIR", &requested)
            .args(["doctor", "--json"])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        let report: serde_json::Value = crate::json_output::from_slice(&output.stdout).unwrap();
        let projects = report["storage"]
            .as_array()
            .unwrap()
            .iter()
            .find(|check| check["name"] == "projects")
            .unwrap();
        assert_eq!(projects["path"], requested.to_string_lossy().as_ref());
        assert_eq!(projects["ok"], writable);
        if writable {
            assert_eq!(std::fs::read_dir(&requested).unwrap().count(), 0);
            assert_eq!(
                std::fs::read_to_string(&replacement).unwrap(),
                "retain replacement"
            );
        } else {
            assert_eq!(
                std::fs::read_to_string(&requested).unwrap(),
                "retain requested"
            );
            assert_eq!(std::fs::read_dir(&replacement).unwrap().count(), 0);
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn non_unicode_project_paths_return_structured_errors_before_management() {
    use std::os::unix::ffi::OsStrExt;

    let temp = tempfile::tempdir().unwrap();
    let requested = temp
        .path()
        .join(std::ffi::OsStr::from_bytes(b"projects-\xff"));
    let replacement = temp.path().join("projects-\u{fffd}");
    for directory in [&requested, &replacement] {
        std::fs::create_dir(directory).unwrap();
        std::fs::write(directory.join("target.gpr"), "retain").unwrap();
    }
    for from_environment in [true, false] {
        for args in [
            vec!["project", "info", "target"],
            vec!["bridge", "status", "--project", "target"],
            vec!["program", "save", "--project", "target"],
        ] {
            let mut command = isolated_command(&temp);
            if from_environment {
                command.env("GHIDRA_PROJECT_DIR", &requested);
            } else {
                command
                    .env("GHIDRA_PROJECT_DIR", &replacement)
                    .arg("--projects-dir")
                    .arg(&requested);
            }
            let output = command.args(&args).output().unwrap();
            assert_eq!(output.status.code(), Some(1), "{args:?}: {output:?}");
            assert!(output.stdout.is_empty(), "{args:?}: {output:?}");
            let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
            assert_eq!(error["status"], "error");
            assert!(error["message"].as_str().unwrap().contains("UTF-8"));
            assert!(error["detail"].get("recovery").is_none());
        }
    }
    for directory in [&requested, &replacement] {
        assert_eq!(
            std::fs::read_to_string(directory.join("target.gpr")).unwrap(),
            "retain"
        );
    }
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
fn selecting_an_installation_format_clears_the_other_saved_selection() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("config.yaml");
    std::fs::write(&path, "default_program: retained-program\n").unwrap();
    for (selected, cleared, value) in [
        ("ghidra_install_dir", "ghidra_jar", "official installation"),
        ("ghidra_jar", "ghidra_install_dir", "standalone ghidra.jar"),
        ("ghidra_install_dir", "ghidra_jar", "another installation"),
    ] {
        let output = isolated_command(&temp)
            .args(["config", "set", selected, value])
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let saved: serde_json::Value =
            serde_yaml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(saved[selected], value);
        assert!(saved[cleared].is_null(), "{saved}");
        assert_eq!(saved["default_program"], "retained-program");
        let output = isolated_command(&temp)
            .args(["config", "get", selected])
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert_eq!(
            crate::json_output::from_slice::<String>(&output.stdout).unwrap(),
            value
        );
    }
}
