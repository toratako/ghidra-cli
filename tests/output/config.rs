use super::isolated_command;

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
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
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
    let status: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
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
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
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
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
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
