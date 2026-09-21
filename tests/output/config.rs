use super::isolated_command;

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
