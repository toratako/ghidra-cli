use super::{installation_fixture, isolated_command};

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
        assert_eq!(error["detail"]["installation"]["status"], "invalid");
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
fn doctor_reports_path_selection_without_persisting_it() {
    let temp = tempfile::tempdir().unwrap();
    let install = temp.path().join("Ghidra space's");
    installation_fixture::write(&install);
    let output = isolated_command(&temp)
        .env_remove("GHIDRA_INSTALL_DIR")
        .env("PATH", install.join("support"))
        .env("GHIDRA_CLI_JAVA_HOME", temp.path().join("missing-jdk"))
        .args(["--json", "doctor"])
        .output()
        .unwrap();
    // This fixture proves selection only; it has no executable Ghidra or JDK.
    assert!(!output.status.success());
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["installation"]["ok"], true);
    assert_eq!(
        result["installation"]["path"],
        serde_json::json!(dunce::canonicalize(&install).unwrap())
    );
    assert_eq!(result["installation"]["version"], "12.1.3");
    assert!(result["installation"]["source"]
        .as_str()
        .unwrap()
        .starts_with("PATH "));
    assert!(!temp.path().join("config.yaml").exists());
}

#[test]
fn empty_installation_override_is_an_error_even_with_valid_config() {
    let temp = tempfile::tempdir().unwrap();
    let install = temp.path().join("installed");
    installation_fixture::write(&install);
    let config_path = temp.path().join("config.yaml");
    let config = serde_json::to_vec(&serde_json::json!({"ghidra_install_dir": install})).unwrap();
    std::fs::write(&config_path, &config).unwrap();
    let output = isolated_command(&temp)
        .env("GHIDRA_INSTALL_DIR", "")
        .args(["bridge", "start", "--project", "missing"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["detail"]["installation"]["status"], "invalid");
    assert!(error["message"].as_str().unwrap().contains("path is empty"));
    assert_eq!(std::fs::read(config_path).unwrap(), config);
    assert!(!temp.path().join("projects").exists());
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
