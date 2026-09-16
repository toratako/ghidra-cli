//! Tests for basic CLI commands that don't require daemon.

use predicates::prelude::*;

#[macro_use]
mod common;

#[test]
fn test_version_flag() {
    require_ghidra!();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("ghidra-cli"));
}

#[test]
fn test_doctor() {
    let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("doctor")
        .output()
        .expect("Failed to run doctor");
    common::assert_doctor_ready(&output);
    assert!(String::from_utf8_lossy(&output.stdout).contains("Ghidra CLI Doctor"));
}

#[test]
fn test_config_list() {
    require_ghidra!();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("config")
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("ghidra_install_dir"));
}

#[test]
fn test_config_get() {
    require_ghidra!();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("config")
        .arg("get")
        .arg("ghidra_install_dir")
        .assert()
        .success();
}

#[test]
fn test_config_set() {
    require_ghidra!();

    let temp = tempfile::tempdir().unwrap();
    let config_path = temp.path().join("config.yaml");

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .env("GHIDRA_CLI_CONFIG", &config_path)
        .arg("config")
        .arg("set")
        .arg("default_output_format")
        .arg("json")
        .assert()
        .success();
}

#[test]
fn test_legacy_config_timeout_is_rejected_with_replacements() {
    require_ghidra!();

    let temp = tempfile::tempdir().unwrap();
    let config_path = temp.path().join("config.yaml");

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .env("GHIDRA_CLI_CONFIG", &config_path)
        .arg("config")
        .arg("set")
        .arg("timeout")
        .arg("1800")
        .assert()
        .failure()
        .stderr(predicate::str::contains("GHIDRA_CLI_READ_TIMEOUT"));
}

#[test]
fn test_config_set_launch_timeout() {
    require_ghidra!();

    let temp = tempfile::tempdir().unwrap();
    let config_path = temp.path().join("config.yaml");

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .env("GHIDRA_CLI_CONFIG", &config_path)
        .arg("config")
        .arg("set")
        .arg("launch_timeout_secs")
        .arg("240")
        .assert()
        .success();

    let config = std::fs::read_to_string(config_path).unwrap();
    assert!(config.contains("launch_timeout_secs: 240"), "{config}");
}

#[test]
fn config_set_java_home_persists_requested_value_and_preserves_other_settings() {
    let temp = tempfile::tempdir().unwrap();
    let config_path = temp.path().join("config.yaml");
    let java_home = temp.path().join("JDK home's directory");
    std::fs::write(&config_path, "default_program: keep-me\naliases: {}\n").unwrap();

    let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .env("GHIDRA_CLI_CONFIG", &config_path)
        .env("XDG_DATA_HOME", temp.path())
        .env("GHIDRA_CLI_JAVA_HOME", temp.path().join("environment-jdk"))
        .arg("--java-home")
        .arg(temp.path().join("invocation-jdk"))
        .args(["config", "set", "java_home"])
        .arg(&java_home)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["key"], "java_home");

    let config: ghidra_cli::config::Config =
        serde_yaml::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
    assert_eq!(config.java_home.as_ref(), Some(&java_home));
    assert_eq!(config.default_program.as_deref(), Some("keep-me"));

    let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .env("GHIDRA_CLI_CONFIG", &config_path)
        .env("XDG_DATA_HOME", temp.path())
        .args(["config", "get", "java_home", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        serde_json::from_slice::<std::path::PathBuf>(&output.stdout).unwrap(),
        java_home
    );
}

#[test]
fn test_config_reset() {
    require_ghidra!();

    let temp = tempfile::tempdir().unwrap();
    let config_path = temp.path().join("config.yaml");

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .env("GHIDRA_CLI_CONFIG", &config_path)
        .arg("config")
        .arg("reset")
        .assert()
        .success();
}

#[test]
fn test_config_set_default_program() {
    require_ghidra!();

    let temp = tempfile::tempdir().unwrap();
    let config_path = temp.path().join("config.yaml");

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .env("GHIDRA_CLI_CONFIG", &config_path)
        .args(["config", "set", "default_program"])
        .arg("sample_binary")
        .assert()
        .success()
        .stdout(predicate::str::contains("Configuration updated"));
}

#[test]
fn test_config_set_default_project() {
    require_ghidra!();

    let temp = tempfile::tempdir().unwrap();
    let config_path = temp.path().join("config.yaml");

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .env("GHIDRA_CLI_CONFIG", &config_path)
        .args(["config", "set", "default_project"])
        .arg("test-project")
        .assert()
        .success()
        .stdout(predicate::str::contains("Configuration updated"));
}

#[test]
fn config_updates_from_multiple_processes_preserve_independent_values() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("config.yaml");
    let changes = [
        ("default_program", "program-a"),
        ("default_project", "project-a"),
        ("default_limit", "47"),
        ("launch_timeout_secs", "241"),
        ("ghidra_install_dir", "install-a"),
        ("ghidra_project_dir", "projects-a"),
        ("java_home", "jdk-a"),
    ];
    let mut children = Vec::new();
    for (key, value) in changes {
        children.push(
            std::process::Command::new(assert_cmd::cargo::cargo_bin!("ghidra-cli"))
                .env("GHIDRA_CLI_CONFIG", &path)
                .env("XDG_DATA_HOME", temp.path())
                .args(["config", "set", key, value])
                .stdout(std::process::Stdio::null())
                .spawn()
                .unwrap(),
        );
    }
    for mut child in children {
        assert!(child.wait().unwrap().success());
    }
    let config: ghidra_cli::config::Config =
        serde_yaml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(config.default_program.as_deref(), Some("program-a"));
    assert_eq!(config.default_project.as_deref(), Some("project-a"));
    assert_eq!(config.default_limit, Some(47));
    assert_eq!(config.launch_timeout_secs, Some(241));
    assert_eq!(config.ghidra_install_dir, Some("install-a".into()));
    assert_eq!(config.ghidra_project_dir, Some("projects-a".into()));
    assert_eq!(config.java_home, Some("jdk-a".into()));
}

#[test]
fn config_invalid_format_preserves_previous_file() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("config.yaml");
    let original = "default_program: keep-me\naliases: {}\n";
    std::fs::write(&path, original).unwrap();
    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .env("GHIDRA_CLI_CONFIG", &path)
        .env("XDG_DATA_HOME", temp.path())
        .args(["config", "set", "default_output_format", "unknown-format"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Unknown format"));
    assert_eq!(std::fs::read_to_string(path).unwrap(), original);
}

#[test]
fn config_relative_filename_updates_preserve_existing_settings() {
    let temp = tempfile::tempdir().unwrap();
    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .current_dir(temp.path())
        .env("GHIDRA_CLI_CONFIG", "config.yaml")
        .env("XDG_DATA_HOME", temp.path())
        .args(["config", "set", "default_program", "keep-me"])
        .assert()
        .success();
    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .current_dir(temp.path())
        .env("GHIDRA_CLI_CONFIG", "config.yaml")
        .env("XDG_DATA_HOME", temp.path())
        .args(["config", "set", "default_limit", "7"])
        .assert()
        .success();
    let config: ghidra_cli::config::Config =
        serde_yaml::from_str(&std::fs::read_to_string(temp.path().join("config.yaml")).unwrap())
            .unwrap();
    assert_eq!(config.default_program.as_deref(), Some("keep-me"));
    assert_eq!(config.default_limit, Some(7));
}
