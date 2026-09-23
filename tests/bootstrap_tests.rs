//! Durable import checkpoints, saved names, and real doctor startup.
#[path = "support/json.rs"]
mod json_output;

use ghidra_cli::ghidra::bridge;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

#[macro_use]
mod common;

#[path = "bootstrap/analysis.rs"]
mod analysis;
#[path = "bootstrap/compilation.rs"]
mod compilation;
#[path = "bootstrap/imports.rs"]
mod imports;

struct Project {
    root: tempfile::TempDir,
    path: PathBuf,
}
impl Project {
    fn new() -> Self {
        let root = tempfile::Builder::new()
            .prefix("bootstrap tests ")
            .tempdir()
            .unwrap();
        let path = root.path().join("project");
        Self { root, path }
    }
    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(assert_cmd::cargo::cargo_bin!("ghidra-cli"));
        command
            .args(args)
            .arg("--project")
            .arg(&self.path)
            .arg("--json");
        command
    }
    fn run(&self, args: &[&str]) -> Output {
        common::run_command_with_output(&mut self.command(args), Duration::from_secs(240)).unwrap()
    }
    fn ok(&self, args: &[&str]) -> Value {
        let output = self.run(args);
        assert!(
            output.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        crate::json_output::from_slice(&output.stdout).unwrap()
    }
    fn raw(&self) -> PathBuf {
        let path = self.root.path().join("original's file.bin");
        std::fs::write(&path, [0x31, 0xc0, 0xc3]).unwrap();
        path
    }
    fn client(&self) -> ghidra_cli::ipc::client::BridgeClient {
        ghidra_cli::ipc::client::BridgeClient::new(
            bridge::is_bridge_running(&self.path).expect("test bridge is running"),
        )
    }
    fn assert_program_identity(&self, name: &str) {
        let path = format!("/{name}");
        let command = ["program", "info"];
        let result = self.ok(&command);
        assert_eq!(result["name"], name, "{command:?}: {result}");
        assert_eq!(result["path"], path, "{command:?}: {result}");
        let client = self.client();
        assert_eq!(
            client.list_programs().unwrap()["current_program_name"],
            name
        );
        let state = client.bridge_info().unwrap();
        assert_eq!(state["current_program"], name);
        assert_eq!(state["current_program_path"], path);
        assert_eq!(client.stats().unwrap()["stats"]["program_name"], name);
    }
}
impl Drop for Project {
    fn drop(&mut self) {
        bridge::stop_bridge(&self.path).expect("stop test bridge before deleting its project");
    }
}

#[test]
fn configured_startup_targets_apply_to_all_entry_points() {
    require_ghidra!();
    let project = Project::new();
    let raw = project.raw();
    project.ok(&[
        "program",
        "import",
        raw.to_str().unwrap(),
        "--name",
        "configured-program",
        "--language",
        "x86:LE:32:default",
        "--no-analyze",
    ]);
    let config = project.root.path().join("config.yaml");
    let mut test_config = ghidra_cli::config::Config::load().unwrap();
    // Preserve runtime settings and exercise config-only installation lookup,
    // even when the test runner selects Ghidra through the environment.
    let installation = test_config.get_ghidra_installation().unwrap();
    test_config.ghidra_install_dir = None;
    test_config.ghidra_jar = None;
    match installation.kind {
        ghidra_cli::ghidra::installation::InstallationKind::Directory => {
            test_config.ghidra_install_dir = Some(installation.path);
        }
        ghidra_cli::ghidra::installation::InstallationKind::Jar => {
            test_config.ghidra_jar = Some(installation.path);
        }
    }
    test_config.default_project = Some(project.path.to_str().unwrap().to_owned());
    test_config.default_program = Some("configured-program".to_owned());
    std::fs::write(&config, serde_yaml::to_string(&test_config).unwrap()).unwrap();
    let batch = project.root.path().join("batch.txt");
    std::fs::write(&batch, "symbol externals\nsymbol entry-points\n").unwrap();
    for args in [
        vec!["bridge", "start"],
        vec!["symbol", "externals"],
        vec!["batch", batch.to_str().unwrap()],
    ] {
        project.ok(&["bridge", "stop"]);
        let mut command = Command::new(assert_cmd::cargo::cargo_bin!("ghidra-cli"));
        command
            .args(&args)
            .arg("--json")
            .env("GHIDRA_CLI_CONFIG", &config)
            .env_remove("GHIDRA_INSTALL_DIR")
            .env_remove("GHIDRA_JAR");
        let output =
            common::run_command_with_output(&mut command, Duration::from_secs(240)).unwrap();
        assert!(
            output.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        project.assert_program_identity("configured-program");
    }
}

#[test]
fn doctor_runtime_resolves_installation_and_removes_disposable_project() {
    require_ghidra!();
    let root = tempfile::Builder::new()
        .prefix("doctor tests ")
        .tempdir()
        .unwrap();
    let settings = tempfile::tempdir().unwrap();
    let mut config = ghidra_cli::config::Config::load().unwrap();
    let install = config.get_ghidra_installation().unwrap();
    config.ghidra_install_dir = None;
    config.ghidra_jar = None;
    let config_path = settings.path().join("config.yaml");
    let saved = serde_yaml::to_string(&config).unwrap();
    std::fs::write(&config_path, &saved).unwrap();
    let mut command = Command::new(assert_cmd::cargo::cargo_bin!("ghidra-cli"));
    command
        .args(["doctor", "--runtime", "--json"])
        .env_remove("GHIDRA_INSTALL_DIR")
        .env_remove("GHIDRA_JAR")
        .env("GHIDRA_CLI_CONFIG", &config_path)
        .env("GHIDRA_PROJECT_DIR", root.path());
    let expected_source = match install.kind {
        ghidra_cli::ghidra::installation::InstallationKind::Directory => {
            let mut path = vec![install.path.join("support")];
            path.extend(std::env::split_paths(
                &std::env::var_os("PATH").unwrap_or_default(),
            ));
            command.env("PATH", std::env::join_paths(path).unwrap());
            "PATH "
        }
        ghidra_cli::ghidra::installation::InstallationKind::Jar => {
            command.env("GHIDRA_JAR", &install.path);
            "GHIDRA_JAR"
        }
    };
    let output = common::run_command_with_output(&mut command, Duration::from_secs(240)).unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: Value = crate::json_output::from_slice(&output.stdout).unwrap();
    assert_eq!(
        result["installation"]["path"],
        serde_json::json!(install.path)
    );
    assert!(result["installation"]["source"]
        .as_str()
        .unwrap()
        .starts_with(expected_source));
    assert_eq!(std::fs::read_to_string(config_path).unwrap(), saved);
    assert_eq!(result["runtime"]["status"], "success", "{result}");
    assert_eq!(result["loopback"]["ok"], true);
    assert!(Path::new(
        result["runtime"]["paths"]["ghidra_settings"]
            .as_str()
            .unwrap()
    )
    .is_dir());
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
}
