//! Durable import checkpoints, saved names, and real doctor startup.
use ghidra_cli::ghidra::bridge;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

#[macro_use]
mod common;

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
        serde_json::from_slice(&output.stdout).unwrap()
    }
    fn raw(&self) -> PathBuf {
        let path = self.root.path().join("original's file.bin");
        std::fs::write(&path, [0x31, 0xc0, 0xc3]).unwrap();
        path
    }
}
impl Drop for Project {
    fn drop(&mut self) {
        bridge::stop_bridge(&self.path).expect("stop test bridge before deleting its project");
    }
}

#[test]
fn import_names_are_saved_and_selected_across_all_routes() {
    require_ghidra!();
    let project = Project::new();
    let binary = common::fixture_binary();
    for name in ["fresh-name", "running-name", "stopped-name"] {
        if name == "stopped-name" {
            project.ok(&["stop"]);
        }
        let result = project.ok(&[
            "import",
            binary.to_str().unwrap(),
            "--program",
            name,
            "--no-analyze",
        ]);
        assert_eq!(result[0]["program"], name);
        let programs = project.ok(&["program", "list"]);
        assert!(
            programs
                .as_array()
                .unwrap()
                .iter()
                .any(|p| p["name"] == name && p["current"] == true),
            "{programs}"
        );
    }
    let raw = project.raw();
    let args = [
        "import",
        raw.to_str().unwrap(),
        "--program",
        "raw-name",
        "--language",
        "x86:LE:32:default",
        "--base-address",
        "0x8000",
    ];
    let result = project.ok(&args);
    assert_eq!(result[0]["program"], "raw-name");
    let info = project.ok(&["program", "info"]);
    assert_eq!(info[0]["name"], raw.file_name().unwrap().to_str().unwrap());
    let disassembly = project.ok(&["disasm-at", "0x8000", "--count", "2"]);
    assert_eq!(disassembly[0]["instructions"][0]["mnemonic"], "XOR");
    let duplicate = project.run(&args);
    assert!(!duplicate.status.success());
    assert!(String::from_utf8_lossy(&duplicate.stderr).contains("Program already exists"));
    let programs = project.ok(&["program", "list"]);
    let names: Vec<_> = programs
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["name"].as_str().unwrap())
        .collect();
    assert_eq!(names.len(), 4, "{programs}");
    assert!(!names.contains(&raw.file_name().unwrap().to_str().unwrap()));
    // Without an explicit name, Ghidra may choose a suffix; return and select
    // the real saved file rather than the original input name.
    for _ in 0..2 {
        let result = project.ok(&["import", binary.to_str().unwrap(), "--no-analyze"]);
        let name = result[0]["program"].as_str().unwrap();
        let selected = project.ok(&["program", "list"]);
        assert!(
            selected
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["name"] == name && row["current"] == true),
            "{selected}"
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn saved_import_survives_bridge_state_directory_failure() {
    require_ghidra!();
    let project = Project::new();
    let raw = project.raw();
    let blocked = project.root.path().join("blocked-data");
    std::fs::write(&blocked, "retain").unwrap();
    let mut command = project.command(&[
        "import",
        raw.to_str().unwrap(),
        "--program",
        "saved-name",
        "--language",
        "x86:LE:32:default",
        "--base-address",
        "0x8000",
        "--no-analyze",
    ]);
    command.env("XDG_DATA_HOME", &blocked);
    let output = common::run_command_with_output(&mut command, Duration::from_secs(240)).unwrap();
    assert!(!output.status.success());
    let error: Value = serde_json::from_slice(&output.stderr).unwrap();
    let detail = &error["detail"];
    assert_eq!(detail["stage"], "bridge.state_directory", "{error}");
    assert_eq!(detail["path"], blocked.join("ghidra-cli").to_str().unwrap());
    assert_eq!(detail["import_status"], "saved");
    assert_eq!(detail["analysis_status"], "skipped");
    assert_eq!(detail["program"], "saved-name");
    assert_eq!(detail["recovery"][1], "start");
    project.ok(&["start", "--program", "saved-name"]);
    let programs = project.ok(&["program", "list"]);
    assert!(
        programs
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["name"] == "saved-name" && p["current"] == true),
        "{programs}"
    );
    assert_eq!(std::fs::read_to_string(blocked).unwrap(), "retain");
    project.ok(&["stop"]);
    let missing = project.run(&["start", "--program", "missing-program"]);
    assert!(!missing.status.success());
    let error: Value = serde_json::from_slice(&missing.stderr).unwrap();
    assert_eq!(error["detail"]["stage"], "bridge.program_open", "{error}");
    assert_eq!(error["detail"]["path"], "missing-program");
    assert!(bridge::is_bridge_running(&project.path).is_none());
}

#[test]
fn doctor_runtime_checks_real_jvm_and_removes_disposable_project() {
    require_ghidra!();
    let root = tempfile::Builder::new()
        .prefix("doctor tests ")
        .tempdir()
        .unwrap();
    let mut command = Command::new(assert_cmd::cargo::cargo_bin!("ghidra-cli"));
    command
        .args(["doctor", "--runtime", "--json"])
        .env("GHIDRA_PROJECT_DIR", root.path());
    let output = common::run_command_with_output(&mut command, Duration::from_secs(240)).unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
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
