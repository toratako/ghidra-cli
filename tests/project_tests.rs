//! Tests for project management commands.

use predicates::prelude::*;
use serial_test::serial;

#[macro_use]
mod common;

/// Generate unique project name for test isolation.
/// UUID prevents collisions in parallel CI runs.
fn unique_project_name(prefix: &str) -> String {
    format!("test-{}-{}", prefix, uuid::Uuid::new_v4())
}

#[test]
fn test_project_create() {
    require_ghidra!();

    let project = unique_project_name("create");

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("project")
        .arg("create")
        .arg(&project)
        .assert()
        .success()
        .stdout(predicate::str::contains("created").or(predicate::str::contains("Created")));

    // Cleanup
    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("project")
        .arg("delete")
        .arg(&project)
        .assert()
        .success();
}

#[test]
fn test_project_list() {
    require_ghidra!();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("project")
        .arg("list")
        .assert()
        .success();
}

#[test]
fn test_project_info() {
    require_ghidra!();

    let project = unique_project_name("info");

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("project")
        .arg("create")
        .arg(&project)
        .assert()
        .success();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("project")
        .arg("info")
        .arg(&project)
        .assert()
        .success();

    // Cleanup
    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("project")
        .arg("delete")
        .arg(&project)
        .assert()
        .success();
}

#[test]
fn test_project_lifecycle() {
    require_ghidra!();

    let project = unique_project_name("lifecycle");

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("project")
        .arg("create")
        .arg(&project)
        .assert()
        .success();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("project")
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains(&project));

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("project")
        .arg("delete")
        .arg(&project)
        .assert()
        .success();
}

#[test]
#[serial]
fn test_import_binary() {
    require_ghidra!();

    let project = unique_project_name("import");
    let binary = common::fixture_binary();

    // Use run_cli_with_timeout to avoid Windows pipe handle inheritance.
    // `ghidra-cli import` spawns a JVM whose inherited pipe handles block output() forever.
    let ghidra_bin = assert_cmd::cargo::cargo_bin!("ghidra-cli");
    let status = common::run_cli_with_timeout(
        ghidra_bin,
        &[
            "import",
            binary.to_str().unwrap(),
            "--project",
            &project,
            "--program",
            common::FIXTURE_PROGRAM,
        ],
        std::time::Duration::from_secs(300),
    )
    .expect("Failed to run import");
    assert!(status.success(), "Import failed with status: {}", status);

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("project")
        .arg("delete")
        .arg(&project)
        .assert()
        .success();
}

#[test]
#[serial]
fn test_analyze_program() {
    require_ghidra!();

    let project = unique_project_name("analyze");
    let binary = common::fixture_binary();

    let ghidra_bin = assert_cmd::cargo::cargo_bin!("ghidra-cli");
    let status = common::run_cli_with_timeout(
        ghidra_bin,
        &[
            "import",
            binary.to_str().unwrap(),
            "--project",
            &project,
            "--program",
            common::FIXTURE_PROGRAM,
            "--no-analyze",
        ],
        std::time::Duration::from_secs(300),
    )
    .expect("Failed to run import");
    assert!(status.success(), "Import failed with status: {}", status);

    let status = common::run_cli_with_timeout(
        ghidra_bin,
        &[
            "analyze",
            "--project",
            &project,
            "--program",
            common::FIXTURE_PROGRAM,
        ],
        std::time::Duration::from_secs(300),
    )
    .expect("Failed to run analyze");
    assert!(status.success(), "Analyze failed with status: {}", status);

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("project")
        .arg("delete")
        .arg(&project)
        .assert()
        .success();
}

#[test]
fn test_project_delete_nonexistent() {
    require_ghidra!();

    let project = unique_project_name("missing");

    let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("project")
        .arg("delete")
        .arg(&project)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["project"], project);
    assert_eq!(value["deleted"], false);
}

#[test]
#[serial]
fn test_project_delete_stops_bridge_for_equivalent_paths() -> anyhow::Result<()> {
    use ghidra_cli::ghidra::bridge;

    require_ghidra!();
    let root = tempfile::Builder::new()
        .prefix("ghidra-delete-alias-")
        .tempdir()?;
    let project = root.path().join("nested/project");
    common::fixture::copy_analyzed_project(&project)?;
    let harness =
        common::DaemonTestHarness::new(project.to_str().unwrap(), common::FIXTURE_PROGRAM)?;
    let pid = bridge::read_pid_file(&project)?.expect("bridge PID");
    let port_file = bridge::port_file_path(&project)?;
    let pid_file = bridge::pid_file_path(&project)?;
    let alias = root.path().join(if cfg!(windows) {
        "nested/./PROJECT"
    } else {
        "nested/./project"
    });
    assert_eq!(bridge::is_bridge_running(&alias), Some(harness.port()));

    let output = common::run_command_with_output(
        std::process::Command::new(assert_cmd::cargo::cargo_bin!("ghidra-cli"))
            .args(["--json", "project", "delete"])
            .arg(&alias),
        std::time::Duration::from_secs(60),
    )?;
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout)?["deleted"],
        true
    );
    assert!(
        !bridge::is_pid_alive(pid),
        "Project deletion left the bridge running"
    );
    assert!(!project.with_extension("gpr").exists());
    assert!(!project.with_extension("rep").exists());
    assert!(!port_file.exists());
    assert!(!pid_file.exists());
    drop(harness);
    Ok(())
}

#[test]
#[serial]
fn test_import_existing_program() {
    require_ghidra!();

    let project = unique_project_name("import-existing");
    let binary = common::fixture_binary();

    // Use run_cli_with_timeout to avoid Windows pipe handle inheritance.
    let ghidra_bin = assert_cmd::cargo::cargo_bin!("ghidra-cli");
    let status = common::run_cli_with_timeout(
        ghidra_bin,
        &[
            "import",
            binary.to_str().unwrap(),
            "--project",
            &project,
            "--program",
            common::FIXTURE_PROGRAM,
            "--no-analyze",
        ],
        std::time::Duration::from_secs(300),
    )
    .expect("Failed to run import");
    assert!(status.success(), "Import failed with status: {}", status);

    // Import again - should still succeed (idempotent or with new name)
    let status = common::run_cli_with_timeout(
        ghidra_bin,
        &[
            "import",
            binary.to_str().unwrap(),
            "--project",
            &project,
            "--program",
            common::FIXTURE_PROGRAM,
            "--no-analyze",
        ],
        std::time::Duration::from_secs(300),
    )
    .expect("Failed to run second import");
    assert!(
        status.success(),
        "Second import failed with status: {}",
        status
    );

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("project")
        .arg("delete")
        .arg(&project)
        .assert()
        .success();
}

#[test]
#[serial]
fn test_import_raw_x86_blob_with_language_and_base_address() {
    require_ghidra!();

    let project = unique_project_name("raw-x86");
    let tmp = tempfile::tempdir().expect("tempdir");
    let blob = tmp.path().join("x86_raw.bin");
    // x86 32-bit little-endian: xor eax, eax; ret
    std::fs::write(&blob, [0x31, 0xc0, 0xc3]).expect("write raw fixture");

    let ghidra_bin = assert_cmd::cargo::cargo_bin!("ghidra-cli");
    let status = common::run_cli_with_timeout(
        ghidra_bin,
        &[
            "import",
            blob.to_str().unwrap(),
            "--project",
            &project,
            "--language",
            "x86:LE:32:default",
            "--base-address",
            "0x8000",
            "--block-name",
            "ROM",
            "--no-analyze",
        ],
        std::time::Duration::from_secs(300),
    )
    .expect("raw import command");
    assert!(status.success(), "raw x86 import failed: {}", status);

    let info = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .args([
            "program",
            "info",
            "--project",
            &project,
            "--program",
            "x86_raw.bin",
            "--json",
        ])
        .output()
        .expect("program info");
    assert!(info.status.success());
    let info_json: serde_json::Value =
        serde_json::from_slice(&info.stdout).expect("program info JSON");
    let program = &info_json[0];
    assert_eq!(program["executable_format"], "Raw Binary");
    assert_eq!(program["language"], "x86/little/32/default");
    assert_eq!(program["min_address"], "00008000");
    assert_eq!(program["max_address"], "00008002");

    let disasm = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .args([
            "disasm-at",
            "0x8000",
            "--count",
            "2",
            "--project",
            &project,
            "--program",
            "x86_raw.bin",
            "--json",
        ])
        .output()
        .expect("raw disassembly");
    assert!(disasm.status.success());
    let disasm_json: serde_json::Value =
        serde_json::from_slice(&disasm.stdout).expect("disassembly JSON");
    let instructions = disasm_json[0]["instructions"]
        .as_array()
        .expect("instructions");
    assert_eq!(instructions.len(), 2);
    assert_eq!(instructions[0]["mnemonic"], "XOR");
    assert_eq!(instructions[1]["mnemonic"], "RET");

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .args(["stop", "--project", &project])
        .assert()
        .success();
    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .args(["project", "delete", &project])
        .assert()
        .success();
}
