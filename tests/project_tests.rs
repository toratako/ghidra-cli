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

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("project")
        .arg("create")
        .arg(&project)
        .assert()
        .success()
        .stdout(predicate::str::contains("created").or(predicate::str::contains("Created")));

    // Cleanup
    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("project")
        .arg("delete")
        .arg(&project)
        .assert()
        .success();
}

#[test]
fn test_project_list() {
    require_ghidra!();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("project")
        .arg("list")
        .assert()
        .success();
}

#[test]
fn test_project_info() {
    require_ghidra!();

    let project = unique_project_name("info");

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("project")
        .arg("create")
        .arg(&project)
        .assert()
        .success();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("project")
        .arg("info")
        .arg(&project)
        .assert()
        .success();

    // Cleanup
    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
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

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("project")
        .arg("create")
        .arg(&project)
        .assert()
        .success();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("project")
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains(&project));

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
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
    // `ghidra import` spawns a JVM whose inherited pipe handles block output() forever.
    let ghidra_bin = assert_cmd::cargo::cargo_bin!("ghidra");
    let status = common::run_cli_with_timeout(
        ghidra_bin,
        &[
            "import",
            binary.to_str().unwrap(),
            "--project",
            &project,
            "--program",
            "sample_binary",
        ],
        std::time::Duration::from_secs(300),
    )
    .expect("Failed to run import");
    assert!(status.success(), "Import failed with status: {}", status);

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
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

    let ghidra_bin = assert_cmd::cargo::cargo_bin!("ghidra");
    let status = common::run_cli_with_timeout(
        ghidra_bin,
        &[
            "import",
            binary.to_str().unwrap(),
            "--project",
            &project,
            "--program",
            "sample_binary",
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
            "sample_binary",
        ],
        std::time::Duration::from_secs(300),
    )
    .expect("Failed to run analyze");
    assert!(status.success(), "Analyze failed with status: {}", status);

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
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

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("project")
        .arg("delete")
        .arg(&project)
        .assert()
        .success()
        .stdout(predicate::str::contains("not found"));
}

#[test]
#[serial]
fn test_import_existing_program() {
    require_ghidra!();

    let project = unique_project_name("import-existing");
    let binary = common::fixture_binary();

    // Use run_cli_with_timeout to avoid Windows pipe handle inheritance.
    let ghidra_bin = assert_cmd::cargo::cargo_bin!("ghidra");
    let status = common::run_cli_with_timeout(
        ghidra_bin,
        &[
            "import",
            binary.to_str().unwrap(),
            "--project",
            &project,
            "--program",
            "sample_binary",
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
            "sample_binary",
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

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
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

    let ghidra_bin = assert_cmd::cargo::cargo_bin!("ghidra");
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

    let info = assert_cmd::cargo::cargo_bin_cmd!("ghidra")
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

    let disasm = assert_cmd::cargo::cargo_bin_cmd!("ghidra")
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

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .args(["stop", "--project", &project])
        .assert()
        .success();
    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .args(["project", "delete", &project])
        .assert()
        .success();
}
