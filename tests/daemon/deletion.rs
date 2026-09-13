use super::TEST_PROGRAM;
use crate::common::{self, DaemonTestHarness};
use serial_test::serial;
use std::time::Duration;

fn deletion_project() -> (tempfile::TempDir, std::path::PathBuf) {
    let root = ghidra_cli::config::Config::load()
        .unwrap()
        .get_project_dir()
        .unwrap();
    std::fs::create_dir_all(&root).unwrap();
    let directory = tempfile::Builder::new()
        .prefix("delete-test-")
        .tempdir_in(root)
        .unwrap();
    let project = directory.path().join(common::fixture::PROJECT_NAME);
    common::fixture::copy_analyzed_project(&project).unwrap();
    (directory, project)
}

fn project_cli(project: &std::path::Path, args: &[&str]) -> std::process::Output {
    common::run_command_with_output(
        std::process::Command::new(assert_cmd::cargo::cargo_bin!("ghidra-cli"))
            .args(["--json", "--quiet"])
            .args(args)
            .arg("--project")
            .arg(project),
        Duration::from_secs(300),
    )
    .unwrap()
}

#[test]
#[serial]
fn test_program_delete_current_closed_and_missing() {
    require_ghidra!();
    let (_directory, project) = deletion_project();
    let harness = DaemonTestHarness::new(project.to_str().unwrap(), TEST_PROGRAM).unwrap();
    let client = harness.client().unwrap();
    let pid = ghidra_cli::ghidra::bridge::read_pid_file(&project).unwrap();
    client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
public class CopyDeletionTargets extends GhidraScript {
    public void run() throws Exception {
        var root = state.getProject().getProjectData().getRootFolder();
        var folder = root.createFolder("copies");
        currentProgram.getDomainFile().copyTo(folder, monitor).setName("closed");
        currentProgram.getDomainFile().copyTo(folder, monitor).setName("later");
    }
}
"#,
            &[],
            &[],
            false,
        )
        .unwrap();

    // Copied files retain the same internal Program name. Deleting a closed
    // copy must not switch away from or close the initial program.
    let output = project_cli(
        &project,
        &["program", "delete", "--program", "/copies/closed"],
    );
    assert!(output.status.success(), "{output:?}");
    assert_eq!(client.program_info().unwrap()["name"], TEST_PROGRAM);
    client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
public class CheckDeletedCopy extends GhidraScript {
    public void run() throws Exception {
        if (!currentProgram.getDomainFile().getPathname().equals("/" + getScriptArgs()[0]))
            throw new IllegalStateException("Deletion changed the selected file");
        if (state.getProject().getProjectData().getFile("/copies/closed") != null)
            throw new IllegalStateException("Deleted file still exists");
    }
}
"#,
            &[TEST_PROGRAM.to_owned()],
            &[],
            false,
        )
        .unwrap();

    let output = project_cli(&project, &["program", "delete", "--program", "/missing"]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("Program not found"));
    assert_eq!(client.program_info().unwrap()["name"], TEST_PROGRAM);

    let output = project_cli(&project, &["program", "delete", "--program", TEST_PROGRAM]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(client.bridge_info().unwrap()["has_current_program"], false);
    assert_eq!(
        ghidra_cli::ghidra::bridge::read_pid_file(&project).unwrap(),
        pid
    );
    assert!(client.open_program(TEST_PROGRAM).is_err());

    client.open_program("/copies/later").unwrap();
    client.program_close().unwrap();
    let output = project_cli(
        &project,
        &["program", "delete", "--program", "/copies/later"],
    );
    assert!(output.status.success(), "{output:?}");
    assert_eq!(client.bridge_info().unwrap()["has_current_program"], false);
    assert!(client.open_program("/copies/later").is_err());
}

#[test]
#[serial]
fn test_program_delete_from_stopped_bridge_and_empty_project() {
    require_ghidra!();
    let (_directory, project) = deletion_project();
    // The harness retains cleanup ownership across CLI stop/start invocations.
    let harness = DaemonTestHarness::new(project.to_str().unwrap(), TEST_PROGRAM).unwrap();
    ghidra_cli::ghidra::bridge::stop_bridge(&project).unwrap();
    let output = project_cli(&project, &["program", "delete", "--program", TEST_PROGRAM]);
    assert!(output.status.success(), "{output:?}");
    ghidra_cli::ghidra::bridge::stop_bridge(&project).unwrap();

    let output = project_cli(&project, &["start", "--program", "missing"]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(ghidra_cli::ghidra::bridge::is_bridge_running(&project).is_none());

    // Reopen the now-empty project to prove deletion persisted. Project mode
    // must not depend on a file that the headless analyzer can -process.
    let output = project_cli(&project, &["program", "list"]);
    assert!(output.status.success(), "{output:?}");
    let programs: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(programs, serde_json::json!([]));
    let port = ghidra_cli::ghidra::bridge::is_bridge_running(&project).unwrap();
    let client = ghidra_cli::ipc::client::BridgeClient::new(port);
    assert_eq!(client.bridge_info().unwrap()["has_current_program"], false);
    assert!(client.open_program(TEST_PROGRAM).is_err());
    let missing_project = project.parent().unwrap().join("missing-project");
    let output = project_cli(&missing_project, &["start"]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(!missing_project.with_extension("gpr").exists());
    assert!(!missing_project.with_extension("rep").exists());
    drop(harness);
}

#[test]
#[serial]
fn test_program_delete_preserves_other_consumers_and_works_in_batch() {
    require_ghidra!();
    let (_directory, project) = deletion_project();
    let harness = DaemonTestHarness::new(project.to_str().unwrap(), TEST_PROGRAM).unwrap();
    let client = harness.client().unwrap();
    client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
public class HoldDeletionTarget extends GhidraScript {
    public void run() { currentProgram.addConsumer(currentProgram); }
}
"#,
            &[],
            &[],
            false,
        )
        .unwrap();
    let deletion = client.program_delete(TEST_PROGRAM);
    // Release the test's own reference before asserting the deletion result.
    client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
public class ReleaseDeletionTarget extends GhidraScript {
    public void run() {
        if (!currentProgram.getConsumerList().contains(currentProgram))
            throw new IllegalStateException("Deletion released another consumer");
        currentProgram.release(currentProgram);
    }
}
"#,
            &[],
            &[],
            false,
        )
        .unwrap();
    assert!(deletion.unwrap_err().to_string().contains("is in use"));
    assert_eq!(client.program_info().unwrap()["name"], TEST_PROGRAM);

    let batch = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        batch.path(),
        format!("program delete --program {TEST_PROGRAM}\nprogram list\n"),
    )
    .unwrap();
    let output = project_cli(&project, &["batch", batch.path().to_str().unwrap()]);
    assert!(output.status.success(), "{output:?}");
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value[0]["failed"], 0);
    assert_eq!(value[0]["results"][0]["result"]["status"], "deleted");
    assert_eq!(value[0]["results"][1]["result"]["count"], 0);
    assert_eq!(client.bridge_info().unwrap()["has_current_program"], false);
}
