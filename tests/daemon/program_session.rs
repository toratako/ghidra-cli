use super::{start_daemon, TEST_PROGRAM};
use crate::common::{self, ensure_test_project, test_project};
use ghidra_cli::ipc::{client::BridgeClient, protocol::BridgeCommandError};
use serde_json::json;
use serial_test::serial;
use std::time::{Duration, Instant};

/// Read a separate database object from the saved file while the bridge stays
/// running. A normal comment_get would only prove the in-memory edit exists.
fn assert_saved_comment(client: &ghidra_cli::ipc::client::BridgeClient, address: &str, text: &str) {
    client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.CodeUnit;
public class CheckAutoSavedComment extends GhidraScript {
    public void run() throws Exception {
        if (currentProgram.isChanged()) throw new IllegalStateException("Program is still dirty");
        Object consumer = new Object();
        Program saved = (Program) currentProgram.getDomainFile()
            .getReadOnlyDomainObject(consumer, DomainFile.DEFAULT_VERSION, monitor);
        try {
            String actual = saved.getListing().getComment(CodeUnit.EOL_COMMENT,
                saved.getAddressFactory().getAddress(getScriptArgs()[0]));
            if (!getScriptArgs()[1].equals(actual)) {
                throw new IllegalStateException("Saved comment differs: " + actual);
            }
        } finally {
            saved.release(consumer);
        }
    }
}
"#,
            &[address.to_owned(), text.to_owned()],
            &[],
            false,
        )
        .unwrap();
}

#[test]
#[serial]
fn test_program_list_excludes_archives_at_every_depth() {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    let client = harness.client().unwrap();
    let initial_count = client.list_programs().unwrap()["count"].as_u64().unwrap();
    let name = format!("mixed-{}", uuid::Uuid::new_v4());
    client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.database.DataTypeArchiveDB;
public class CreateMixedProjectFiles extends GhidraScript {
    public void run() throws Exception {
        var root = state.getProject().getProjectData().getRootFolder();
        String name = getScriptArgs()[0];
        var folder = root.createFolder(name);
        for (var parent : new ghidra.framework.model.DomainFolder[] { root, folder }) {
            Object consumer = new Object();
            var archive = new DataTypeArchiveDB(parent, name + ".gdt", consumer);
            archive.release(consumer);
            if (parent.getFile(name + ".gdt") == null)
                throw new IllegalStateException("Archive fixture was not saved");
        }
        currentProgram.getDomainFile().copyTo(folder, monitor).setName("copy");
    }
}
"#,
            std::slice::from_ref(&name),
            &[],
            false,
        )
        .unwrap();
    let programs = client.list_programs().unwrap();
    assert_eq!(programs["count"], initial_count + 1);
    assert_eq!(
        client.bridge_info().unwrap()["program_count"],
        programs["count"]
    );
    let rows = programs["programs"].as_array().unwrap();
    assert!(rows
        .iter()
        .any(|row| row["path"] == format!("/{name}/copy")));
    assert!(rows
        .iter()
        .all(|row| !row["name"].as_str().unwrap().ends_with(".gdt")));
    for row in rows {
        client.open_program(row["path"].as_str().unwrap()).unwrap();
    }
    client.open_program(TEST_PROGRAM).unwrap();
    drop(harness);
    let restarted = start_daemon();
    let client = restarted.client().unwrap();
    assert_eq!(client.list_programs().unwrap()["count"], initial_count + 1);
    assert_eq!(
        client.bridge_info().unwrap()["program_count"],
        initial_count + 1
    );
    client.program_delete(&format!("/{name}/copy")).unwrap();
}

#[test]
#[serial]
fn test_failed_mutation_preserves_prior_edits_after_restart() {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    let client = harness.client().unwrap();
    let function = crate::common::helpers::get_fixture_function(&client, "add_numbers");
    let address = function.address.as_str();
    let text = format!("persist-before-failure-{}", uuid::Uuid::new_v4());
    client.comment_set(address, &text, Some("EOL")).unwrap();
    assert_saved_comment(&client, address, &text);

    // The address parses, but is outside every memory block. Preflight must
    // reject it while retaining the previously saved comment.
    let error = client
        .send_command(
            "memory_write",
            Some(serde_json::json!({"address": "0x0", "hex": "00"})),
        )
        .unwrap_err();
    assert!(
        error.to_string().contains("fully mapped and initialized"),
        "{error}"
    );
    let detail = &error
        .downcast_ref::<ghidra_cli::ipc::protocol::BridgeCommandError>()
        .unwrap()
        .detail;
    assert_eq!(detail["rolled_back"], true);
    assert!(detail.get("partial_changes_saved").is_none());
    assert_saved_comment(&client, address, &text);
    drop(harness);

    let restarted = start_daemon();
    let comments = restarted.client().unwrap().comment_get(address).unwrap();
    assert!(
        comments["comments"]
            .as_array()
            .unwrap()
            .iter()
            .any(|comment| comment["text"] == text),
        "prior edit lost after failed mutation: {comments}"
    );
}

#[test]
#[serial]
fn test_queued_requests_keep_their_program_target() {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    let client = harness.client().unwrap();
    let function = crate::common::helpers::get_fixture_function(&client, "add_numbers");
    let address = function.address;
    let folder = format!("request-targets-{}", uuid::Uuid::new_v4());
    client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
public class CopyRequestTargetPrograms extends GhidraScript {
    public void run() throws Exception {
        var folder = state.getProject().getProjectData().getRootFolder().createFolder(getScriptArgs()[0]);
        for (String child : new String[] { "first", "second" }) {
            currentProgram.getDomainFile().copyTo(folder.createFolder(child), monitor).setName("same-name");
        }
    }
}
"#,
            std::slice::from_ref(&folder),
            &[],
            false,
        )
        .unwrap();
    let first = format!("/{folder}/first/same-name");
    let second = format!("/{folder}/second/same-name");
    client.open_program(&second).unwrap();

    // Hold the script lane until all requests have been accepted. Every queued
    // request must retain its own target despite sharing one current Program.
    let release_directory = tempfile::tempdir().unwrap();
    let release = release_directory.path().join("release");
    let script_release = release.to_str().unwrap().to_owned();
    let worker = harness.client().unwrap();
    let blocker = std::thread::spawn(move || {
        worker.script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
public class HoldProgramTargetQueue extends GhidraScript {
    public void run() throws Exception {
        var release = new java.io.File(getScriptArgs()[0]);
        monitor.setMessage("holding-program-target-queue");
        long deadline = System.currentTimeMillis() + 30000;
        while (!release.exists()) {
            monitor.checkCancelled();
            if (System.currentTimeMillis() > deadline) {
                throw new IllegalStateException("Program target queue was not released");
            }
            Thread.sleep(10);
        }
    }
}
"#,
            &[script_release],
            &[],
            false,
        )
    });
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        let status = client.status().unwrap();
        if status["active_job"]["progress_message"] == "holding-program-target-queue" {
            break;
        }
        assert!(!blocker.is_finished(), "queue blocker exited: {status}");
        assert!(
            Instant::now() < deadline,
            "queue blocker did not start: {status}"
        );
        std::thread::sleep(Duration::from_millis(10));
    }

    let mut queued = Vec::new();
    for (program, command, args, field, expected) in [
        (
            &first,
            "rename_function",
            json!({"old_name": address, "new_name": "targeted_first"}),
            "old_name",
            function.name.as_str(),
        ),
        (
            &second,
            "rename_function",
            json!({"old_name": address, "new_name": "targeted_second"}),
            "old_name",
            function.name.as_str(),
        ),
        (
            &first,
            "get_function",
            json!({"address": address}),
            "name",
            "targeted_first",
        ),
        (
            &second,
            "get_function",
            json!({"address": address}),
            "name",
            "targeted_second",
        ),
    ] {
        let worker = BridgeClient::new(harness.port()).with_program(program.clone());
        let request = std::thread::spawn(move || worker.send_command(command, Some(args)));
        queued.push((request, field, expected));
        loop {
            let status = client.status().unwrap();
            if status["queue_depth"].as_u64() == Some(queued.len() as u64) {
                break;
            }
            assert!(!blocker.is_finished(), "queue blocker exited: {status}");
            assert!(
                Instant::now() < deadline,
                "request was not queued: {status}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    std::fs::write(&release, b"release").unwrap();
    blocker.join().unwrap().unwrap();
    for (request, field, expected) in queued {
        let response = request.join().unwrap().unwrap();
        assert_eq!(response[field], expected, "{response}");
    }

    // Closing and selecting each copy again proves that the edits were saved
    // to separate databases, including when their file/internal names match.
    client.program_close().unwrap();
    for (program, expected) in [(&first, "targeted_first"), (&second, "targeted_second")] {
        let selected = BridgeClient::new(harness.port()).with_program(program.clone());
        let info = selected.program_info().unwrap();
        assert_eq!(info["path"], *program);
        let function = selected
            .send_command("get_function", Some(json!({"address": address})))
            .unwrap();
        assert_eq!(function["name"], expected, "{function}");
    }

    // An invalid target must fail before the mutation, without falling back to
    // the successfully selected second copy.
    for target in ["".to_owned(), format!("/{folder}/missing")] {
        let invalid = BridgeClient::new(harness.port()).with_program(target);
        invalid
            .send_command(
                "rename_function",
                Some(json!({"old_name": address, "new_name": "wrong_target"})),
            )
            .unwrap_err();
        assert_eq!(
            client.bridge_info().unwrap()["current_program_path"],
            second
        );
        let function = client
            .send_command("get_function", Some(json!({"address": address})))
            .unwrap();
        assert_eq!(function["name"], "targeted_second");
    }
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&first).unwrap();
    client.program_delete(&second).unwrap();
}

#[test]
#[serial]
fn test_handlers_follow_program_switch_and_close() {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    let client = harness.client().unwrap();
    let initial_count = client.list_programs().unwrap()["count"].as_u64().unwrap();
    assert_eq!(
        client.bridge_info().unwrap()["program_count"],
        initial_count
    );
    let folder = format!("switch-{}", uuid::Uuid::new_v4());
    client.script_run_source(r#"
import ghidra.app.script.GhidraScript;
public class CopyBridgeProgram extends GhidraScript {
    public void run() throws Exception {
        var folder = state.getProject().getProjectData().getRootFolder().createFolder(getScriptArgs()[0]);
        currentProgram.getDomainFile().copyTo(folder, monitor).setName("alternate");
        currentProgram.getDomainFile().copyTo(folder.createFolder("deeper"), monitor).setName("alternate");
    }
}
"#, std::slice::from_ref(&folder), &[], false).unwrap();
    let alternate = format!("/{folder}/alternate");
    let deeper_alternate = format!("/{folder}/deeper/alternate");
    client.open_program(&alternate).unwrap();
    // Copying/renaming the project file retains the original internal Program
    // name. Switching back must compare project files, not that internal name.
    let info = client.program_info().unwrap();
    assert_eq!(info["name"], "alternate");
    assert_eq!(info["path"], alternate);
    let state = client.bridge_info().unwrap();
    assert_eq!(state["current_program"], "alternate");
    assert_eq!(state["current_program_path"], alternate);
    let programs = client.send_command("list_programs", None).unwrap();
    let rows = programs["programs"].as_array().unwrap();
    assert_eq!(programs["count"].as_u64(), Some(rows.len() as u64));
    assert_eq!(programs["count"], initial_count + 2);
    assert_eq!(
        client.bridge_info().unwrap()["program_count"],
        programs["count"]
    );
    for path in [&alternate, &deeper_alternate] {
        let row = rows.iter().find(|row| row["path"] == *path).unwrap();
        assert_eq!(row["name"], "alternate");
        assert_eq!(row["current"], *path == alternate);
        assert!(row["function_count"].as_u64().unwrap() > 1);
        assert_eq!(row["analyzed"], true);
    }
    assert_eq!(rows.iter().filter(|row| row["current"] == true).count(), 1);
    client.open_program(&deeper_alternate).unwrap();
    let programs = client.send_command("list_programs", None).unwrap();
    let current: Vec<_> = programs["programs"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["current"] == true)
        .collect();
    assert_eq!(current.len(), 1);
    assert_eq!(current[0]["path"], deeper_alternate);
    client.open_program(&alternate).unwrap();
    let function = crate::common::helpers::get_fixture_function(&client, "add_numbers");
    let address = function.address.as_str();
    let marker = format!("alternate-only-{}", uuid::Uuid::new_v4());
    client.comment_set(address, &marker, Some("EOL")).unwrap();
    assert_saved_comment(&client, address, &marker);
    assert!(client.comment_get(address).unwrap()["comments"]
        .as_array()
        .unwrap()
        .iter()
        .any(|comment| comment["text"] == marker));
    client.open_program(TEST_PROGRAM).unwrap();
    assert_eq!(client.program_info().unwrap()["name"], TEST_PROGRAM);
    let programs = client.send_command("list_programs", None).unwrap();
    assert!(programs["programs"]
        .as_array()
        .unwrap()
        .iter()
        .any(|program| program["name"] == TEST_PROGRAM && program["current"] == true));
    assert!(!client.comment_get(address).unwrap()["comments"]
        .as_array()
        .unwrap()
        .iter()
        .any(|comment| comment["text"] == marker));
    client.open_program(&alternate).unwrap();
    common::ghidra(&harness)
        .arg("comment")
        .arg("get")
        .arg(address)
        .with_project(test_project(), TEST_PROGRAM)
        .json_format()
        .run()
        .assert_success()
        .assert_stdout_not_contains(&marker);
    client.open_program(&alternate).unwrap();
    BridgeClient::new(harness.port())
        .with_program(TEST_PROGRAM)
        .send_command("analysis_run", None)
        .unwrap();
    assert!(!client.comment_get(address).unwrap()["comments"]
        .as_array()
        .unwrap()
        .iter()
        .any(|comment| comment["text"] == marker));
    client.program_close().unwrap();
    let programs = client.send_command("list_programs", None).unwrap();
    assert_eq!(programs["has_current_program"], false);
    assert!(programs["programs"]
        .as_array()
        .unwrap()
        .iter()
        .all(|row| row["current"] == false));
    assert!(client
        .comment_get(address)
        .unwrap_err()
        .to_string()
        .contains("No program loaded"));
    client.open_program(TEST_PROGRAM).unwrap();
    client.comment_get(address).unwrap();
    drop(harness);
    let restarted = start_daemon();
    let client = restarted.client().unwrap();
    assert_eq!(
        client.bridge_info().unwrap()["program_count"],
        initial_count + 2
    );
    client.program_delete(&deeper_alternate).unwrap();
    assert_eq!(
        client.bridge_info().unwrap()["program_count"],
        initial_count + 1
    );
    client.program_delete(&alternate).unwrap();
    assert_eq!(
        client.bridge_info().unwrap()["program_count"],
        initial_count
    );
    assert_eq!(client.list_programs().unwrap()["count"], initial_count);
}

#[test]
#[serial]
fn test_program_list_analysis_flag_uses_live_and_saved_options() {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    let client = harness.client().unwrap();
    let folder = format!("analysis-flags-{}", uuid::Uuid::new_v4());
    client.script_run_source(r#"
import ghidra.app.script.GhidraScript;
public class CopyAnalysisFlagProgram extends GhidraScript {
    public void run() throws Exception {
        var folder = state.getProject().getProjectData().getRootFolder().createFolder(getScriptArgs()[0]);
        currentProgram.getDomainFile().copyTo(folder, monitor);
    }
}
"#, std::slice::from_ref(&folder), &[], false).unwrap();
    let copied = format!("/{folder}/{TEST_PROGRAM}");
    for (flag, expected) in [
        ("false", serde_json::json!(false)),
        ("missing", serde_json::Value::Null),
        ("invalid", serde_json::Value::Null),
        ("true", serde_json::json!(true)),
    ] {
        client.open_program(&copied).unwrap();
        client.script_run_source(r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;
public class SetAnalysisFlagForMetadata extends GhidraScript {
    public void run() throws Exception {
        var options = currentProgram.getOptions(Program.PROGRAM_INFO);
        options.removeOption(Program.ANALYZED_OPTION_NAME);
        String flag = getScriptArgs()[0];
        if (flag.equals("invalid")) options.setString(Program.ANALYZED_OPTION_NAME, "unknown");
        else if (!flag.equals("missing")) options.setBoolean(Program.ANALYZED_OPTION_NAME, Boolean.parseBoolean(flag));
    }
}
"#, &[flag.to_owned()], &[], false).unwrap();
        for current in [true, false] {
            if !current {
                client.open_program(TEST_PROGRAM).unwrap();
            }
            let listing = client.list_programs().unwrap();
            let row = listing["programs"]
                .as_array()
                .unwrap()
                .iter()
                .find(|row| row["path"] == copied)
                .unwrap();
            assert_eq!(row["current"], current);
            assert!(row["function_count"].as_u64().unwrap() > 1, "{row}");
            assert_eq!(row.get("analyzed"), Some(&expected), "{flag}: {row}");
        }
    }
    client.program_delete(&copied).unwrap();
}

#[test]
#[serial]
fn test_failed_script_saves_partial_changes() {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    let client = harness.client().unwrap();
    let function = crate::common::helpers::get_fixture_function(&client, "add_numbers");
    let address = function.address.as_str();
    let text = format!("failed-script-autosave-{}", uuid::Uuid::new_v4());
    let error = client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
public class EditThenFailAutoSave extends GhidraScript {
    public void run() throws Exception {
        setEOLComment(toAddr(getScriptArgs()[0]), getScriptArgs()[1]);
        throw new IllegalStateException("intentional failure after editing");
    }
}
"#,
            &[address.to_owned(), text.clone()],
            &[],
            false,
        )
        .unwrap_err();
    let error = error
        .downcast_ref::<ghidra_cli::ipc::protocol::BridgeCommandError>()
        .unwrap();
    assert!(error.message.contains("intentional failure after editing"));
    assert_eq!(error.detail["partial_changes_saved"], true);
    assert!(error.detail.get("rolled_back").is_none());
    assert_saved_comment(&client, address, &text);
    drop(harness);
    let restarted = start_daemon();
    let comments = restarted.client().unwrap().comment_get(address).unwrap();
    assert!(comments["comments"]
        .as_array()
        .unwrap()
        .iter()
        .any(|comment| comment["text"] == text));
}

#[test]
#[serial]
fn test_save_failure_preserves_program_and_does_not_replay_edit() {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    let client = harness.client().unwrap();
    let original_path = client.program_info().unwrap()["path"]
        .as_str()
        .unwrap()
        .to_owned();
    let function = crate::common::helpers::get_fixture_function(&client, "add_numbers");
    let folder = format!("failed-target-switch-{}", uuid::Uuid::new_v4());
    client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
public class CopyFailedSwitchTarget extends GhidraScript {
    public void run() throws Exception {
        var folder = state.getProject().getProjectData().getRootFolder().createFolder(getScriptArgs()[0]);
        currentProgram.getDomainFile().copyTo(folder, monitor);
    }
}
"#,
            std::slice::from_ref(&folder),
            &[],
            false,
        )
        .unwrap();
    let target_path = format!("/{folder}/{TEST_PROGRAM}");
    let targeted = BridgeClient::new(harness.port()).with_program(&target_path);
    let key = uuid::Uuid::new_v4().to_string();
    // Deliberately leave a script-owned transaction open: the edit completes,
    // but a durable save cannot acquire the program lock.
    let error = client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
public class PreventAutoSave extends GhidraScript {
    public void run() throws Exception {
        var options = currentProgram.getOptions("AutoSaveTest");
        String key = getScriptArgs()[0];
        options.setInt(key, options.getInt(key, 0) + 1);
        println(Integer.toString(currentProgram.startTransaction("deliberately left open")));
    }
}
"#,
            std::slice::from_ref(&key),
            &[],
            false,
        )
        .unwrap_err();
    let detail = &error
        .downcast_ref::<ghidra_cli::ipc::protocol::BridgeCommandError>()
        .unwrap()
        .detail;
    assert_eq!(detail["save_failed"], true);
    assert_eq!(detail["saved"], false);
    assert_eq!(detail["command_response"]["status"], "success");
    let status = client.status().unwrap();
    let job_id = status["recent_jobs"][0]["id"].as_str().unwrap();
    let recovered = client.job_result(job_id).unwrap();
    assert_eq!(recovered["state"], "failed");
    assert_eq!(&recovered["response"]["detail"], detail);
    let transaction = detail["command_response"]["data"]["stdout"]
        .as_str()
        .unwrap()
        .trim()
        .to_owned();
    let failed_switch = targeted
        .send_command(
            "rename_function",
            Some(json!({"old_name": function.address, "new_name": "must_not_run_after_failed_switch"})),
        )
        .unwrap_err();
    let switch_detail = &failed_switch
        .downcast_ref::<BridgeCommandError>()
        .unwrap()
        .detail;
    assert_eq!(switch_detail["save_failed"], true, "{switch_detail}");
    assert_eq!(switch_detail["saved"], false);
    assert_eq!(switch_detail["program"], original_path);
    assert_eq!(
        client.bridge_info().unwrap()["current_program_path"],
        original_path
    );
    let project_path = std::path::Path::new(test_project());
    let pid = ghidra_cli::ghidra::bridge::read_pid_file(project_path).unwrap();
    for args in [
        vec!["bridge", "stop", "--project", test_project()],
        vec!["bridge", "restart", "--project", test_project()],
        vec!["project", "delete", test_project()],
    ] {
        let output = common::run_command_with_output(
            std::process::Command::new(assert_cmd::cargo::cargo_bin!("ghidra-cli"))
                .args(&args)
                .arg("--json"),
            std::time::Duration::from_secs(30),
        )
        .unwrap();
        assert!(!output.status.success(), "{args:?}: {output:?}");
        let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(error["detail"]["save_failed"], true, "{error}");
        assert_eq!(error["detail"]["stage"], "bridge.shutdown_save");
        assert_eq!(
            ghidra_cli::ghidra::bridge::read_pid_file(project_path).unwrap(),
            pid
        );
        assert!(
            client.ping().unwrap(),
            "failed shutdown must retain the listener"
        );
        assert_eq!(
            client.bridge_info().unwrap()["current_program"],
            TEST_PROGRAM
        );
        assert!(project_path.with_added_extension("gpr").is_file());
        assert!(project_path.with_added_extension("rep").is_dir());
    }
    assert!(client.program_save().is_err());
    assert!(client.program_close().is_err());
    let deletion = client.program_delete(TEST_PROGRAM).unwrap_err();
    assert_eq!(
        deletion
            .downcast_ref::<ghidra_cli::ipc::protocol::BridgeCommandError>()
            .unwrap()
            .detail["save_failed"],
        true
    );
    assert_eq!(client.bridge_info().unwrap()["has_current_program"], true);

    let batch = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(batch.path(), "program save\nprogram info\n").unwrap();
    let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .args(["--json", "batch"])
        .arg(batch.path())
        .args(["--project", test_project()])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let batch_error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(batch_error["detail"]["save_failed"], true);
    assert_eq!(batch_error["detail"]["not_executed"], 1);
    assert!(batch_error["detail"].get("results").is_none());
    let report: serde_json::Value = crate::json_output::from_slice(&output.stdout).unwrap();
    assert_eq!(report["save_failed"], true);
    assert_eq!(report["not_executed"], 1);
    assert_eq!(
        report["results"][0]["detail"]["command_response"]["status"],
        "success"
    );

    let repaired = client.script_run_source(r#"
import ghidra.app.script.GhidraScript;
public class AllowAutoSave extends GhidraScript {
    public void run() throws Exception {
        currentProgram.endTransaction(Integer.parseInt(getScriptArgs()[0]), true);
        println("edit-count:" + currentProgram.getOptions("AutoSaveTest").getInt(getScriptArgs()[1], 0));
    }
}
"#, &[transaction, key.clone()], &[], false).unwrap();
    assert!(repaired["stdout"]
        .as_str()
        .unwrap()
        .contains("edit-count:1"));
    assert_eq!(client.program_save().unwrap()["saved"], true);
    assert!(client.ping().unwrap());
    for reader in [&client, &targeted] {
        let unchanged = reader
            .send_command("get_function", Some(json!({"address": function.address})))
            .unwrap();
        assert_eq!(unchanged["name"], function.name, "{unchanged}");
    }
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&target_path).unwrap();
    drop(harness);
    let restarted = start_daemon();
    let saved = restarted.client().unwrap().script_run_source(r#"
import ghidra.app.script.GhidraScript;
public class CheckRecoveredShutdownEdit extends GhidraScript {
    public void run() throws Exception {
        println("edit-count:" + currentProgram.getOptions("AutoSaveTest").getInt(getScriptArgs()[0], 0));
    }
}
"#, &[key], &[], false).unwrap();
    assert!(
        saved["stdout"].as_str().unwrap().contains("edit-count:1"),
        "{saved}"
    );
}
