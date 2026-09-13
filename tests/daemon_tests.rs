//! Tests for daemon lifecycle commands.

use predicates::prelude::*;
use serial_test::serial;
use std::time::Duration;

#[macro_use]
mod common;
use common::{ensure_test_project, DaemonTestHarness};

use common::test_project;
const TEST_PROGRAM: &str = common::FIXTURE_PROGRAM;

/// Start the bridge; missing programs and startup failures must fail the test.
fn start_daemon() -> DaemonTestHarness {
    DaemonTestHarness::new(test_project(), TEST_PROGRAM)
        .unwrap_or_else(|e| panic!("Failed to start bridge: {e}"))
}

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
fn test_analyzer_enable_disable_in_bridge() {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    let client = harness.client().expect("bridge client");
    let listing = client.analyzer_list().expect("list analyzers");
    let analyzer = listing["analyzers"]
        .as_array()
        .expect("analyzer array")
        .first()
        .expect("fixture must have analyzers");
    let name = analyzer["name"].as_str().expect("analyzer name");
    let original = analyzer["enabled"].as_bool().expect("enabled flag");

    // Exercise both explicit values and verify actual Ghidra state, not only
    // the command's response. End with the original setting restored.
    for enabled in [!original, original] {
        assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
            .args([
                "analyzer",
                "set",
                name,
                if enabled { "true" } else { "false" },
            ])
            .args(["--project", test_project(), "--program", TEST_PROGRAM])
            .assert()
            .success();
        let updated = client.analyzer_list().expect("list updated analyzers");
        let actual = updated["analyzers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["name"].as_str() == Some(name))
            .expect("analyzer still exists");
        assert_eq!(actual["enabled"].as_bool(), Some(enabled));
    }
}

#[test]
#[serial]
fn test_daemon_start() {
    require_ghidra!();

    ensure_test_project(test_project(), TEST_PROGRAM);

    let harness = start_daemon();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("status")
        .arg("--project")
        .arg(test_project())
        .assert()
        .success();

    drop(harness);
}

#[test]
#[serial]
fn test_daemon_status() {
    require_ghidra!();

    ensure_test_project(test_project(), TEST_PROGRAM);

    let harness = start_daemon();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("status")
        .arg("--project")
        .arg(test_project())
        .assert()
        .success()
        .stdout(predicate::str::contains("running"));

    drop(harness);
}

#[test]
#[serial]
fn test_daemon_ping() {
    require_ghidra!();

    ensure_test_project(test_project(), TEST_PROGRAM);

    let harness = start_daemon();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("ping")
        .arg("--project")
        .arg(test_project())
        .assert()
        .success();

    drop(harness);
}

#[test]
#[serial]
fn test_daemon_lifecycle() {
    require_ghidra!();

    ensure_test_project(test_project(), TEST_PROGRAM);

    let _harness = start_daemon();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("status")
        .arg("--project")
        .arg(test_project())
        .assert()
        .success()
        .stdout(predicate::str::contains("running"));

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("ping")
        .arg("--project")
        .arg(test_project())
        .assert()
        .success();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("stop")
        .arg("--project")
        .arg(test_project())
        .assert()
        .success();
}

#[test]
#[serial]
fn test_daemon_stop() {
    require_ghidra!();

    ensure_test_project(test_project(), TEST_PROGRAM);

    let harness = start_daemon();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("stop")
        .arg("--project")
        .arg(test_project())
        .assert()
        .success();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("status")
        .arg("--project")
        .arg(test_project())
        .assert()
        .success()
        .stdout(predicate::str::contains("No bridge running"));

    drop(harness);
}

#[test]
#[serial]
fn test_daemon_restart() {
    require_ghidra!();

    ensure_test_project(test_project(), TEST_PROGRAM);

    let harness = start_daemon();

    // Use run_cli_with_timeout to avoid Windows pipe handle inheritance.
    // `ghidra-cli restart` stops the old bridge and starts a new JVM. With piped
    // stdout/stderr, the new JVM inherits pipe handles, blocking forever.
    let ghidra_bin = assert_cmd::cargo::cargo_bin!("ghidra-cli");
    let status = common::run_cli_with_timeout(
        ghidra_bin,
        &[
            "restart",
            "--project",
            test_project(),
            "--program",
            TEST_PROGRAM,
        ],
        std::time::Duration::from_secs(300),
    )
    .expect("Failed to run restart");

    assert!(status.success(), "Restart failed with status: {status}");

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("stop")
        .arg("--project")
        .arg(test_project())
        .assert()
        .success();

    drop(harness);
}

#[test]
#[serial]
fn test_daemon_start_when_running() {
    require_ghidra!();

    ensure_test_project(test_project(), TEST_PROGRAM);

    let harness = start_daemon();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("start")
        .arg("--project")
        .arg(test_project())
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success()
        .stdout(predicate::str::contains("already running"));

    drop(harness);
}

#[test]
#[serial]
fn test_bridge_job_status_is_available_when_idle() {
    require_ghidra!();

    ensure_test_project(test_project(), TEST_PROGRAM);

    let harness = start_daemon();
    let client = harness.client().expect("bridge client");

    let status = client.status().expect("bridge status");
    assert_eq!(
        status.get("bridge_state").and_then(|v| v.as_str()),
        Some("running")
    );
    assert_eq!(status.get("queue_depth").and_then(|v| v.as_u64()), Some(0));
    assert!(status.get("active_job").is_some_and(|v| v.is_null()));

    let missing = client
        .job_status(Some(u64::MAX))
        .expect("missing job status");
    assert_eq!(missing.get("found").and_then(|v| v.as_bool()), Some(false));
}

#[test]
#[serial]
fn test_control_plane_stays_responsive_while_program_job_runs() {
    require_ghidra!();

    ensure_test_project(test_project(), TEST_PROGRAM);

    let harness = start_daemon();
    let port = harness.port();

    let analysis =
        std::thread::spawn(move || ghidra_cli::ipc::client::BridgeClient::new(port).analyze());

    let control = harness.client().expect("control client");
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let active_job_id = loop {
        let status = control.status().expect("status while analysis runs");
        if let Some(active) = status.get("active_job").filter(|v| !v.is_null()) {
            if active.get("command").and_then(|v| v.as_str()) == Some("analyze") {
                break active
                    .get("id")
                    .and_then(|v| v.as_u64())
                    .expect("active job id");
            }
        }
        assert!(
            !analysis.is_finished(),
            "analysis completed before its active job was observable"
        );
        assert!(
            std::time::Instant::now() < deadline,
            "analysis never appeared as the active bridge job"
        );
        std::thread::sleep(Duration::from_millis(20));
    };

    let ping_started = std::time::Instant::now();
    assert!(control.ping().expect("ping while analysis runs"));
    assert!(
        ping_started.elapsed() < Duration::from_secs(2),
        "control-plane ping waited behind the active program job"
    );

    let active = control
        .job_status(Some(active_job_id))
        .expect("active job status");
    assert_eq!(active.get("found").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(
        active
            .get("job")
            .and_then(|v| v.get("command"))
            .and_then(|v| v.as_str()),
        Some("analyze")
    );

    // Queue more program operations than the old connection pool's four core
    // threads. A ping after all eight are visible proves control handling does
    // not depend on a spare job-waiting connection thread.
    let queued: Vec<_> = (0..8)
        .map(|_| {
            let queued_port = harness.port();
            std::thread::spawn(move || {
                ghidra_cli::ipc::client::BridgeClient::new(queued_port).stats()
            })
        })
        .collect();

    let queued_deadline = std::time::Instant::now() + Duration::from_secs(10);
    let queued_job_ids = loop {
        let status = control.status().expect("status with queued job");
        let ids: Vec<u64> = status
            .get("queued_jobs")
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
            .filter(|job| job.get("command").and_then(|v| v.as_str()) == Some("stats"))
            .filter_map(|job| job.get("id").and_then(|v| v.as_u64()))
            .collect();
        if ids.len() == queued.len() {
            break ids;
        }
        assert!(
            queued.iter().all(|thread| !thread.is_finished()),
            "a queued stats job ran before the saturated queue was observable"
        );
        assert!(
            std::time::Instant::now() < queued_deadline,
            "stats job never appeared in the bridge queue"
        );
        std::thread::sleep(Duration::from_millis(20));
    };

    let saturated_ping_started = std::time::Instant::now();
    assert!(control.ping().expect("ping with eight queued jobs"));
    assert!(
        saturated_ping_started.elapsed() < Duration::from_secs(2),
        "control-plane ping was starved by program clients waiting for results"
    );

    for queued_job_id in queued_job_ids {
        let cancelled = control
            .cancel_job(Some(queued_job_id))
            .expect("cancel queued job");
        assert_eq!(
            cancelled.get("state").and_then(|v| v.as_str()),
            Some("cancelled")
        );
    }

    for queued_thread in queued {
        let queued_result = queued_thread.join().expect("queued client thread");
        assert!(
            queued_result.is_err(),
            "cancelled queued job unexpectedly ran"
        );
    }

    analysis
        .join()
        .expect("analysis client thread")
        .expect("analysis job should complete");
}

#[test]
#[serial]
fn test_failed_mutation_preserves_prior_edits_after_restart() {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    let client = harness.client().unwrap();
    let function = client
        .send_command(
            "get_function",
            Some(serde_json::json!({"address": "add_numbers"})),
        )
        .unwrap();
    let address = function["address"].as_str().expect("function address");
    let text = format!("persist-before-failure-{}", uuid::Uuid::new_v4());
    client.comment_set(address, &text, Some("EOL")).unwrap();
    assert_saved_comment(&client, address, &text);

    // The address parses, but is outside every memory block. This fails inside
    // patch_bytes' transaction, after the earlier comment has succeeded.
    let error = client
        .send_command(
            "patch_bytes",
            Some(serde_json::json!({"address": "0", "hex": "00"})),
        )
        .unwrap_err();
    assert!(
        error.to_string().contains("Failed to patch bytes"),
        "{error}"
    );
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
fn test_active_script_cancel_does_not_cancel_next_job() {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    let client = harness.client().unwrap();
    let worker = harness.client().unwrap();
    let script = std::thread::spawn(move || {
        worker.script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
public class WaitForBridgeCancel extends GhidraScript {
    public void run() throws Exception {
        monitor.setMessage("waiting-for-bridge-cancel");
        long deadline = System.currentTimeMillis() + 30000;
        while (!monitor.isCancelled() && System.currentTimeMillis() < deadline) {
            Thread.sleep(10);
        }
        monitor.checkCancelled();
        throw new IllegalStateException("Cancellation never arrived");
    }
}
"#,
            &[],
            &[],
            false,
        )
    });

    let deadline = std::time::Instant::now() + Duration::from_secs(25);
    let id = loop {
        let status = client.status().unwrap();
        let active = &status["active_job"];
        if active["progress_message"] == "waiting-for-bridge-cancel" {
            break active["id"].as_u64().unwrap();
        }
        assert!(!script.is_finished(), "script exited before cancellation");
        assert!(
            std::time::Instant::now() < deadline,
            "script never became cancellable: {status}"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    client.cancel_job(Some(id)).unwrap();
    assert!(script
        .join()
        .unwrap()
        .unwrap_err()
        .to_string()
        .contains("Script cancelled"));
    assert_eq!(
        client.job_status(Some(id)).unwrap()["job"]["state"],
        "cancelled"
    );

    let next = client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
public class CheckFreshBridgeMonitor extends GhidraScript {
    public void run() throws Exception {
        monitor.checkCancelled();
        println("fresh-monitor:" + currentProgram.getName());
    }
}
"#,
            &[],
            &[],
            false,
        )
        .unwrap();
    assert!(next["stdout"]
        .as_str()
        .unwrap()
        .contains(&format!("fresh-monitor:{TEST_PROGRAM}")));
}

#[test]
#[serial]
fn test_handlers_follow_program_switch_and_close() {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    let client = harness.client().unwrap();
    let folder = format!("switch-{}", uuid::Uuid::new_v4());
    client.script_run_source(r#"
import ghidra.app.script.GhidraScript;
public class CopyBridgeProgram extends GhidraScript {
    public void run() throws Exception {
        var folder = state.getProject().getProjectData().getRootFolder().createFolder(getScriptArgs()[0]);
        currentProgram.getDomainFile().copyTo(folder, monitor).setName("alternate");
    }
}
"#, std::slice::from_ref(&folder), &[], false).unwrap();
    let alternate = format!("/{folder}/alternate");
    client.open_program(&alternate).unwrap();
    // Copying/renaming the project file retains the original internal Program
    // name. Switching back must compare project files, not that internal name.
    assert_eq!(client.program_info().unwrap()["name"], TEST_PROGRAM);
    let programs = client.send_command("list_programs", None).unwrap();
    assert!(programs["programs"]
        .as_array()
        .unwrap()
        .iter()
        .all(|program| program["current"] == false));
    let function = client
        .send_command(
            "get_function",
            Some(serde_json::json!({"address": "add_numbers"})),
        )
        .unwrap();
    let address = function["address"].as_str().unwrap();
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
    client
        .send_command(
            "analyze",
            Some(serde_json::json!({"program": TEST_PROGRAM})),
        )
        .unwrap();
    assert!(!client.comment_get(address).unwrap()["comments"]
        .as_array()
        .unwrap()
        .iter()
        .any(|comment| comment["text"] == marker));
    client.program_close().unwrap();
    assert!(client
        .comment_get(address)
        .unwrap_err()
        .to_string()
        .contains("No program loaded"));
    client.open_program(TEST_PROGRAM).unwrap();
    client.comment_get(address).unwrap();
}

#[test]
#[serial]
fn test_failed_script_saves_partial_changes() {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    let client = harness.client().unwrap();
    let function = client
        .send_command("get_function", Some(serde_json::json!({"address": "main"})))
        .unwrap();
    let address = function["address"].as_str().unwrap();
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
    assert_saved_comment(&client, address, &text);
}

#[test]
#[serial]
fn test_save_failure_preserves_program_and_does_not_replay_edit() {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    let client = harness.client().unwrap();
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
    let transaction = detail["command_response"]["data"]["stdout"]
        .as_str()
        .unwrap()
        .trim()
        .to_owned();
    assert!(client.program_save().is_err());
    assert!(client.program_close().is_err());
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
    assert!(output.stdout.is_empty());
    let batch_error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(batch_error["detail"]["save_failed"], true);
    assert_eq!(batch_error["detail"]["not_executed"], 1);
    assert_eq!(
        batch_error["detail"]["results"][0]["detail"]["command_response"]["status"],
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
"#, &[transaction, key], &[], false).unwrap();
    assert!(repaired["stdout"]
        .as_str()
        .unwrap()
        .contains("edit-count:1"));
    assert_eq!(client.program_save().unwrap()["saved"], true);
    assert!(client.ping().unwrap());
}

#[test]
#[serial]
fn management_results_are_single_json_documents() {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    for flag in ["--json", "--pretty"] {
        for command in ["start", "status", "ping", "jobs"] {
            let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
                .args([flag, "--quiet", command, "--project", test_project()])
                .output()
                .unwrap();
            assert!(output.status.success(), "{command}: {output:?}");
            let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert!(value.is_object(), "{command}: {value}");
            assert!(output.stderr.is_empty(), "{command}: {output:?}");
            if command == "status" {
                assert_eq!(value["state"], "running");
                assert!(value["port"].is_number());
                assert!(value["info"].is_object());
            }
        }
    }
    let function = harness
        .client()
        .unwrap()
        .send_command(
            "get_function",
            Some(serde_json::json!({"address": "add_numbers"})),
        )
        .unwrap();
    let address = function["address"].as_str().unwrap();
    for flag in ["--json", "--pretty"] {
        let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
            .args([
                flag,
                "function",
                "create",
                address,
                "--project",
                test_project(),
            ])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        assert!(output.stdout.is_empty(), "{output:?}");
        let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
        assert!(error["detail"].is_object(), "{error}");
    }
    let project_path = ghidra_cli::config::Config::load()
        .unwrap()
        .get_project_dir()
        .unwrap()
        .join(test_project());
    let initial_pid = ghidra_cli::ghidra::bridge::read_pid_file(&project_path)
        .unwrap()
        .unwrap();
    for args in [vec!["program", "save"], vec!["restart"], vec!["stop"]] {
        let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
            .args(["--json", "--quiet"])
            .args(&args)
            .args(["--project", test_project(), "--program", TEST_PROGRAM])
            .timeout(Duration::from_secs(300))
            .output()
            .unwrap();
        assert!(output.status.success(), "{args:?}: {output:?}");
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        if args == ["program", "save"] {
            assert_eq!(value["saved"], true);
            assert_eq!(
                ghidra_cli::ghidra::bridge::read_pid_file(&project_path).unwrap(),
                Some(initial_pid),
                "program save restarted the bridge"
            );
        }
        assert!(output.stderr.is_empty(), "{output:?}");
    }
}

#[test]
#[serial]
fn test_batch_failure_exit_and_results() {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    let batch = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        batch.path(),
        "program info\nfunction create main\nprogram info\n",
    )
    .unwrap();
    let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .args(["--json", "batch"])
        .arg(batch.path())
        .args(["--project", test_project()])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(output.stdout.is_empty());
    let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["detail"]["commands_executed"], 3);
    assert_eq!(error["detail"]["failed"], 1);
    assert!(error["detail"]["results"][0]["result"]["function_count"].is_number());
    assert!(error["detail"]["results"][1]["detail"].is_object());
    assert!(error["detail"]["results"][2]["result"]["function_count"].is_number());
    std::fs::write(batch.path(), "program info\nprogram save\n").unwrap();
    let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .args(["--json", "batch"])
        .arg(batch.path())
        .args(["--project", test_project()])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result[0]["failed"], 0);
    assert_eq!(result[0]["results"][1]["result"]["saved"], true);
    assert!(harness.client().unwrap().ping().unwrap());
}
