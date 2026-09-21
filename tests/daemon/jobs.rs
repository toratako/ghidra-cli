use super::{start_daemon, TEST_PROGRAM};
use crate::common::{ensure_test_project, test_project};
use serial_test::serial;
use std::time::Duration;

fn job_command(args: &[&str]) -> serde_json::Value {
    let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .args(["--json", "--project", test_project(), "job"])
        .args(args)
        .timeout(Duration::from_secs(30))
        .output()
        .unwrap();
    assert!(output.status.success(), "{args:?}: {output:?}");
    assert!(output.stderr.is_empty(), "{args:?}: {output:?}");
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
#[serial]
fn test_bridge_job_status_is_available_when_idle() {
    require_ghidra!();

    ensure_test_project(test_project(), TEST_PROGRAM);

    let _harness = start_daemon();

    let status = job_command(&["list"]);
    assert_eq!(
        status.get("bridge_state").and_then(|v| v.as_str()),
        Some("running")
    );
    assert_eq!(status.get("queue_depth").and_then(|v| v.as_u64()), Some(0));
    assert!(status.get("active_job").is_some_and(|v| v.is_null()));

    let missing = job_command(&["get", &u64::MAX.to_string()]);
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
        std::thread::spawn(move || ghidra_cli::ipc::client::BridgeClient::new(port).analysis_run());

    let control = harness.client().expect("control client");
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let active_job_id = loop {
        let status = control.status().expect("status while analysis runs");
        if let Some(active) = status.get("active_job").filter(|v| !v.is_null()) {
            if active.get("command").and_then(|v| v.as_str()) == Some("analysis_run") {
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
        Some("analysis_run")
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
fn test_active_script_cancel_does_not_cancel_next_job() {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    let client = harness.client().unwrap();
    let worker = harness.client().unwrap();
    let function = crate::common::helpers::get_fixture_function(&client, "add_numbers");
    let address = function.address;
    let marker = format!("cancelled-script-edit-{}", uuid::Uuid::new_v4());
    let script_args = vec![address.clone(), marker.clone()];
    let script = std::thread::spawn(move || {
        worker.script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
public class WaitForBridgeCancel extends GhidraScript {
    public void run() throws Exception {
        setEOLComment(toAddr(getScriptArgs()[0]), getScriptArgs()[1]);
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
            &script_args,
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
    let cancelled = job_command(&["cancel"]);
    assert_eq!(cancelled["job_id"], id);
    let error = script.join().unwrap().unwrap_err();
    assert!(error.to_string().contains("Script cancelled"));
    let detail = &error
        .downcast_ref::<ghidra_cli::ipc::protocol::BridgeCommandError>()
        .unwrap()
        .detail;
    assert_eq!(detail["partial_changes_saved"], true);
    assert!(detail.get("rolled_back").is_none());
    assert_eq!(
        job_command(&["get", &id.to_string()])["job"]["state"],
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
    let status = client.status().unwrap();
    assert!(status["active_job"].is_null(), "{status}");
    let finished = &status["recent_jobs"][0];
    assert_eq!(finished["state"], "complete");
    let finished_id = finished["id"].as_u64().unwrap();
    let cancelled = job_command(&["cancel", &finished_id.to_string()]);
    assert_eq!(cancelled["state"], "complete");
    let unchanged = client.job_status(Some(finished_id)).unwrap();
    assert_eq!(unchanged["job"]["state"], "complete");
    assert_eq!(unchanged["job"]["cancel_requested"], false);
    drop(harness);
    let restarted = start_daemon();
    let comments = restarted.client().unwrap().comment_get(&address).unwrap();
    assert!(comments["comments"]
        .as_array()
        .unwrap()
        .iter()
        .any(|comment| comment["text"] == marker));
}

#[test]
#[serial]
fn test_shutdown_wait_drains_full_queue_before_reply() {
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpStream;

    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    let control = harness.client().unwrap();
    let worker = harness.client().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let release = directory.path().join("release");
    let script_release = release.to_str().unwrap().to_owned();
    let script = std::thread::spawn(move || {
        worker.script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
public class HoldQueueForShutdown extends GhidraScript {
    public void run() throws Exception {
        java.io.File release = new java.io.File(getScriptArgs()[0]);
        monitor.setMessage("holding-queue-for-shutdown");
        long deadline = System.currentTimeMillis() + 60000;
        while (!release.exists()) {
            if (System.currentTimeMillis() > deadline) {
                throw new IllegalStateException("Queue was not released");
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
    let deadline = std::time::Instant::now() + Duration::from_secs(45);
    loop {
        let status = control.status().unwrap();
        if status["active_job"]["progress_message"] == "holding-queue-for-shutdown" {
            break;
        }
        assert!(
            !script.is_finished(),
            "script exited before queue saturation"
        );
        assert!(std::time::Instant::now() < deadline, "{status}");
        std::thread::sleep(Duration::from_millis(20));
    }

    // Enqueue one at a time and observe acceptance to avoid saturating the
    // socket accept backlog instead of the program queue.
    let mut pending = Vec::new();
    for depth in 1..=256 {
        let mut socket = TcpStream::connect(("127.0.0.1", harness.port())).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        writeln!(socket, "{{\"command\":\"stats\"}}").unwrap();
        pending.push(socket);
        loop {
            let status = control.status().unwrap();
            if status["queue_depth"] == depth {
                break;
            }
            assert!(std::time::Instant::now() < deadline, "{status}");
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    let overflow = control.stats().unwrap_err();
    assert!(overflow.to_string().contains("queue is full"));
    // Shutdown must bypass the full queue, while its response waits for draining.
    let mut receipt = TcpStream::connect(("127.0.0.1", harness.port())).unwrap();
    writeln!(receipt, "{{\"command\":\"shutdown_wait\"}}").unwrap();
    receipt
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let mut receipt = BufReader::new(receipt);
    let mut response = String::new();
    let waiting = receipt.read_line(&mut response);
    let draining = control.status();
    std::fs::write(&release, b"release").unwrap();
    script.join().unwrap().unwrap();
    assert!(
        matches!(waiting, Err(ref error) if matches!(error.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock)),
        "shutdown_wait replied before draining: {waiting:?}, {response}"
    );
    assert_eq!(draining.unwrap()["bridge_state"], "draining");
    for socket in pending {
        let mut line = String::new();
        BufReader::new(socket).read_line(&mut line).unwrap();
        let response: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(response["status"], "success", "{response}");
    }
    receipt
        .get_ref()
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    receipt.read_line(&mut response).unwrap();
    let response: serde_json::Value = serde_json::from_str(&response).unwrap();
    assert_eq!(response["status"], "shutdown", "{response}");
}
