use super::{start_daemon, TEST_PROGRAM};
use crate::common::{ensure_test_project, test_project};
use serial_test::serial;
use std::time::Duration;

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
