use super::{start_daemon, TEST_PROGRAM};
use crate::common::{ensure_test_project, test_project};
use ghidra_cli::ipc::{client::BridgeClient, protocol::BridgeCommandError};
use serde_json::{json, Value};
use serial_test::serial;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

fn send_without_reading(port: u16, request: &Value) {
    let mut socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
    writeln!(socket, "{request}").unwrap();
}

fn completed(client: &BridgeClient, id: &str) -> Value {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let status = client.job_status(Some(id)).unwrap();
        if status["job"]["finished_at_ms"].is_number() {
            return status["job"].clone();
        }
        assert!(Instant::now() < deadline, "Job did not finish: {status}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
#[serial]
fn disconnected_edits_retain_results_and_errors_without_reexecution() {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    let client = harness.client().unwrap();
    let address = crate::common::helpers::get_fixture_function(&client, "add_numbers").address;
    let id = uuid::Uuid::new_v4().to_string();
    let request = json!({"command": "comment_set", "job_id": id,
        "args": {"address": address, "text": "recovered edit", "comment_type": "EOL"}});
    send_without_reading(harness.port(), &request);
    assert_eq!(completed(&client, &id)["state"], "complete");
    let result = client.job_result(&id).unwrap();
    assert_eq!(result["id"], id);
    assert_eq!(result["command"], "comment_set");
    assert_eq!(result["result"]["state"], "available");
    assert_eq!(result["response"]["status"], "success");
    assert_eq!(result["response"]["job_id"], id);

    // Retrieving an old response must not replay its mutation or inspect current state.
    client
        .comment_set(&address, "later edit", Some("EOL"))
        .unwrap();
    assert_eq!(client.job_result(&id).unwrap(), result);
    let mut duplicate = TcpStream::connect(("127.0.0.1", harness.port())).unwrap();
    duplicate
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    writeln!(duplicate, "{request}").unwrap();
    let mut line = String::new();
    BufReader::new(duplicate).read_line(&mut line).unwrap();
    let rejection: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(rejection["status"], "error");
    assert!(rejection["message"]
        .as_str()
        .unwrap()
        .contains("already exists"));
    assert!(client.comment_get(&address).unwrap()["comments"]
        .as_array()
        .unwrap()
        .iter()
        .any(|comment| comment["text"] == "later edit"));
    assert_eq!(client.job_result(&id).unwrap(), result);

    let failed_id = uuid::Uuid::new_v4().to_string();
    send_without_reading(
        harness.port(),
        &json!({"command": "comment_set", "job_id": failed_id,
        "args": {"address": address, "text": "must not land", "comment_type": "invalid"}}),
    );
    assert_eq!(completed(&client, &failed_id)["state"], "failed");
    let failure = client.job_result(&failed_id).unwrap();
    assert_eq!(failure["response"]["status"], "error");
    assert_eq!(failure["response"]["detail"]["rolled_back"], true);
    assert!(failure["response"]["message"]
        .as_str()
        .unwrap()
        .contains("Invalid comment type"));
    let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .args([
            "--json",
            "--project",
            test_project(),
            "job",
            "result",
            &failed_id,
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "A failed operation's result is still retrievable: {output:?}"
    );
    assert!(output.stderr.is_empty());
    assert_eq!(
        crate::json_output::from_slice::<Value>(&output.stdout).unwrap(),
        failure
    );

    drop(harness);
    let restarted = start_daemon();
    let error = restarted.client().unwrap().job_result(&id).unwrap_err();
    assert_eq!(
        error.downcast_ref::<BridgeCommandError>().unwrap().detail["result_state"],
        "unknown"
    );
}

#[test]
#[serial]
fn queued_result_is_pending_and_cancelled_response_can_be_recovered() {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    let client = harness.client().unwrap();
    let worker = harness.client().unwrap();
    let script = std::thread::spawn(move || {
        worker.script_run_source(
            include_str!("../fixtures/daemon/HoldJobResults.java"),
            &[],
            &[],
            false,
        )
    });
    let deadline = Instant::now() + Duration::from_secs(25);
    let active_id = loop {
        let status = client.status().unwrap();
        if status["active_job"]["progress_message"] == "holding-for-result-recovery" {
            break status["active_job"]["id"].as_str().unwrap().to_owned();
        }
        assert!(!script.is_finished());
        assert!(Instant::now() < deadline, "{status}");
        std::thread::sleep(Duration::from_millis(10));
    };
    let id = uuid::Uuid::new_v4().to_string();
    send_without_reading(harness.port(), &json!({"command": "stats", "job_id": id}));
    loop {
        if client.job_status(Some(&id)).unwrap()["found"] == true {
            break;
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .args(["--json", "--project", test_project(), "job", "result", &id])
        .timeout(Duration::from_secs(5))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(75));
    assert!(output.stdout.is_empty());
    let error: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["status"], "pending");
    assert_eq!(error["detail"]["result_state"], "pending");
    assert_eq!(error["detail"]["job"]["state"], "queued");
    assert!(error["detail"].get("outcome_unknown").is_none());
    client.cancel_job(Some(&id)).unwrap();
    let cancelled = client.job_result(&id).unwrap();
    assert_eq!(cancelled["state"], "cancelled");
    assert_eq!(
        cancelled["response"]["message"],
        "Cancelled before execution"
    );
    assert!(client.ping().unwrap());
    client.cancel_job(Some(&active_id)).unwrap();
    let error = script.join().unwrap().unwrap_err();
    let active = client.job_result(&active_id).unwrap();
    assert_eq!(active["response"]["message"], error.to_string());
    if let Some(error) = error.downcast_ref::<BridgeCommandError>() {
        assert_eq!(active["response"]["detail"], error.detail);
    }
    assert_eq!(active["state"], "cancelled");
}

#[test]
#[serial]
fn result_store_bounds_utf8_bytes_expiry_and_eviction_without_real_time_waits() {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    harness
        .client()
        .unwrap()
        .script_run_source(
            include_str!("../fixtures/daemon/CheckJobResultStore.java"),
            &[],
            &[],
            false,
        )
        .unwrap();
}

#[test]
#[serial]
fn deferred_result_reads_do_not_occupy_control_connection_threads() {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    harness
        .client()
        .unwrap()
        .script_run_source(
            include_str!("../fixtures/daemon/CheckResultResponsePool.java"),
            &[],
            &[],
            false,
        )
        .unwrap();
}
