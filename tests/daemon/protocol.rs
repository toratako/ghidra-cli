use super::{start_daemon, TEST_PROGRAM};
use crate::common::{ensure_test_project, get_function_address, test_project};
use serde_json::json;
use serial_test::serial;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::time::Duration;

#[test]
#[serial]
fn incomplete_or_invalid_utf8_frames_cannot_admit_or_retarget_mutations() {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    let client = harness.client().unwrap();
    // A replacement decoder would turn the invalid byte into this existing name.
    let name = format!("wire-\u{fffd}-{}", uuid::Uuid::new_v4());
    client
        .send_command("tag_create", Some(json!({"name": name})))
        .unwrap();
    let before = client.tag_get(&name).unwrap();

    for frame in ["eof", "bare-cr", "invalid-utf8"] {
        let id = uuid::Uuid::new_v4().to_string();
        let mut wire = json!({"command": "tag_delete", "job_id": id, "args": {"name": name}})
            .to_string()
            .into_bytes();
        match frame {
            "eof" => {}
            "bare-cr" => wire.push(b'\r'),
            "invalid-utf8" => {
                let replacement = wire
                    .windows(3)
                    .position(|bytes| bytes == [0xef, 0xbf, 0xbd])
                    .unwrap();
                wire.splice(replacement..replacement + 3, [0xff]);
                wire.push(b'\n');
            }
            _ => unreachable!(),
        }
        let mut socket = TcpStream::connect(("127.0.0.1", harness.port())).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket.write_all(&wire).unwrap();
        if frame != "invalid-utf8" {
            socket.shutdown(Shutdown::Write).unwrap();
        }
        let mut response = Vec::new();
        if let Err(error) = socket.read_to_end(&mut response) {
            assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
        }
        assert_eq!(
            client.job_status(Some(&id)).unwrap()["found"],
            false,
            "{frame} admitted a mutation: {}",
            String::from_utf8_lossy(&response)
        );
        assert_eq!(
            client.tag_get(&name).unwrap(),
            before,
            "{frame} changed the target"
        );
    }
    client.program_close().unwrap();
    client.open_program(TEST_PROGRAM).unwrap();
    assert_eq!(client.tag_get(&name).unwrap(), before);
    client
        .send_command("tag_delete", Some(json!({"name": name})))
        .unwrap();
}

#[test]
#[serial]
fn fragmented_utf8_request_waits_for_lf_and_persists_its_mutation() {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    let client = harness.client().unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    let name = format!("wire-日本語-😀-{}", uuid::Uuid::new_v4());
    let wire = json!({"command": "tag_create", "job_id": id, "args": {"name": name}})
        .to_string()
        .into_bytes();
    let mut socket = TcpStream::connect(("127.0.0.1", harness.port())).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    for byte in &wire {
        socket.write_all(&[*byte]).unwrap();
    }
    assert_eq!(client.job_status(Some(&id)).unwrap()["found"], false);
    socket.write_all(b"\n").unwrap();
    let mut response = String::new();
    BufReader::new(socket).read_line(&mut response).unwrap();
    let response: serde_json::Value = serde_json::from_str(&response).unwrap();
    assert_eq!(response["status"], "success", "{response}");
    assert_eq!(response["job_id"], id);
    let saved = client.tag_get(&name).unwrap();
    client.program_close().unwrap();
    client.open_program(TEST_PROGRAM).unwrap();
    assert_eq!(client.tag_get(&name).unwrap(), saved);
    client
        .send_command("tag_delete", Some(json!({"name": name})))
        .unwrap();
}

#[test]
#[serial]
fn native_failure_without_message_preserves_rollback_and_retained_error() {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    harness
        .client()
        .unwrap()
        .script_run_source(
            include_str!("../fixtures/runtime/CheckNullMessageFailure.java"),
            &[],
            &[],
            false,
        )
        .unwrap();
}

#[test]
#[serial]
fn failed_admission_releases_socket_without_closing_pending_replies() {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    harness
        .client()
        .unwrap()
        .script_run_source(
            include_str!("../fixtures/runtime/CheckAdmissionSocketOwnership.java"),
            &[],
            &[],
            false,
        )
        .unwrap();
}

#[test]
#[serial]
fn malformed_mutation_arguments_preserve_saved_tags() {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    let client = harness.client().unwrap();
    let address = get_function_address(&harness, test_project(), TEST_PROGRAM, "main");
    let name = format!("protocol-{}", uuid::Uuid::new_v4());
    client
        .send_command("tag_create", Some(json!({"name": name})))
        .unwrap();
    client
        .send_command(
            "tag_attach",
            Some(json!({"function": address, "tags": [name]})),
        )
        .unwrap();
    let before = client.tag_list(None, Some(&address)).unwrap();

    // Gson coerces singleton containers, and the old array helper silently
    // discarded a scalar. None may broaden or retarget a destructive request.
    for (command, args, diagnostic) in [
        (
            "tag_delete",
            json!({"name": [name]}),
            "name must be a string",
        ),
        (
            "tag_detach",
            json!({"function": address, "all": [true]}),
            "all must be a boolean",
        ),
        (
            "tag_detach",
            json!({"function": address, "tags": [[name]]}),
            "tags must be an array of strings",
        ),
        (
            "tag_detach",
            json!({"function": address, "tags": name, "all": true}),
            "tags must be an array of strings",
        ),
    ] {
        let error = client.send_command(command, Some(args)).unwrap_err();
        assert!(error.to_string().contains(diagnostic), "{error:#}");
        assert_eq!(client.tag_list(None, Some(&address)).unwrap(), before);
    }

    client.program_close().unwrap();
    client.open_program(TEST_PROGRAM).unwrap();
    assert_eq!(client.tag_list(None, Some(&address)).unwrap(), before);
    client
        .send_command("tag_delete", Some(json!({"name": name})))
        .unwrap();
}
