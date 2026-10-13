use super::{parse_secs, BridgeClient};
use std::io::{BufRead, BufReader, Error, ErrorKind, Write};
use std::net::TcpListener;
use std::time::Duration;

fn exchange_response(
    command: &str,
    selection: &crate::ipc::client::ProgramSelection,
    response: impl FnOnce(&serde_json::Value) -> serde_json::Value + Send + 'static,
) -> (anyhow::Result<serde_json::Value>, serde_json::Value) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = BridgeClient::new(listener.local_addr().unwrap().port())
        .with_program("/previous")
        .with_selection(selection.clone());
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut line = String::new();
        BufReader::new(&stream).read_line(&mut line).unwrap();
        let request: serde_json::Value = serde_json::from_str(&line).unwrap();
        writeln!(stream, "{}", response(&request)).unwrap();
        (listener, request)
    });
    let result = client.send_command_with_timeout(command, None, Some(Duration::from_secs(2)));
    let (listener, request) = server.join().unwrap();
    listener.set_nonblocking(true).unwrap();
    assert_eq!(listener.accept().unwrap_err().kind(), ErrorKind::WouldBlock);
    (result, request)
}

#[test]
fn targeted_requests_track_executed_selection_but_controls_do_not_change_it() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let selection = crate::ipc::client::ProgramSelection::default();
    let client = BridgeClient::new(listener.local_addr().unwrap().port())
        .with_program("/requested")
        .with_selection(selection.clone());
    let server = std::thread::spawn(move || {
        for (command, status, selected) in [
            ("program_info", "success", serde_json::json!("/requested")),
            ("comment_set", "error", serde_json::json!("/requested")),
            ("program_close", "success", serde_json::Value::Null),
            ("bridge_info", "success", serde_json::json!("/another")),
        ] {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut line = String::new();
            BufReader::new(&stream).read_line(&mut line).unwrap();
            let request: serde_json::Value = serde_json::from_str(&line).unwrap();
            assert_eq!(request["command"], command);
            if command == "bridge_info" {
                assert!(request.get("program").is_none());
                assert!(request.get("job_id").is_none());
            } else {
                assert_eq!(request["program"], "/requested");
                assert!(request["job_id"].is_string());
            }
            writeln!(
                stream,
                "{}",
                serde_json::json!({
                    "status": status, "job_id": request["job_id"],
                    "selected_program": selected, "message": "operation failed", "data": {}
                })
            )
            .unwrap();
        }
    });
    assert_eq!(selection.observed(), None);
    client.program_info().unwrap();
    assert_eq!(selection.observed(), Some(Some("/requested".to_owned())));
    assert!(client.send_command("comment_set", None).is_err());
    assert_eq!(selection.observed(), Some(Some("/requested".to_owned())));
    client.program_close().unwrap();
    assert_eq!(selection.observed(), Some(None));
    client.bridge_info().unwrap();
    assert_eq!(selection.observed(), Some(None));
    server.join().unwrap();
}

#[test]
fn response_status_controls_success_and_failure() {
    for (status, data, expected) in [
        (
            "success",
            Some(serde_json::json!({"count": 1})),
            Some(serde_json::json!({"count": 1})),
        ),
        ("success", None, Some(serde_json::json!({}))),
        (
            "shutdown",
            None,
            Some(serde_json::json!({"status": "shutdown"})),
        ),
        ("error", None, None),
        ("unexpected", Some(serde_json::json!({"count": 1})), None),
        ("", None, None),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = BridgeClient::new(listener.local_addr().unwrap().port());
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = String::new();
            BufReader::new(&stream).read_line(&mut request).unwrap();
            let response = serde_json::json!({
                "status": status,
                "data": data,
                "message": "Request failed",
            });
            writeln!(stream, "{response}").unwrap();
        });
        let result = client.send_command_with_deadline(
            if status == "shutdown" {
                "shutdown_wait"
            } else {
                "ping"
            },
            None,
            Some(std::time::Instant::now() + Duration::from_secs(2)),
        );
        server.join().unwrap();
        match expected {
            Some(expected) => assert_eq!(result.unwrap(), expected),
            None => {
                let error = result.unwrap_err();
                let message = error.to_string();
                if status == "error" {
                    assert_eq!(message, "Request failed");
                } else {
                    assert!(error
                        .downcast_ref::<crate::ipc::protocol::BridgeOutcomeUnknownError>()
                        .is_some());
                    assert_eq!(
                        error.root_cause().to_string(),
                        format!("Invalid bridge response status: '{status}'")
                    );
                }
            }
        }
    }
}

#[test]
fn reply_reassembles_utf8_across_receive_buffers() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = BridgeClient::new(listener.local_addr().unwrap().port());
    let data = serde_json::json!({"text": "é".repeat(10_000)});
    let response = serde_json::json!({"status": "success", "data": data});
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut line = String::new();
        BufReader::new(&stream).read_line(&mut line).unwrap();
        writeln!(stream, "{response}").unwrap();
    });
    let result = client.send_command_with_timeout("ping", None, Some(Duration::from_secs(2)));
    server.join().unwrap();
    assert_eq!(result.unwrap(), data);
}

#[test]
fn request_deadline_bounds_a_trickling_response() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = BridgeClient::new(listener.local_addr().unwrap().port());
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut request = String::new();
        BufReader::new(&stream).read_line(&mut request).unwrap();
        assert!(request.contains("ping"));
        for _ in 0..30 {
            if stream.write_all(b" ").is_err() {
                break;
            }
            std::thread::sleep(Duration::from_millis(30));
        }
    });
    let started = std::time::Instant::now();
    let error = client
        .send_command_with_deadline("ping", None, Some(started + Duration::from_millis(150)))
        .unwrap_err();
    assert!(
        error
            .downcast_ref::<crate::ipc::protocol::BridgeTimeoutError>()
            .is_some(),
        "{error:#}"
    );
    assert!(started.elapsed() < Duration::from_millis(700));
    server.join().unwrap();
}

#[test]
fn request_deadline_bounds_connection_retries() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = BridgeClient::new(listener.local_addr().unwrap().port());
    drop(listener);
    let started = std::time::Instant::now();
    assert!(client
        .send_command_with_deadline("ping", None, Some(started + Duration::from_millis(100)))
        .is_err());
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[test]
fn ping_deadline_bounds_connection_retries() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = BridgeClient::new(listener.local_addr().unwrap().port());
    drop(listener);
    let started = std::time::Instant::now();
    assert!(!client
        .ping_with_deadline(started + Duration::from_millis(100))
        .unwrap());
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[test]
fn shutdown_preserves_save_failure_without_resending() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = BridgeClient::new(listener.local_addr().unwrap().port());
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut request = String::new();
        BufReader::new(&stream).read_line(&mut request).unwrap();
        let request: serde_json::Value = serde_json::from_str(&request).unwrap();
        assert_eq!(request["command"], "shutdown_wait");
        writeln!(
            stream,
            "{{\"status\":\"error\",\"message\":\"Shutdown save failed\",\"detail\":{{\"save_failed\":true,\"saved\":false}}}}"
        )
        .unwrap();
        listener
    });
    let error = client
        .shutdown_with_deadline(Some(std::time::Instant::now() + Duration::from_secs(2)))
        .unwrap_err();
    let error = error
        .downcast_ref::<crate::ipc::protocol::BridgeCommandError>()
        .expect("shutdown must preserve structured save failures");
    assert_eq!(error.message, "Shutdown save failed");
    assert_eq!(error.detail["save_failed"], true);
    assert_eq!(error.detail["saved"], false);
    let listener = server.join().unwrap();
    listener.set_nonblocking(true).unwrap();
    assert_eq!(listener.accept().unwrap_err().kind(), ErrorKind::WouldBlock);
}

#[test]
fn expired_shutdown_deadline_does_not_connect() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let client = BridgeClient::new(listener.local_addr().unwrap().port());
    let error = client
        .shutdown_with_deadline(Some(std::time::Instant::now()))
        .unwrap_err();
    assert_eq!(
        error.downcast_ref::<Error>().unwrap().kind(),
        ErrorKind::TimedOut
    );
    assert!(error
        .downcast_ref::<crate::ipc::protocol::BridgeOutcomeUnknownError>()
        .is_none());
    assert!(error
        .downcast_ref::<crate::ipc::protocol::BridgeJob>()
        .is_none());
    assert_eq!(listener.accept().unwrap_err().kind(), ErrorKind::WouldBlock);
}

#[test]
fn expired_program_deadline_does_not_create_a_recovery_job() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let client = BridgeClient::new(listener.local_addr().unwrap().port());
    let error = client
        .send_command_with_deadline("comment_set", None, Some(std::time::Instant::now()))
        .unwrap_err();
    assert_eq!(
        error.downcast_ref::<Error>().unwrap().kind(),
        ErrorKind::TimedOut
    );
    assert!(error
        .downcast_ref::<crate::ipc::protocol::BridgeOutcomeUnknownError>()
        .is_none());
    assert!(error
        .downcast_ref::<crate::ipc::protocol::BridgeJob>()
        .is_none());
    assert_eq!(listener.accept().unwrap_err().kind(), ErrorKind::WouldBlock);
}

#[test]
fn invalid_read_timeout_fails_before_sending_request() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = BridgeClient::new(listener.local_addr().unwrap().port());
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut request = String::new();
        BufReader::new(&stream).read_line(&mut request).unwrap();
        if !request.is_empty() {
            // Let a regressed client finish rather than hang indefinitely.
            writeln!(stream, "{{\"status\":\"success\"}}").unwrap();
        }
        request
    });
    let result = client.send_command_with_timeout("comment_set", None, Some(Duration::ZERO));
    let request = server.join().unwrap();
    assert!(
        request.is_empty(),
        "Sent request despite invalid timeout: {request}"
    );
    let error = result.unwrap_err();
    assert_eq!(
        error.downcast_ref::<Error>().unwrap().kind(),
        ErrorKind::InvalidInput
    );
    assert!(error.to_string().contains("before sending request"));
    assert!(error
        .downcast_ref::<crate::ipc::protocol::BridgeOutcomeUnknownError>()
        .is_none());
    assert!(error
        .downcast_ref::<crate::ipc::protocol::BridgeJob>()
        .is_none());
}

#[test]
fn eof_after_send_reports_unknown_outcome_without_replay() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = BridgeClient::new(listener.local_addr().unwrap().port());
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut request = String::new();
        BufReader::new(&stream).read_line(&mut request).unwrap();
        assert!(request.contains("comment_set"));
        // The request was accepted, but its response is lost.
        // Keep the listener alive so an unsafe retry remains observable.
        listener
    });
    let error = client
        .send_command_with_timeout("comment_set", None, Some(Duration::from_secs(5)))
        .unwrap_err();
    let listener = server.join().unwrap();
    listener.set_nonblocking(true).unwrap();
    assert_eq!(listener.accept().unwrap_err().kind(), ErrorKind::WouldBlock);
    assert!(error
        .downcast_ref::<crate::ipc::protocol::BridgeOutcomeUnknownError>()
        .is_some());
    let message = format!("{error:#}");
    assert!(message.contains("outcome is unknown"), "{message}");
    assert!(message.contains("applied and saved"), "{message}");
    assert!(message.contains("program state"), "{message}");
    assert!(!message.contains("Retry"), "{message}");
}

#[test]
fn unterminated_reply_reports_unknown_outcome_without_replay() {
    for deadline in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = BridgeClient::new(listener.local_addr().unwrap().port());
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut line = String::new();
            BufReader::new(&stream).read_line(&mut line).unwrap();
            let request: serde_json::Value = serde_json::from_str(&line).unwrap();
            let response = serde_json::json!({
                "status": "success", "job_id": request["job_id"], "data": {"changed": true}
            });
            // A complete JSON object is still an incomplete wire frame without its newline.
            write!(stream, "{response}").unwrap();
            (listener, request["job_id"].as_str().unwrap().to_owned())
        });
        let result = if deadline {
            client.send_command_with_deadline(
                "comment_set",
                None,
                Some(std::time::Instant::now() + Duration::from_secs(2)),
            )
        } else {
            client.send_command_with_timeout("comment_set", None, Some(Duration::from_secs(2)))
        };
        let (listener, sent_id) = server.join().unwrap();
        let error = result.unwrap_err();
        assert!(error
            .downcast_ref::<crate::ipc::protocol::BridgeOutcomeUnknownError>()
            .is_some());
        assert_eq!(
            error
                .downcast_ref::<crate::ipc::protocol::BridgeJob>()
                .unwrap()
                .id,
            sent_id
        );
        assert_eq!(
            error.downcast_ref::<Error>().unwrap().kind(),
            ErrorKind::UnexpectedEof
        );
        listener.set_nonblocking(true).unwrap();
        assert_eq!(listener.accept().unwrap_err().kind(), ErrorKind::WouldBlock);
    }
}

#[test]
fn malformed_reply_retains_parse_failure_and_unknown_outcome() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = BridgeClient::new(listener.local_addr().unwrap().port());
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut request = String::new();
        BufReader::new(&stream).read_line(&mut request).unwrap();
        assert!(request.contains("comment_set"));
        stream
            .write_all(b"{\"status\":\"success\",\"data\":\n")
            .unwrap();
        listener
    });
    let error = client
        .send_command_with_timeout("comment_set", None, Some(Duration::from_secs(5)))
        .unwrap_err();
    let listener = server.join().unwrap();
    listener.set_nonblocking(true).unwrap();
    assert_eq!(listener.accept().unwrap_err().kind(), ErrorKind::WouldBlock);
    assert!(error
        .downcast_ref::<crate::ipc::protocol::BridgeOutcomeUnknownError>()
        .is_some());
    assert!(error.downcast_ref::<serde_json::Error>().is_some());
}

#[test]
fn mutation_read_timeout_retains_its_type_without_replay() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = BridgeClient::new(listener.local_addr().unwrap().port());
    let args = serde_json::json!({"address": "0x1000", "text": "reviewed"});
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut request = String::new();
        BufReader::new(&stream).read_line(&mut request).unwrap();
        // The accepted job can still be running after the client gives up.
        // Return the open socket to keep it alive until the client times out.
        (listener, stream, request)
    });
    let error = client
        .send_command_with_timeout(
            "comment_set",
            Some(args.clone()),
            Some(Duration::from_millis(100)),
        )
        .unwrap_err();
    let (listener, _pending_job, request) = server.join().unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&request).unwrap(),
        serde_json::json!({"command": "comment_set", "args": args, "job_id": error.downcast_ref::<crate::ipc::protocol::BridgeJob>().unwrap().id})
    );
    let timeout = error
        .downcast_ref::<crate::ipc::protocol::BridgeTimeoutError>()
        .expect("callers must still recognize a wait timeout for exit code 75");
    assert_eq!(timeout.command, "comment_set");
    listener.set_nonblocking(true).unwrap();
    assert_eq!(listener.accept().unwrap_err().kind(), ErrorKind::WouldBlock);
}

#[test]
fn shutdown_reply_is_only_accepted_for_shutdown_wait() {
    for command in ["comment_set", "ping"] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let selection = crate::ipc::client::ProgramSelection::default();
        let client = BridgeClient::new(listener.local_addr().unwrap().port())
            .with_selection(selection.clone());
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut line = String::new();
            BufReader::new(&stream).read_line(&mut line).unwrap();
            let request: serde_json::Value = serde_json::from_str(&line).unwrap();
            writeln!(stream, "{{\"status\":\"shutdown\"}}").unwrap();
            (listener, request["job_id"].as_str().map(str::to_owned))
        });
        let result = client.send_command_with_timeout(command, None, Some(Duration::from_secs(2)));
        let (listener, sent_id) = server.join().unwrap();
        let error = result.unwrap_err();
        assert!(error
            .downcast_ref::<crate::ipc::protocol::BridgeOutcomeUnknownError>()
            .is_some());
        assert_eq!(
            error
                .downcast_ref::<crate::ipc::protocol::BridgeJob>()
                .map(|job| job.id.clone()),
            sent_id
        );
        assert_eq!(selection.observed(), None);
        listener.set_nonblocking(true).unwrap();
        assert_eq!(listener.accept().unwrap_err().kind(), ErrorKind::WouldBlock);
    }
}

#[test]
fn program_response_identity_is_checked_before_observing_selection() {
    for status in ["success", "error"] {
        for identity in ["matching", "different", "missing"] {
            let selection = crate::ipc::client::ProgramSelection::default();
            selection.record(Some("/previous".to_owned()));
            let (result, request) = exchange_response("open_program", &selection, move |request| {
                let mut response = serde_json::json!({
                    "status": status,
                    "selected_program": "/opened",
                    "data": {"changed": true},
                });
                if status == "error" {
                    response["message"] = serde_json::json!("Operation failed");
                    response["detail"] = serde_json::json!({"rolled_back": true});
                }
                match identity {
                    "matching" => response["job_id"] = request["job_id"].clone(),
                    "different" => {
                        response["job_id"] = serde_json::json!(uuid::Uuid::new_v4().to_string())
                    }
                    _ => {}
                }
                response
            });
            let sent_id = request["job_id"].as_str().unwrap();
            uuid::Uuid::parse_str(sent_id).unwrap();
            if identity == "matching" {
                if status == "success" {
                    assert_eq!(result.unwrap(), serde_json::json!({"changed": true}));
                } else {
                    let error = result.unwrap_err();
                    let command_error = error
                        .downcast_ref::<crate::ipc::protocol::BridgeCommandError>()
                        .unwrap();
                    assert_eq!(command_error.message, "Operation failed");
                    assert_eq!(command_error.detail["rolled_back"], true);
                    assert!(error
                        .downcast_ref::<crate::ipc::protocol::BridgeOutcomeUnknownError>()
                        .is_none());
                    assert!(error
                        .downcast_ref::<crate::ipc::protocol::BridgeJob>()
                        .is_none());
                }
                assert_eq!(selection.observed(), Some(Some("/opened".to_owned())));
            } else {
                let error = result.unwrap_err();
                assert!(error
                    .downcast_ref::<crate::ipc::protocol::BridgeOutcomeUnknownError>()
                    .is_some());
                assert_eq!(
                    error
                        .downcast_ref::<crate::ipc::protocol::BridgeJob>()
                        .unwrap()
                        .id,
                    sent_id
                );
                assert_eq!(selection.observed(), Some(Some("/previous".to_owned())));
            }
        }
    }
}

#[test]
fn successful_program_reply_requires_a_selection_receipt() {
    let selection = crate::ipc::client::ProgramSelection::default();
    selection.record(Some("/previous".to_owned()));
    let (result, request) = exchange_response("open_program", &selection, |request| {
        serde_json::json!({
            "status": "success", "job_id": request["job_id"], "data": {"opened": true}
        })
    });
    let error = result.unwrap_err();
    assert!(error
        .downcast_ref::<crate::ipc::protocol::BridgeOutcomeUnknownError>()
        .is_some());
    assert_eq!(
        error
            .downcast_ref::<crate::ipc::protocol::BridgeJob>()
            .unwrap()
            .id,
        request["job_id"]
    );
    assert!(error.root_cause().to_string().contains("selected_program"));
    assert_eq!(selection.observed(), Some(Some("/previous".to_owned())));
}

#[test]
fn unexecuted_program_errors_preserve_selection_without_unknown_outcome() {
    for accepted in [false, true] {
        let selection = crate::ipc::client::ProgramSelection::default();
        selection.record(Some("/previous".to_owned()));
        let (result, _) = exchange_response("open_program", &selection, move |request| {
            let mut response = serde_json::json!({
                "status": "error",
                "message": if accepted { "Cancelled before execution" } else { "Queue full" },
            });
            if accepted {
                response["job_id"] = request["job_id"].clone();
                response["detail"] = serde_json::Value::Null;
            }
            response
        });
        let error = result.unwrap_err();
        assert!(error
            .downcast_ref::<crate::ipc::protocol::BridgeOutcomeUnknownError>()
            .is_none());
        assert!(error
            .downcast_ref::<crate::ipc::protocol::BridgeJob>()
            .is_none());
        assert_eq!(selection.observed(), Some(Some("/previous".to_owned())));
    }
}

#[test]
fn invalid_error_detail_is_unknown_before_dispatch_or_selection_update() {
    for command in ["comment_set", "job_cancel"] {
        for detail in [serde_json::json!(true), serde_json::json!([])] {
            let selection = crate::ipc::client::ProgramSelection::default();
            selection.record(Some("/previous".to_owned()));
            let (result, request) = exchange_response(command, &selection, move |request| {
                let mut response = serde_json::json!({
                    "status": "error", "message": "Operation failed", "detail": detail,
                });
                if let Some(id) = request.get("job_id") {
                    response["job_id"] = id.clone();
                    response["selected_program"] = serde_json::json!("/opened");
                }
                response
            });
            let error = result.unwrap_err();
            assert!(error
                .downcast_ref::<crate::ipc::protocol::BridgeOutcomeUnknownError>()
                .is_some());
            assert!(error.downcast_ref::<serde_json::Error>().is_some());
            assert!(error
                .downcast_ref::<crate::ipc::protocol::BridgeCommandError>()
                .is_none());
            assert_eq!(
                error
                    .downcast_ref::<crate::ipc::protocol::BridgeJob>()
                    .map(|job| job.id.as_str()),
                request.get("job_id").and_then(serde_json::Value::as_str)
            );
            assert_eq!(selection.observed(), Some(Some("/previous".to_owned())));
        }
    }
}

#[test]
fn parse_secs_zero_means_no_timeout() {
    assert_eq!(parse_secs(Some("0"), 300), None);
}

#[test]
fn parse_secs_reads_value() {
    assert_eq!(parse_secs(Some("12"), 300), Some(Duration::from_secs(12)));
    assert_eq!(parse_secs(Some("  7 "), 300), Some(Duration::from_secs(7)));
}

#[test]
fn parse_secs_falls_back_when_absent_or_garbage() {
    assert_eq!(parse_secs(None, 42), Some(Duration::from_secs(42)));
    assert_eq!(parse_secs(Some("nope"), 42), Some(Duration::from_secs(42)));
    // Fallback default of 0 still means "no timeout".
    assert_eq!(parse_secs(None, 0), None);
}
