use super::{is_transient_connect_error, parse_secs, retry_connect, BridgeClient};
use std::cell::Cell;
use std::io::{BufRead, BufReader, Error, ErrorKind, Write};
use std::net::TcpListener;
use std::time::Duration;

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
            "ping",
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
    assert_eq!(listener.accept().unwrap_err().kind(), ErrorKind::WouldBlock);
}

#[test]
fn connect_attempts_and_backoff_share_one_deadline() {
    let elapsed = Cell::new(Duration::ZERO);
    let mut attempts = Vec::new();
    let mut waits = Vec::new();
    let error = retry_connect::<()>(
        Duration::from_millis(250),
        |timeout| {
            attempts.push(timeout);
            Err(ErrorKind::ConnectionRefused.into())
        },
        || elapsed.get(),
        |wait| {
            waits.push(wait);
            elapsed.set(elapsed.get() + wait);
        },
    )
    .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::ConnectionRefused);
    assert_eq!(
        attempts,
        [Duration::from_millis(250), Duration::from_millis(150)]
    );
    assert_eq!(
        waits,
        [Duration::from_millis(100), Duration::from_millis(150)]
    );
    assert_eq!(elapsed.get(), Duration::from_millis(250));
}

#[test]
fn connect_does_not_attempt_after_oversleep() {
    let elapsed = Cell::new(Duration::ZERO);
    let mut attempts = 0;
    let error = retry_connect::<()>(
        Duration::from_secs(20),
        |timeout| {
            attempts += 1;
            assert_eq!(timeout, Duration::from_secs(10));
            Err(ErrorKind::ConnectionRefused.into())
        },
        || elapsed.get(),
        |_| elapsed.set(Duration::from_secs(21)),
    )
    .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::ConnectionRefused);
    assert_eq!(attempts, 1);
}

#[test]
fn connect_rejects_success_returned_after_deadline() {
    let elapsed = Cell::new(Duration::ZERO);
    let error = retry_connect(
        Duration::from_secs(1),
        |timeout| {
            assert_eq!(timeout, Duration::from_secs(1));
            elapsed.set(Duration::from_secs(1));
            Ok(())
        },
        || elapsed.get(),
        |_| panic!("successful connect must not be retried"),
    )
    .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::TimedOut);
}

#[test]
fn connect_preserves_permanent_error_after_transient_failure() {
    let elapsed = Cell::new(Duration::ZERO);
    let mut attempts = 0;
    let error = retry_connect::<()>(
        Duration::from_secs(1),
        |_| {
            attempts += 1;
            Err(if attempts == 1 {
                ErrorKind::ConnectionRefused
            } else {
                ErrorKind::PermissionDenied
            }
            .into())
        },
        || elapsed.get(),
        |wait| elapsed.set(elapsed.get() + wait),
    )
    .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::PermissionDenied);
    assert_eq!(attempts, 2);
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
    let message = error.to_string();
    assert!(message.contains("outcome is unknown"), "{message}");
    assert!(message.contains("applied and saved"), "{message}");
    assert!(message.contains("program state"), "{message}");
    assert!(!message.contains("Retry"), "{message}");
}

#[test]
fn truncated_reply_retains_parse_failure_and_unknown_outcome() {
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
            .write_all(b"{\"status\":\"success\",\"data\":")
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
        serde_json::json!({"command": "comment_set", "args": args})
    );
    let timeout = error
        .downcast_ref::<crate::ipc::protocol::BridgeTimeoutError>()
        .expect("callers must still recognize a wait timeout for exit code 75");
    assert_eq!(timeout.command, "comment_set");
    listener.set_nonblocking(true).unwrap();
    assert_eq!(listener.accept().unwrap_err().kind(), ErrorKind::WouldBlock);
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

#[test]
fn transient_connect_errors_are_retryable() {
    for kind in [
        ErrorKind::ConnectionRefused,
        ErrorKind::ConnectionReset,
        ErrorKind::ConnectionAborted,
        ErrorKind::TimedOut,
    ] {
        assert!(
            is_transient_connect_error(&Error::from(kind)),
            "{kind:?} should be retryable"
        );
    }
}

#[test]
fn permanent_connect_errors_are_not_retryable() {
    for kind in [ErrorKind::NotFound, ErrorKind::PermissionDenied] {
        assert!(
            !is_transient_connect_error(&Error::from(kind)),
            "{kind:?} should not be retryable"
        );
    }
}
