//! Connection retry, socket timeouts, and request/response transport.

use super::BridgeClient;
use crate::ipc::protocol::{
    BridgeCommandError, BridgeOutcomeUnknownError, BridgeRequest, BridgeResponse,
    BridgeTimeoutError,
};
use anyhow::{Context, Result};
use serde_json::json;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};
use tracing::debug;

/// Default socket read timeout for short, interactive commands, in seconds.
///
/// Ghidra program access is serialized through the bridge's explicit job queue,
/// so a command that arrives while another is in flight waits its turn while
/// control requests remain responsive. This budget must therefore be generous
/// enough to outlast whatever is ahead of it. Override with
/// `GHIDRA_CLI_READ_TIMEOUT` (seconds); `0` means block indefinitely.
const DEFAULT_READ_TIMEOUT_SECS: u64 = 300;

/// Wall-clock budget for establishing the initial TCP connection, retried with
/// backoff while the bridge is starting, restarting, or its accept backlog is
/// momentarily saturated. Override with `GHIDRA_CLI_CONNECT_DEADLINE` (seconds).
const DEFAULT_CONNECT_DEADLINE_SECS: u64 = 60;

/// Interpret a seconds string into an optional [`Duration`]: `0` means "no
/// timeout" (`None`), and an absent/unparseable value falls back to `default`.
fn parse_secs(raw: Option<&str>, default: u64) -> Option<Duration> {
    let secs = raw
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(default);
    (secs > 0).then(|| Duration::from_secs(secs))
}

/// Parse a seconds-valued env var into an optional [`Duration`], where `0` means
/// "no timeout" (`None`) and an unset/invalid value falls back to `default`.
fn secs_env(var: &str, default: u64) -> Option<Duration> {
    parse_secs(std::env::var(var).ok().as_deref(), default)
}

/// Read timeout for short, interactive commands. `None` blocks indefinitely.
fn default_read_timeout() -> Option<Duration> {
    secs_env("GHIDRA_CLI_READ_TIMEOUT", DEFAULT_READ_TIMEOUT_SECS)
}

/// Read timeout for long-running operations (analyze/import of large binaries).
///
/// `None` means block until the bridge responds or the connection drops — these
/// ops can legitimately exceed any fixed cap. Power users can impose a ceiling
/// via `GHIDRA_CLI_OP_TIMEOUT` (seconds); `0` or unset means unbounded.
pub(super) fn long_op_timeout() -> Option<Duration> {
    match std::env::var("GHIDRA_CLI_OP_TIMEOUT")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
    {
        Some(0) | None => None,
        Some(secs) => Some(Duration::from_secs(secs)),
    }
}

/// Overall connect budget, from `GHIDRA_CLI_CONNECT_DEADLINE` (min 1s).
fn connect_deadline() -> Duration {
    let secs = std::env::var("GHIDRA_CLI_CONNECT_DEADLINE")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_CONNECT_DEADLINE_SECS);
    Duration::from_secs(secs.max(1))
}

/// A connect error that means "not yet", not "never": the bridge is (re)starting
/// or its accept backlog is momentarily full. Safe to wait and retry.
fn is_transient_connect_error(e: &std::io::Error) -> bool {
    use std::io::ErrorKind::*;
    matches!(
        e.kind(),
        ConnectionRefused | ConnectionReset | ConnectionAborted | TimedOut | AddrInUse | WouldBlock
    )
}

/// Connect to the bridge, waiting out transient failures.
///
/// A busy bridge still accepts connections and queues program jobs, so connect
/// normally succeeds immediately and the wait happens on the read. But during
/// bridge (re)start or saturated client capacity, connect can
/// fail transiently; rather than surfacing that as a hard error we retry with
/// exponential backoff until [`connect_deadline`] elapses. Only pre-send connect
/// failures are retried — nothing has been written yet — so this stays safe for
/// non-idempotent commands (rename/comment/patch).
fn connect_with_retry(addr: &std::net::SocketAddr, deadline: Option<Instant>) -> Result<TcpStream> {
    let budget = remaining_timeout(deadline, Some(connect_deadline()))?.unwrap();
    let started = std::time::Instant::now();
    retry_connect(
        budget,
        |timeout| TcpStream::connect_timeout(addr, timeout),
        || started.elapsed(),
        std::thread::sleep,
    )
    .map_err(|error| {
        let message = format!(
            "Failed to connect to bridge on port {} within {}s: {}. \
             Is the bridge running? Check `ghidra-cli bridge status`.",
            addr.port(),
            budget.as_secs(),
            error
        );
        anyhow::Error::new(error).context(message)
    })
}

// Keep time and connection attempts injectable so deadline boundaries can be
// checked without wall-clock races or changing the process environment.
fn retry_connect<T>(
    budget: Duration,
    mut connect: impl FnMut(Duration) -> std::io::Result<T>,
    mut elapsed: impl FnMut() -> Duration,
    mut sleep: impl FnMut(Duration),
) -> std::io::Result<T> {
    let mut backoff = Duration::from_millis(100);
    let mut last_err: Option<std::io::Error> = None;
    loop {
        let remaining = budget.saturating_sub(elapsed());
        if remaining.is_zero() {
            return Err(last_err.unwrap_or_else(|| std::io::ErrorKind::TimedOut.into()));
        }
        match connect(remaining.min(Duration::from_secs(10))) {
            Ok(stream) if elapsed() < budget => return Ok(stream),
            Ok(_) => return Err(std::io::ErrorKind::TimedOut.into()),
            Err(e) if is_transient_connect_error(&e) => {
                let wait = backoff.min(budget.saturating_sub(elapsed()));
                debug!("bridge connect transient ({e}); retrying in {wait:?}");
                last_err = Some(e);
                sleep(wait);
                backoff = (backoff * 2).min(Duration::from_secs(2));
            }
            Err(e) => return Err(e),
        }
    }
}

fn remaining_timeout(
    deadline: Option<Instant>,
    limit: Option<Duration>,
) -> std::io::Result<Option<Duration>> {
    match deadline {
        Some(deadline) => {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(std::io::ErrorKind::TimedOut.into());
            }
            Ok(Some(limit.map_or(remaining, |limit| limit.min(remaining))))
        }
        None => Ok(limit),
    }
}

impl BridgeClient {
    /// Send a command to the bridge and return the result.
    ///
    /// Uses [`DEFAULT_READ_TIMEOUT_SECS`] for the response wait — suitable for short,
    /// interactive commands. Long-running ops should use
    /// [`Self::send_command_with_timeout`] with an unbounded read timeout.
    pub fn send_command(
        &self,
        command: &str,
        args: Option<serde_json::Value>,
    ) -> Result<serde_json::Value> {
        self.send_command_with_timeout(command, args, default_read_timeout())
    }

    /// Send a command with an explicit socket read timeout.
    ///
    /// `read_timeout = None` blocks until the bridge responds or the connection
    /// drops — required for operations whose duration is unbounded (e.g. analysis
    /// of a large binary), which would otherwise spuriously time out.
    pub fn send_command_with_timeout(
        &self,
        command: &str,
        args: Option<serde_json::Value>,
        read_timeout: Option<Duration>,
    ) -> Result<serde_json::Value> {
        self.send_command_inner(command, args, read_timeout, None)
    }

    /// Bound connection, request writes and response reads by one wall-clock deadline.
    /// `None` keeps the response wait unbounded.
    pub fn send_command_with_deadline(
        &self,
        command: &str,
        args: Option<serde_json::Value>,
        deadline: Option<Instant>,
    ) -> Result<serde_json::Value> {
        self.send_command_inner(command, args, None, deadline)
    }

    fn send_command_inner(
        &self,
        command: &str,
        args: Option<serde_json::Value>,
        read_timeout: Option<Duration>,
        deadline: Option<Instant>,
    ) -> Result<serde_json::Value> {
        let timeout_description = deadline
            .map(|end| end.saturating_duration_since(Instant::now()))
            .or(read_timeout);
        let addr: std::net::SocketAddr = format!("127.0.0.1:{}", self.port)
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid address: {}", e))?;
        let mut stream = connect_with_retry(&addr, deadline)?;
        // `None` => blocking reads (no timeout). A long analysis can exceed any
        // fixed cap, so callers route those ops through here with `None`.
        stream
            .set_read_timeout(remaining_timeout(deadline, read_timeout)?)
            .context("Failed to set bridge read timeout before sending request")?;
        stream
            .set_write_timeout(remaining_timeout(deadline, Some(Duration::from_secs(30)))?)
            .context("Failed to set bridge write timeout before sending request")?;

        let request = BridgeRequest {
            command: command.to_string(),
            args,
        };

        let request_json = serde_json::to_string(&request)?;
        debug!("Sending: {}", request_json);

        let wire = format!("{request_json}\n");
        // From the first write onward, a transport/protocol failure cannot prove
        // that the bridge did not execute the command. Never replay it.
        let response = (|| -> Result<BridgeResponse> {
            let mut pending = wire.as_bytes();
            while !pending.is_empty() {
                stream.set_write_timeout(remaining_timeout(
                    deadline,
                    Some(Duration::from_secs(30)),
                )?)?;
                let written = stream.write(pending)?;
                anyhow::ensure!(written > 0, "Bridge closed while writing request");
                pending = &pending[written..];
            }

            let mut reader = BufReader::new(&stream);
            let mut response_line = String::new();
            let read_result = if deadline.is_some() {
                // Refresh the remaining budget on every receive, so a partial reply
                // cannot extend the shutdown deadline by trickling bytes.
                let mut bytes = Vec::new();
                (|| -> std::io::Result<usize> {
                    loop {
                        stream.set_read_timeout(remaining_timeout(deadline, read_timeout)?)?;
                        let available = reader.fill_buf()?;
                        if available.is_empty() {
                            break;
                        }
                        let count = available
                            .iter()
                            .position(|byte| *byte == b'\n')
                            .map_or(available.len(), |index| index + 1);
                        let complete = available[count - 1] == b'\n';
                        bytes.extend_from_slice(&available[..count]);
                        reader.consume(count);
                        if complete {
                            break;
                        }
                    }
                    let count = bytes.len();
                    response_line = String::from_utf8(bytes).map_err(|error| {
                        std::io::Error::new(std::io::ErrorKind::InvalidData, error)
                    })?;
                    Ok(count)
                })()
            } else {
                reader.read_line(&mut response_line)
            };
            match read_result {
                // EOF before any response: bridge closed the socket without replying.
                Ok(0) => {
                    anyhow::bail!("Bridge closed the connection without responding to '{command}'")
                }
                Ok(_) => {}
                // A read timeout here means the bridge is up (we connected) but hasn't
                // reached our queued request in time — almost always because it is busy
                // serving another agent. Surface that plainly, with the knob to wait longer.
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    return Err(BridgeTimeoutError {
                        command: command.to_string(),
                        timeout_secs: timeout_description.map(|d| d.as_secs()).unwrap_or(0),
                    }
                    .into())
                }
                Err(e) => return Err(e.into()),
            }

            debug!("Received: {}", response_line.trim());

            let response: BridgeResponse = serde_json::from_str(&response_line)?;
            anyhow::ensure!(
                matches!(response.status.as_str(), "success" | "error" | "shutdown"),
                "Invalid bridge response status: '{}'",
                response.status
            );
            Ok(response)
        })()
        .map_err(|error| {
            if error.downcast_ref::<BridgeTimeoutError>().is_some() {
                error
            } else {
                error.context(BridgeOutcomeUnknownError {
                    command: command.to_owned(),
                })
            }
        })?;

        match response.status.as_str() {
            "success" => Ok(response.data.unwrap_or(json!({}))),
            "error" => {
                let msg = response
                    .message
                    .unwrap_or_else(|| "Unknown error".to_string());
                match response.detail {
                    Some(detail) if !detail.is_null() => Err(BridgeCommandError {
                        message: msg,
                        detail,
                    }
                    .into()),
                    _ => anyhow::bail!("{}", msg),
                }
            }
            "shutdown" => Ok(json!({"status": "shutdown"})),
            _ => unreachable!("response status was validated before dispatch"),
        }
    }
}

#[cfg(test)]
mod tests {
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
        });
        let error = client
            .send_command_with_timeout("comment_set", None, Some(Duration::from_secs(5)))
            .unwrap_err();
        server.join().unwrap();
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
        });
        let error = client
            .send_command_with_timeout("comment_set", None, Some(Duration::from_secs(5)))
            .unwrap_err();
        server.join().unwrap();
        assert!(error
            .downcast_ref::<crate::ipc::protocol::BridgeOutcomeUnknownError>()
            .is_some());
        assert!(error.downcast_ref::<serde_json::Error>().is_some());
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
}
