//! Connection retry, socket timeouts, and request/response transport.

use super::BridgeClient;
use crate::ipc::protocol::{BridgeCommandError, BridgeRequest, BridgeResponse, BridgeTimeoutError};
use anyhow::Result;
use serde_json::json;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::Duration;
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
fn connect_with_retry(addr: &std::net::SocketAddr) -> Result<TcpStream> {
    let budget = connect_deadline();
    let deadline = std::time::Instant::now() + budget;
    let mut backoff = Duration::from_millis(100);
    let mut last_err: Option<std::io::Error> = None;
    loop {
        match TcpStream::connect_timeout(addr, Duration::from_secs(10)) {
            Ok(stream) => return Ok(stream),
            Err(e) if is_transient_connect_error(&e) && std::time::Instant::now() < deadline => {
                debug!("bridge connect transient ({e}); retrying in {backoff:?}");
                last_err = Some(e);
                std::thread::sleep(backoff);
                backoff = (backoff * 2).min(Duration::from_secs(2));
            }
            Err(e) => {
                let e = last_err.unwrap_or(e);
                anyhow::bail!(
                    "Failed to connect to bridge on port {} after waiting {}s: {}. \
                     Is the bridge running? Check `ghidra status`.",
                    addr.port(),
                    budget.as_secs(),
                    e
                );
            }
        }
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
        let addr: std::net::SocketAddr = format!("127.0.0.1:{}", self.port)
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid address: {}", e))?;
        let mut stream = connect_with_retry(&addr)?;
        // `None` => blocking reads (no timeout). A long analysis can exceed any
        // fixed cap, so callers route those ops through here with `None`.
        stream.set_read_timeout(read_timeout).ok();
        stream.set_write_timeout(Some(Duration::from_secs(30))).ok();

        let request = BridgeRequest {
            command: command.to_string(),
            args,
        };

        let request_json = serde_json::to_string(&request)?;
        debug!("Sending: {}", request_json);

        writeln!(stream, "{}", request_json)?;
        stream.flush()?;

        let mut reader = BufReader::new(&stream);
        let mut response_line = String::new();
        match reader.read_line(&mut response_line) {
            // EOF before any response: bridge closed the socket without replying.
            Ok(0) => anyhow::bail!(
                "Bridge closed the connection without responding to '{}' \
                 (it may have crashed or been restarted). Retry, or check `ghidra status`.",
                command
            ),
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
                    timeout_secs: read_timeout.map(|d| d.as_secs()).unwrap_or(0),
                }
                .into())
            }
            Err(e) => return Err(e.into()),
        }

        debug!("Received: {}", response_line.trim());

        let response: BridgeResponse = serde_json::from_str(&response_line)?;

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
            _ => Ok(response.data.unwrap_or(json!({}))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{is_transient_connect_error, parse_secs};
    use std::io::{Error, ErrorKind};
    use std::time::Duration;

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
