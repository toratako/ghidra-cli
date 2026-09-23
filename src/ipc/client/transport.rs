//! Connection retry, socket timeouts, and request/response transport.

use super::BridgeClient;
use crate::ipc::protocol::{
    BridgeCommandError, BridgeJob, BridgeOutcomeUnknownError, BridgeRequest, BridgeResponse,
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

        let job_id = (!matches!(
            command,
            "ping"
                | "status"
                | "bridge_info"
                | "job_status"
                | "job_cancel"
                | "job_result"
                | "shutdown_wait"
        ))
        .then(|| uuid::Uuid::new_v4().to_string());
        let request = BridgeRequest {
            command: command.to_string(),
            job_id: job_id.clone(),
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
            if response.job_id.is_some() || (job_id.is_some() && response.status == "success") {
                anyhow::ensure!(
                    response.job_id == job_id,
                    "Bridge response job ID does not match the sent request"
                );
            }
            Ok(response)
        })()
        .map_err(|error| {
            let error = if error.downcast_ref::<BridgeTimeoutError>().is_some() {
                error
            } else {
                error.context(BridgeOutcomeUnknownError {
                    command: command.to_owned(),
                })
            };
            match job_id {
                Some(id) => error.context(BridgeJob {
                    id,
                    command: command.to_owned(),
                }),
                None => error,
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
mod tests;
