//! Request identity, response validation, and the boundary of unknown outcomes.

mod connection;

use super::BridgeClient;
use crate::ipc::protocol::{
    BridgeCommandError, BridgeJob, BridgeOutcomeUnknownError, BridgeRequest, BridgeResponse,
    BridgeTimeoutError,
};
use anyhow::Result;
use connection::Connection;
use serde_json::json;
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
        let mut connection = Connection::connect(self.port, read_timeout, deadline)?;

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
            program: if job_id.is_some() {
                self.program.clone()
            } else {
                None
            },
            args,
        };

        let request_json = serde_json::to_string(&request)?;
        debug!("Sending: {}", request_json);

        let wire = format!("{request_json}\n");
        // From the first write onward, a transport/protocol failure cannot prove
        // that the bridge did not execute the command. Never replay it.
        let response = (|| -> Result<BridgeResponse> {
            connection.write_request(&wire)?;
            let response_line = match connection.read_line() {
                // EOF before any response: bridge closed the socket without replying.
                Ok(line) if line.is_empty() => {
                    anyhow::bail!("Bridge closed the connection without responding to '{command}'")
                }
                Ok(line) => line,
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
            };

            debug!("Received: {}", response_line.trim());

            let response: BridgeResponse = serde_json::from_str(&response_line)?;
            anyhow::ensure!(
                matches!(response.status.as_str(), "success" | "error" | "shutdown"),
                "Invalid bridge response status: '{}'",
                response.status
            );
            anyhow::ensure!(
                response.status != "shutdown" || command == "shutdown_wait",
                "Unexpected shutdown response to '{command}'"
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
            match &job_id {
                Some(id) => error.context(BridgeJob {
                    id: id.clone(),
                    command: command.to_owned(),
                }),
                None => error,
            }
        })?;

        if job_id.is_some() && response.job_id == job_id {
            if let Some(program) = response.selected_program {
                self.selection.record(program);
            }
        }

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
