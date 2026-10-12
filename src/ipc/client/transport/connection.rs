//! One socket's lifetime, connection retries, and newline framing.

use anyhow::{Context, Result};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};
use tracing::debug;

/// Wall-clock budget for establishing the initial TCP connection, retried with
/// backoff while the bridge is starting, restarting, or its accept backlog is
/// momentarily saturated. Override with `GHIDRA_CLI_CONNECT_DEADLINE` (seconds).
const DEFAULT_CONNECT_DEADLINE_SECS: u64 = 60;

pub(super) struct Connection {
    stream: TcpStream,
    read_timeout: Option<Duration>,
    deadline: Option<Instant>,
}

impl Connection {
    pub(super) fn connect(
        port: u16,
        read_timeout: Option<Duration>,
        deadline: Option<Instant>,
    ) -> Result<Self> {
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
        let stream = connect_with_retry(&addr, deadline)?;
        // `None` => blocking reads (no timeout). A long analysis can exceed any
        // fixed cap, so callers route those ops through here with `None`.
        stream
            .set_read_timeout(remaining_timeout(deadline, read_timeout)?)
            .context("Failed to set bridge read timeout before sending request")?;
        stream
            .set_write_timeout(remaining_timeout(deadline, Some(Duration::from_secs(30)))?)
            .context("Failed to set bridge write timeout before sending request")?;

        Ok(Self {
            stream,
            read_timeout,
            deadline,
        })
    }

    pub(super) fn write_request(&mut self, wire: &str) -> Result<()> {
        let mut pending = wire.as_bytes();
        while !pending.is_empty() {
            self.stream.set_write_timeout(remaining_timeout(
                self.deadline,
                Some(Duration::from_secs(30)),
            )?)?;
            let written = match self.stream.write(pending) {
                Ok(written) => written,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            };
            anyhow::ensure!(written > 0, "Bridge closed while writing request");
            pending = &pending[written..];
        }

        Ok(())
    }

    pub(super) fn read_line(&self) -> std::io::Result<String> {
        let mut reader = BufReader::new(&self.stream);
        let mut bytes = Vec::new();
        loop {
            // Refresh the remaining budget on every receive, so a partial reply
            // cannot extend the shutdown deadline by trickling bytes.
            self.stream
                .set_read_timeout(remaining_timeout(self.deadline, self.read_timeout)?)?;
            let available = match reader.fill_buf() {
                Ok(available) => available,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            };
            if available.is_empty() {
                if bytes.is_empty() {
                    return Ok(String::new());
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "Bridge closed the connection before completing its response frame",
                ));
            }
            let count = available
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(available.len(), |index| index + 1);
            let complete = available[count - 1] == b'\n';
            bytes.extend_from_slice(&available[..count]);
            reader.consume(count);
            if complete {
                return String::from_utf8(bytes)
                    .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error));
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::io::{Error, ErrorKind};

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
