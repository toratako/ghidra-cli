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

    /// Notify the caller immediately before each write attempt: timeout setup
    /// failure still proves that no request bytes reached the bridge.
    pub(super) fn write_request(
        &mut self,
        wire: &str,
        on_write_attempt: impl FnMut(),
    ) -> Result<()> {
        write_request_to(
            &self.stream,
            wire.as_bytes(),
            || {
                self.stream.set_write_timeout(remaining_timeout(
                    self.deadline,
                    Some(Duration::from_secs(30)),
                )?)
            },
            || remaining_timeout(self.deadline, None).map(|_| ()),
            on_write_attempt,
        )?;
        Ok(())
    }

    pub(super) fn read_line(&self) -> std::io::Result<String> {
        read_response_frame(
            BufReader::new(&self.stream),
            || {
                // Refresh the remaining budget on every receive, so a partial
                // reply cannot extend the shutdown deadline by trickling bytes.
                self.stream
                    .set_read_timeout(remaining_timeout(self.deadline, self.read_timeout)?)
            },
            || remaining_timeout(self.deadline, None).map(|_| ()),
        )
    }
}

// Keep framing and the point where a request may reach the bridge testable
// without relying on socket buffer sizes, scheduling, or wall-clock delays.
fn write_request_to(
    mut writer: impl Write,
    mut pending: &[u8],
    mut prepare_write: impl FnMut() -> std::io::Result<()>,
    mut check_deadline: impl FnMut() -> std::io::Result<()>,
    mut on_write_attempt: impl FnMut(),
) -> std::io::Result<()> {
    while !pending.is_empty() {
        prepare_write()?;
        on_write_attempt();
        let written = match writer.write(pending) {
            Ok(written) => written,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        check_deadline()?;
        if written == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "Bridge closed while writing request",
            ));
        }
        pending = &pending[written..];
    }
    Ok(())
}

fn read_response_frame(
    mut reader: impl BufRead,
    mut prepare_read: impl FnMut() -> std::io::Result<()>,
    mut check_deadline: impl FnMut() -> std::io::Result<()>,
) -> std::io::Result<String> {
    let mut bytes = Vec::new();
    loop {
        prepare_read()?;
        let available = match reader.fill_buf() {
            Ok(available) => available,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        // A socket timeout may round its duration up, and a completed receive
        // can be followed by descheduling. Do not accept a late response.
        check_deadline()?;
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
    let started = std::time::Instant::now();
    let budget = remaining_timeout(deadline, Some(connect_deadline()))?.unwrap();
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
            return Err(match last_err {
                Some(error) => std::io::Error::new(std::io::ErrorKind::TimedOut, error),
                None => std::io::ErrorKind::TimedOut.into(),
            });
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
    use std::io::{Cursor, Error, ErrorKind, Read};

    struct WriterFn<F>(F);

    impl<F: FnMut(&[u8]) -> std::io::Result<usize>> Write for WriterFn<F> {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0(bytes)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct ReaderFn<F>(F);

    impl<F: FnMut(&mut [u8]) -> std::io::Result<usize>> Read for ReaderFn<F> {
        fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
            self.0(bytes)
        }
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
        assert_eq!(error.kind(), ErrorKind::TimedOut);
        assert_eq!(
            error
                .get_ref()
                .unwrap()
                .downcast_ref::<Error>()
                .unwrap()
                .kind(),
            ErrorKind::ConnectionRefused
        );
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
        assert_eq!(error.kind(), ErrorKind::TimedOut);
        assert_eq!(attempts, 1);
    }

    #[test]
    fn exhausted_connect_budget_does_not_attempt_or_wait() {
        let error = retry_connect::<()>(
            Duration::ZERO,
            |_| panic!("expired connection budget must not attempt a connection"),
            || Duration::ZERO,
            |_| panic!("expired connection budget must not wait"),
        )
        .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::TimedOut);
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

    #[test]
    fn write_setup_failures_do_not_mark_or_attempt_a_request() {
        for kind in [ErrorKind::TimedOut, ErrorKind::PermissionDenied] {
            let attempted = Cell::new(false);
            let error = write_request_to(
                WriterFn(|_: &[u8]| panic!("failed timeout setup must not write")),
                b"request\n",
                || Err(kind.into()),
                || panic!("failed timeout setup must return before deadline recheck"),
                || attempted.set(true),
            )
            .unwrap_err();
            assert_eq!(error.kind(), kind);
            assert!(!attempted.get());
        }
    }

    #[test]
    fn partial_and_interrupted_writes_preserve_the_request() {
        let mut written = Vec::new();
        let attempted = Cell::new(0);
        let prepared = Cell::new(0);
        write_request_to(
            WriterFn(|pending: &[u8]| {
                assert_eq!(attempted.get(), prepared.get());
                if attempted.get() == 1 {
                    return Err(ErrorKind::Interrupted.into());
                }
                let count = pending.len().min(2);
                written.extend_from_slice(&pending[..count]);
                Ok(count)
            }),
            b"request\n",
            || {
                prepared.set(prepared.get() + 1);
                Ok(())
            },
            || Ok(()),
            || attempted.set(attempted.get() + 1),
        )
        .unwrap();
        assert_eq!(written, b"request\n");
        assert_eq!(attempted.get(), 5);
    }

    #[test]
    fn deadline_expiring_after_a_partial_write_prevents_the_next_write() {
        let mut written = Vec::new();
        let attempted = Cell::new(0);
        let prepared = Cell::new(0);
        let error = write_request_to(
            WriterFn(|pending: &[u8]| {
                written.extend_from_slice(&pending[..3]);
                Ok(3)
            }),
            b"request\n",
            || {
                prepared.set(prepared.get() + 1);
                if prepared.get() == 1 {
                    Ok(())
                } else {
                    Err(ErrorKind::TimedOut.into())
                }
            },
            || Ok(()),
            || attempted.set(attempted.get() + 1),
        )
        .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::TimedOut);
        assert_eq!(written, b"req");
        assert_eq!(attempted.get(), 1);
    }

    #[test]
    fn successful_write_returned_after_deadline_is_still_an_attempted_request() {
        let attempted = Cell::new(false);
        let mut written = Vec::new();
        let error = write_request_to(
            &mut written,
            b"request\n",
            || Ok(()),
            || Err(ErrorKind::TimedOut.into()),
            || attempted.set(true),
        )
        .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::TimedOut);
        assert_eq!(written, b"request\n");
        assert!(attempted.get());
    }

    #[test]
    fn failed_and_zero_writes_are_attempted_once() {
        for failure in [None, Some(ErrorKind::BrokenPipe)] {
            let attempted = Cell::new(0);
            let error = write_request_to(
                WriterFn(|_: &[u8]| match failure {
                    None => Ok(0),
                    Some(kind) => Err(kind.into()),
                }),
                b"request\n",
                || Ok(()),
                || Ok(()),
                || attempted.set(attempted.get() + 1),
            )
            .unwrap_err();
            assert_eq!(error.kind(), failure.unwrap_or(ErrorKind::WriteZero));
            assert_eq!(attempted.get(), 1);
        }
    }

    #[test]
    fn read_frame_reassembles_fragmented_utf8_and_stops_at_first_newline() {
        let response = "{\"text\":\"é\"}\n";
        let bytes = format!("{response}second frame\n");
        let result = read_response_frame(
            BufReader::with_capacity(1, Cursor::new(bytes)),
            || Ok(()),
            || Ok(()),
        )
        .unwrap();
        assert_eq!(result, response);
    }

    #[test]
    fn interrupted_reads_continue_the_same_response_frame() {
        let mut interrupted = false;
        let mut bytes = Cursor::new(b"response\n");
        let reader = ReaderFn(|buffer: &mut [u8]| {
            if !interrupted {
                interrupted = true;
                Err(ErrorKind::Interrupted.into())
            } else {
                bytes.read(buffer)
            }
        });
        let response =
            read_response_frame(BufReader::with_capacity(2, reader), || Ok(()), || Ok(())).unwrap();
        assert!(interrupted);
        assert_eq!(response, "response\n");
    }

    #[test]
    fn read_frame_requires_newline_and_valid_utf8() {
        for (bytes, kind) in [
            (&b"unterminated"[..], ErrorKind::UnexpectedEof),
            (&b"\xff\n"[..], ErrorKind::InvalidData),
        ] {
            let error = read_response_frame(Cursor::new(bytes), || Ok(()), || Ok(())).unwrap_err();
            assert_eq!(error.kind(), kind);
        }
        assert_eq!(
            read_response_frame(Cursor::new([]), || Ok(()), || Ok(())).unwrap(),
            ""
        );
    }

    #[test]
    fn completed_response_returned_after_deadline_is_rejected() {
        let error = read_response_frame(
            Cursor::new(b"response\n"),
            || Ok(()),
            || Err(ErrorKind::TimedOut.into()),
        )
        .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::TimedOut);
    }

    #[test]
    fn read_deadline_prevents_receiving_a_response() {
        let reader = ReaderFn(|_: &mut [u8]| panic!("expired deadline must not receive"));
        let error = read_response_frame(
            BufReader::new(reader),
            || Err(ErrorKind::TimedOut.into()),
            || panic!("expired deadline must return before deadline recheck"),
        )
        .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::TimedOut);
    }
}
