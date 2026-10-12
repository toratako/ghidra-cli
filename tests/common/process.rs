//! Bounded child-process waits and output capture independent of descendant EOF.

use anyhow::{Context, Result};
use std::time::Duration;

/// Run a CLI command with timeout.
///
/// Stdout uses Stdio::null() to avoid pipe handle inheritance on Windows, where
/// grandchild JVM processes inherit pipe handles and block wait_with_output() forever.
/// Stderr uses Stdio::inherit() so errors are visible in CI logs (inheriting the parent
/// fd doesn't create a pipe, so there's no blocking issue).
pub fn run_cli_with_timeout(
    bin: &std::path::Path,
    args: &[&str],
    timeout: Duration,
) -> Result<std::process::ExitStatus> {
    use std::process::{Command, Stdio};

    let mut child = Command::new(bin)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .context("Failed to spawn CLI command")?;

    wait_for_command(&mut child, timeout)
}

/// Capture output without waiting for EOF from a persistent JVM descendant.
/// The caller owns descendant cleanup (normally via DaemonTestHarness).
pub fn run_command_with_output(
    command: &mut std::process::Command,
    timeout: Duration,
) -> Result<std::process::Output> {
    use std::io::Read;
    use std::process::Stdio;

    let stdout = tempfile::NamedTempFile::new()?;
    let stderr = tempfile::NamedTempFile::new()?;
    eprintln!("[test command] {command:?}");
    let started = std::time::Instant::now();
    let mut child = command
        .stdin(Stdio::null())
        .stdout(stdout.reopen()?)
        .stderr(stderr.reopen()?)
        .spawn()
        .context("Failed to spawn command")?;
    let status = wait_for_command(&mut child, timeout);
    // Read a bounded snapshot with independent cursors. Descendants may still
    // hold or write these files after the CLI exits.
    let read = |file: &tempfile::NamedTempFile| -> std::io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        file.reopen()?
            .take(file.as_file().metadata()?.len())
            .read_to_end(&mut bytes)?;
        Ok(bytes)
    };
    let stdout = read(&stdout)?;
    let stderr = read(&stderr)?;
    eprintln!(
        "[test command] finished in {:.2}s: {status:?}",
        started.elapsed().as_secs_f64()
    );
    let status = status.with_context(|| {
        format!(
            "Command {command:?}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&stdout),
            String::from_utf8_lossy(&stderr)
        )
    })?;
    Ok(std::process::Output {
        status,
        stdout,
        stderr,
    })
}

fn wait_for_command(
    child: &mut std::process::Child,
    timeout: Duration,
) -> Result<std::process::ExitStatus> {
    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => {
                if start.elapsed() > timeout {
                    eprintln!("Command timed out after {}s, killing...", timeout.as_secs());
                    let _ = child.kill();
                    let _ = child.wait();
                    anyhow::bail!("Command timed out after {}s", timeout.as_secs());
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => anyhow::bail!("Error waiting for command: {}", e),
        }
    }
}
