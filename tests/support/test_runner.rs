//! Own run-scoped fixtures while Cargo executes its test targets normally.

use anyhow::{Context, Result};
use std::process::{Command, ExitCode};

fn run() -> Result<ExitCode> {
    let run_dir = tempfile::Builder::new()
        .prefix("ghidra-test-run-")
        .tempdir()?;
    let started = std::time::Instant::now();
    let status = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
        .arg("test")
        .args(std::env::args_os().skip(1))
        .env("GHIDRA_TEST_RUN_DIR", run_dir.path())
        .status()
        .context("Failed to run cargo test")?;
    eprintln!(
        "[test run] completed in {:.2}s",
        started.elapsed().as_secs_f64()
    );
    // Wait for all suites before deleting their shared, closed fixture source.
    run_dir
        .close()
        .context("Failed to remove test run fixtures")?;
    Ok(ExitCode::from(status.code().unwrap_or(1) as u8))
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("test-run: {error:#}");
            ExitCode::FAILURE
        }
    }
}
