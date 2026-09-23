//! Common test utilities for E2E tests.
//!
//! This module provides:
//! - `schemas`: Typed data structures for JSON output validation
//! - `helpers`: Fluent test helpers and utilities
//! - `DaemonTestHarness`: Bridge lifecycle management for tests

#![allow(dead_code, unused_imports)]

pub mod fixture;
pub mod helpers;
pub mod schemas;

// Re-export commonly used items
pub use helpers::{
    get_function_address, get_function_addresses, ghidra, GhidraCommand, GhidraResult,
};
pub use schemas::Validate;

use anyhow::{Context, Result};
use std::path::PathBuf;
use std::sync::{Once, OnceLock};
use std::time::Duration;

/// Fresh Ghidra imports use the fixture's filename as their program name.
pub const FIXTURE_PROGRAM: &str = if cfg!(windows) {
    "sample_binary.exe"
} else {
    "sample_binary"
};

pub use fixture::fixture_binary;

static PROJECT: OnceLock<(tempfile::TempDir, PathBuf)> = OnceLock::new();

fn register_cleanup() {
    static REGISTER: Once = Once::new();
    REGISTER.call_once(|| {
        // SAFETY: The callback has C ABI, remains valid for the process lifetime,
        // and catches panics so none can unwind across the FFI boundary.
        assert_eq!(
            unsafe { libc::atexit(cleanup_suite) },
            0,
            "Cannot register suite cleanup"
        );
    });
}

extern "C" fn cleanup_suite() {
    let _ = std::panic::catch_unwind(|| {
        if let Some((directory, project)) = PROJECT.get() {
            // Rust statics are not dropped. Explicitly stop the suite's bridge
            // before removing its unique project, including on test failures.
            if ghidra_cli::ghidra::bridge::stop_bridge(project).is_ok() {
                let _ = std::fs::remove_file(project.with_extension("gpr"));
                let _ = std::fs::remove_dir_all(project.with_extension("rep"));
                let _ = std::fs::remove_dir_all(directory.path());
            }
        }
        fixture::cleanup();
    });
}

/// Each suite opens its own copy under a unique directory. Keep the source's
/// project basename so relocation does not require editing Ghidra metadata.
pub fn test_project() -> &'static str {
    register_cleanup();
    PROJECT
        .get_or_init(|| {
            let root = ghidra_cli::config::Config::load()
                .and_then(|config| config.get_project_dir())
                .expect("Could not determine project dir");
            std::fs::create_dir_all(&root).expect("Failed to create project directory");
            let root = dunce::canonicalize(root).expect("Failed to resolve project directory");
            let dir = tempfile::Builder::new()
                .prefix("ghidra-test-")
                .tempdir_in(root)
                .expect("Failed to create suite project directory");
            let project = dir.path().join(fixture::PROJECT_NAME);
            (dir, project)
        })
        .1
        .to_str()
        .expect("Test project path is not UTF-8")
}

/// Copy the run's closed, analyzed fixture once for this suite.
pub fn ensure_test_project(project: &str, program: &str) {
    static SETUP: OnceLock<std::result::Result<(), String>> = OnceLock::new();
    assert_eq!(
        project,
        test_project(),
        "Setup must use the suite's project"
    );
    assert_eq!(
        program, FIXTURE_PROGRAM,
        "Setup must use the fixture program"
    );
    require_ghidra();
    let setup = SETUP.get_or_init(|| {
        fixture::copy_analyzed_project(std::path::Path::new(project))
            .map_err(|error| format!("{error:#}"))
    });
    if let Err(error) = setup {
        panic!("Failed to prepare test project: {error}");
    }
}

/// Test harness that manages bridge lifecycle for a test suite.
///
/// The bridge is the Ghidra Java process running GhidraCliBridge.
/// Tests connect to it via TCP using BridgeClient.
pub struct DaemonTestHarness {
    port: u16,
    pid: Option<u32>,
    project: String,
    project_path: PathBuf,
}

impl DaemonTestHarness {
    /// Start bridge for testing. Blocks until bridge is ready or timeout.
    ///
    /// Calls bridge functions directly (not via CLI subprocess) so that
    /// detailed error messages (e.g., "program file(s) not found") propagate
    /// correctly to callers like try_start_daemon().
    pub fn new(project: &str, program: &str) -> Result<Self> {
        // Match CLI normalization before hashing discovery paths, including Windows separators.
        let project_path = std::path::absolute(
            ghidra_cli::config::Config::load()?
                .get_project_dir()
                .context("Could not determine default project dir")?
                .join(project),
        )?;

        // Load config to find Ghidra installation
        let config = ghidra_cli::config::Config::load().context("Failed to load config")?;
        let ghidra_install_dir = config
            .get_ghidra_install_dir()
            .context("Ghidra installation directory not configured")?;

        // Start the bridge directly via bridge API (not CLI subprocess).
        // This gives us detailed error messages from Ghidra in the Err value.
        let started = std::time::Instant::now();
        let port = ghidra_cli::ghidra::bridge::ensure_bridge_running(
            &project_path,
            &ghidra_install_dir,
            ghidra_cli::ghidra::bridge::BridgeStartMode::Process {
                program_name: program.to_string(),
            },
        )?;

        eprintln!(
            "[test setup] bridge start: {:.2}s",
            started.elapsed().as_secs_f64()
        );

        // Store PID now so Drop can wait for it even if restart deletes the PID file
        let pid = ghidra_cli::ghidra::bridge::read_pid_file(&project_path)
            .ok()
            .flatten();

        Ok(Self {
            port,
            pid,
            project: project.to_string(),
            project_path,
        })
    }

    /// Get a BridgeClient connected to the test bridge.
    pub fn client(&self) -> Result<ghidra_cli::ipc::client::BridgeClient> {
        Ok(ghidra_cli::ipc::client::BridgeClient::new(self.port))
    }

    /// Get project name.
    pub fn project(&self) -> &str {
        &self.project
    }

    /// Get bridge port.
    pub fn port(&self) -> u16 {
        self.port
    }
}

impl Drop for DaemonTestHarness {
    fn drop(&mut self) {
        let started = std::time::Instant::now();
        // Read current PID from file (may differ from self.pid if restart changed it)
        let file_pid = ghidra_cli::ghidra::bridge::read_pid_file(&self.project_path)
            .ok()
            .flatten();

        // Request graceful shutdown and wait for accepted work to finish.
        let _ = ghidra_cli::ghidra::bridge::stop_bridge(&self.project_path);

        // Collect all PIDs we need to wait for (original + current, deduplicated)
        let mut pids_to_wait: Vec<u32> = Vec::new();
        if let Some(pid) = file_pid {
            pids_to_wait.push(pid);
        }
        if let Some(pid) = self.pid {
            if !pids_to_wait.contains(&pid) {
                pids_to_wait.push(pid);
            }
        }

        // Wait for ALL known processes to fully exit and release project lock.
        let max_wait = if cfg!(windows) {
            Duration::from_secs(30)
        } else {
            Duration::from_secs(15)
        };
        for pid in &pids_to_wait {
            let start = std::time::Instant::now();
            while start.elapsed() < max_wait {
                if !ghidra_cli::ghidra::bridge::is_pid_alive(*pid) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(500));
            }
        }

        // Final cleanup of any remaining stale files
        let _ = ghidra_cli::ghidra::bridge::cleanup_stale_files(&self.project_path);
        eprintln!(
            "[test teardown] bridge stop: {:.2}s",
            started.elapsed().as_secs_f64()
        );
    }
}

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

/// Cache the actual diagnostic output, including failures, rather than poisoning
/// a Once after a panic. Every dependent test still fails with the same reason.
#[derive(Default)]
pub struct DoctorCheck(OnceLock<std::result::Result<std::process::Output, String>>);

impl DoctorCheck {
    pub fn require_with(
        &self,
        check: impl FnOnce() -> std::result::Result<std::process::Output, String>,
    ) {
        match self.0.get_or_init(check) {
            Ok(output) => assert_doctor_ready(output),
            Err(error) => panic!("Failed to run ghidra-cli doctor: {error}"),
        }
    }
}

/// The parent test process keeps its Ghidra/JDK configuration fixed. Tests that
/// change child environments or test doctor itself must invoke doctor directly.
pub fn require_ghidra() {
    static CHECK: DoctorCheck = DoctorCheck(OnceLock::new());
    CHECK.require_with(|| {
        let started = std::time::Instant::now();
        let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
            .arg("doctor")
            .output()
            .map_err(|error| error.to_string());
        eprintln!(
            "[test setup] doctor: {:.2}s",
            started.elapsed().as_secs_f64()
        );
        output
    });
}

#[macro_export]
macro_rules! require_ghidra {
    () => {
        $crate::common::require_ghidra();
    };
}

pub fn assert_doctor_ready(doctor: &std::process::Output) {
    let stdout = String::from_utf8_lossy(&doctor.stdout);
    let stderr = String::from_utf8_lossy(&doctor.stderr);
    assert!(
        doctor.status.success()
            && stdout.contains("analyzeHeadless: OK")
            && stdout.contains("Checking bridge script compiles... OK")
            && !stdout.contains("NOT FOUND")
            && !stdout.contains("FAILED"),
        "Ghidra not properly installed — tests MUST fail without Ghidra.\nStatus: {}\nstdout: {}\nstderr: {}",
        doctor.status, stdout, stderr
    );
}
