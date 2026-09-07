//! Common test utilities for E2E tests.
//!
//! This module provides:
//! - `schemas`: Typed data structures for JSON output validation
//! - `helpers`: Fluent test helpers and utilities
//! - `DaemonTestHarness`: Bridge lifecycle management for tests

#![allow(dead_code, unused_imports)]

pub mod helpers;
pub mod schemas;

// Re-export commonly used items
pub use helpers::{
    get_function_address, get_function_addresses, ghidra, normalize_json, normalize_output,
    GhidraCommand, GhidraResult,
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

static FIXTURE: OnceLock<tempfile::TempDir> = OnceLock::new();
static PROJECT: OnceLock<PathBuf> = OnceLock::new();

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
        if let Some(project) = PROJECT.get() {
            // Rust statics are not dropped. Explicitly stop the suite's bridge
            // before removing its unique project, including on test failures.
            if ghidra_cli::ghidra::bridge::stop_bridge(project).is_ok() {
                let _ = std::fs::remove_file(project.with_extension("gpr"));
                let _ = std::fs::remove_dir_all(project.with_extension("rep"));
            }
        }
        if let Some(fixture) = FIXTURE.get() {
            let _ = std::fs::remove_dir_all(fixture.path());
        }
    });
}

/// Build the host-native fixture once per test executable, outside the source tree.
pub fn fixture_binary() -> PathBuf {
    register_cleanup();
    let dir = FIXTURE.get_or_init(|| {
        let dir = tempfile::Builder::new()
            .prefix("ghidra-fixture-")
            .tempdir()
            .expect("Failed to create fixture directory");
        let output = std::process::Command::new("rustc")
            .args(["--edition", "2021", "-C", "strip=debuginfo"])
            .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sample_binary.rs"))
            .arg("-o")
            .arg(dir.path().join(FIXTURE_PROGRAM))
            .output()
            .expect("Failed to run rustc for test fixture");
        assert!(
            output.status.success(),
            "Fixture compilation failed: {}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        dir
    });
    dir.path().join(FIXTURE_PROGRAM)
}

/// Each test executable and run gets a fresh project, so mutations never affect
/// another suite or a later run. Absolute paths also isolate CLI config changes.
pub fn test_project() -> &'static str {
    register_cleanup();
    PROJECT
        .get_or_init(|| {
            ghidra_cli::config::Config::load()
                .and_then(|config| config.get_project_dir())
                .expect("Could not determine project dir")
                .join(format!("ghidra-test-{}", uuid::Uuid::new_v4()))
        })
        .to_str()
        .expect("Test project path is not UTF-8")
}

/// Import and analyze once for this suite. Setup failures must fail the tests.
pub fn ensure_test_project(project: &str, program: &str) {
    static SETUP: Once = Once::new();
    SETUP.call_once(|| {
        let binary = fixture_binary();
        let projects_dir = ghidra_cli::config::Config::load()
            .and_then(|config| config.get_project_dir())
            .expect("Could not determine project dir");

        eprintln!("=== Setting up test project (durable import + analysis) ===");
        eprintln!("Project dir: {:?}", projects_dir);

        // Step 1: Import the binary
        //
        // IMPORTANT: We use Stdio::null() instead of piped stdout/stderr.
        // On Windows, `ghidra import` spawns analyzeHeadless.bat → cmd.exe → java.exe.
        // If we use piped I/O, the grandchild JVM inherits the pipe handles.
        // When ghidra.exe exits, the pipe stays open (JVM holds inherited handles),
        // so output()/wait_with_output() blocks forever. Using null avoids this.
        eprintln!("Step 1: Importing binary {:?} ...", binary);
        let ghidra_bin = assert_cmd::cargo::cargo_bin!("ghidra");
        let import_status = run_cli_with_timeout(
            ghidra_bin,
            &[
                "import",
                binary.to_str().unwrap(),
                "--project",
                project,
                "--program",
                program,
            ],
            Duration::from_secs(300),
        );
        let import_status = import_status.expect("Test fixture import failed");
        assert!(
            import_status.success(),
            "Test fixture import failed: {import_status}"
        );

        // Step 2: Stop the persistent bridge started by `ghidra import`.
        // The fresh-project one-shot importer already analyzed and durably
        // committed the program before this bridge started, so an additional
        // `ghidra analyze` here is both redundant and expensive. Stopping the
        // bridge keeps test binaries isolated and lets DaemonTestHarness start a
        // fresh Process-mode bridge against the committed project.
        eprintln!("Step 2: Stopping bridge after durable import...");
        let stop_status = run_cli_with_timeout(
            ghidra_bin,
            &["stop", "--project", project],
            Duration::from_secs(120),
        );
        let stop_status = stop_status.expect("Failed to stop fixture import bridge");
        assert!(
            stop_status.success(),
            "Failed to stop fixture import bridge: {stop_status}"
        );

        eprintln!("=== Test project setup complete ===");
    });
}

/// Test harness that manages bridge lifecycle for a test suite.
///
/// The bridge is the Ghidra Java process running GhidraCliBridge.
/// Tests connect to it via TCP using BridgeClient.
pub struct DaemonTestHarness {
    port: u16,
    pid: Option<u32>,
    data_dir: PathBuf,
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
        let data_dir = get_unique_data_dir();

        // Resolve the project path (must match the CLI's default via get_project_dir)
        let project_path = ghidra_cli::config::Config::load()?
            .get_project_dir()
            .context("Could not determine default project dir")?
            .join(project);

        // Load config to find Ghidra installation
        let config = ghidra_cli::config::Config::load().context("Failed to load config")?;
        let ghidra_install_dir = config
            .ghidra_install_dir
            .clone()
            .or_else(|| config.get_ghidra_install_dir().ok())
            .context("Ghidra installation directory not configured")?;

        // Start the bridge directly via bridge API (not CLI subprocess).
        // This gives us detailed error messages from Ghidra in the Err value.
        let port = ghidra_cli::ghidra::bridge::ensure_bridge_running(
            &project_path,
            &ghidra_install_dir,
            ghidra_cli::ghidra::bridge::BridgeStartMode::Process {
                program_name: program.to_string(),
            },
        )?;

        // Store PID now so Drop can wait for it even if restart deletes the PID file
        let pid = ghidra_cli::ghidra::bridge::read_pid_file(&project_path)
            .ok()
            .flatten();

        Ok(Self {
            port,
            pid,
            data_dir,
            project: project.to_string(),
            project_path,
        })
    }

    /// Get a BridgeClient connected to the test bridge.
    pub fn client(&self) -> Result<ghidra_cli::ipc::client::BridgeClient> {
        Ok(ghidra_cli::ipc::client::BridgeClient::new(self.port))
    }

    /// Get data directory for this daemon instance.
    pub fn data_dir(&self) -> &PathBuf {
        &self.data_dir
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
        // Read current PID from file (may differ from self.pid if restart changed it)
        let file_pid = ghidra_cli::ghidra::bridge::read_pid_file(&self.project_path)
            .ok()
            .flatten();

        // Use stop_bridge for proper graceful shutdown + force-kill
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
        let _ = std::fs::remove_dir_all(&self.data_dir);
    }
}

/// Generate unique data directory for test isolation.
fn get_unique_data_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ghidra-data-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).expect("Failed to create test data dir");
    dir
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
                std::thread::sleep(Duration::from_secs(1));
            }
            Err(e) => anyhow::bail!("Error waiting for command: {}", e),
        }
    }
}

/// Require Ghidra to be available for tests to proceed.
#[macro_export]
macro_rules! require_ghidra {
    () => {
        let doctor = assert_cmd::cargo::cargo_bin_cmd!("ghidra")
            .arg("doctor")
            .output()
            .expect("Failed to run ghidra doctor");

        $crate::common::assert_doctor_ready(&doctor);
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
