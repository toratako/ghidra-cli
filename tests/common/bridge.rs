//! Ownership and shutdown of a real Ghidra bridge.

use anyhow::{Context, Result};
use std::path::PathBuf;
use std::time::Duration;

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
        let installation = config
            .get_ghidra_installation()
            .context("Ghidra installation not configured")?;

        // Start the bridge directly via bridge API (not CLI subprocess).
        // This gives us detailed error messages from Ghidra in the Err value.
        let started = std::time::Instant::now();
        let port = ghidra_cli::ghidra::bridge::ensure_bridge_running(
            &project_path,
            &installation,
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

/// Select an already-created temporary program for a test, then restore the
/// suite program and delete the temporary file before resuming any test panic.
/// Setup and cleanup failures remain test failures; deletion requires restoration
/// to succeed. The caller owns fixture creation and the bridge's lifetime.
pub fn with_temporary_program(
    client: &ghidra_cli::ipc::client::BridgeClient,
    program: &str,
    restore_program: &str,
    check: impl FnOnce(),
) {
    client.open_program(program).unwrap();
    let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(check));
    client.open_program(restore_program).unwrap();
    client.program_delete(program).unwrap();
    if let Err(panic) = checked {
        std::panic::resume_unwind(panic);
    }
}
