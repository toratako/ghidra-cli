//! Ghidra Bridge - manages a persistent Ghidra Java bridge process.
//!
//! The bridge runs a GhidraCliBridge.java script via `analyzeHeadless` that
//! starts a TCP socket server. The CLI connects directly to this server
//! to execute commands. No intermediate daemon process is needed.

use std::io::Write;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use tracing::{debug, info, warn};

use crate::ipc::client::BridgeClient;

mod headless;
mod import;
mod sources;
mod startup;
pub use headless::{compile_check, find_headless_script};
pub use import::{import_oneshot, OneShotImportOptions};
pub use startup::start_bridge;

/// Which program, if any, the bridge opens before reporting readiness.
pub enum BridgeStartMode {
    /// Open an existing program in the project
    Process { program_name: String },
    /// Open the project without loading a specific program
    Project,
}

/// Grace period for a bridge to drain accepted program jobs and let Ghidra
/// close the project cleanly before the CLI falls back to process termination.
const DEFAULT_SHUTDOWN_TIMEOUT_SECS: u64 = 300;

fn parse_shutdown_timeout(raw: Option<&str>) -> Option<Duration> {
    let seconds = raw
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_SHUTDOWN_TIMEOUT_SECS);
    (seconds > 0).then(|| Duration::from_secs(seconds))
}

fn shutdown_timeout() -> Option<Duration> {
    parse_shutdown_timeout(std::env::var("GHIDRA_CLI_SHUTDOWN_TIMEOUT").ok().as_deref())
}

/// Get the data directory for bridge port/PID files.
pub fn get_data_dir() -> Result<PathBuf> {
    let dir = dirs::data_local_dir()
        .ok_or_else(|| anyhow::anyhow!("Could not determine data directory"))?
        .join("ghidra-cli");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Compute MD5 hash of project path for file naming.
fn project_hash(project_path: &Path) -> String {
    format!(
        "{:x}",
        md5::compute(project_path.to_string_lossy().as_bytes())
    )
}

/// Get the port file path for a project.
pub fn port_file_path(project_path: &Path) -> Result<PathBuf> {
    let data_dir = get_data_dir()?;
    let hash = project_hash(project_path);
    Ok(data_dir.join(format!("bridge-{}.port", hash)))
}

/// Get the PID file path for a project.
pub fn pid_file_path(project_path: &Path) -> Result<PathBuf> {
    let data_dir = get_data_dir()?;
    let hash = project_hash(project_path);
    Ok(data_dir.join(format!("bridge-{}.pid", hash)))
}

/// Read the port from the port file.
pub fn read_port_file(project_path: &Path) -> Result<Option<u16>> {
    let path = port_file_path(project_path)?;
    if !path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(&path)?;
    let port: u16 = content
        .trim()
        .parse()
        .context("Invalid port in port file")?;
    Ok(Some(port))
}

/// Read the PID from the PID file.
pub fn read_pid_file(project_path: &Path) -> Result<Option<u32>> {
    let path = pid_file_path(project_path)?;
    if !path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(&path)?;
    let pid: u32 = content.trim().parse().context("Invalid PID in PID file")?;
    Ok(Some(pid))
}

/// Check if a process with the given PID is alive.
pub fn is_pid_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::kill(pid as i32, 0) == 0 }
    }
    #[cfg(windows)]
    {
        use std::process::Command;
        Command::new("tasklist")
            .args(["/FI", &format!("PID eq {}", pid)])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains(&pid.to_string()))
            .unwrap_or(false)
    }
}

/// Clean up stale port and PID files.
pub fn cleanup_stale_files(project_path: &Path) -> Result<()> {
    let port_path = port_file_path(project_path)?;
    let pid_path = pid_file_path(project_path)?;
    if port_path.exists() {
        std::fs::remove_file(&port_path).ok();
    }
    if pid_path.exists() {
        std::fs::remove_file(&pid_path).ok();
    }

    // Remove Ghidra project lock files left behind after force-kill.
    // Ghidra creates {project_name}.lock and {project_name}.lock~ as siblings
    // of the project directory. If the JVM is killed, these aren't cleaned up
    // and the next analyzeHeadless invocation may refuse to open the project.
    if let Some(project_name) = project_path.file_name() {
        if let Some(parent) = project_path.parent() {
            let lock_name = format!("{}.lock", project_name.to_string_lossy());
            let lock_path = parent.join(&lock_name);
            let lock_tilde = parent.join(format!("{}~", lock_name));
            if lock_path.exists() {
                debug!("Removing stale Ghidra lock: {:?}", lock_path);
                std::fs::remove_file(&lock_path).ok();
            }
            if lock_tilde.exists() {
                debug!("Removing stale Ghidra lock: {:?}", lock_tilde);
                std::fs::remove_file(&lock_tilde).ok();
            }
        }
    }

    Ok(())
}

/// RAII guard that removes the startup lock file on drop.
struct StartupLockGuard {
    path: PathBuf,
}

impl Drop for StartupLockGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Acquire a per-project startup lock so concurrent callers don't each spawn
/// their own analyzeHeadless (which would cause "Unable to lock project!").
///
/// The lock file contains the holder's PID so stale locks (from crashed
/// processes) are detected and cleaned up automatically.
///
/// Blocks until the lock is acquired or the 60-second timeout expires.
fn acquire_startup_lock(project_path: &Path) -> Result<StartupLockGuard> {
    let data_dir = get_data_dir()?;
    let hash = project_hash(project_path);
    let lock_path = data_dir.join(format!("bridge-{}.starting", hash));
    let pid = std::process::id().to_string();
    let deadline = std::time::Instant::now() + Duration::from_secs(60);

    loop {
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
        {
            Ok(mut f) => {
                let _ = f.write_all(pid.as_bytes());
                debug!("Acquired startup lock: {:?}", lock_path);
                return Ok(StartupLockGuard { path: lock_path });
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // If the holder process is dead, remove the stale lock and retry.
                if let Ok(content) = std::fs::read_to_string(&lock_path) {
                    if let Ok(holder_pid) = content.trim().parse::<u32>() {
                        if !is_pid_alive(holder_pid) {
                            debug!("Removing stale startup lock from dead PID {}", holder_pid);
                            let _ = std::fs::remove_file(&lock_path);
                            continue;
                        }
                    }
                }
                if std::time::Instant::now() > deadline {
                    anyhow::bail!(
                        "Timed out waiting for bridge startup lock \
                         (another process may be starting the bridge)"
                    );
                }
                debug!("Waiting for startup lock...");
                std::thread::sleep(Duration::from_millis(200));
            }
            Err(e) => return Err(e.into()),
        }
    }
}

/// Check if a bridge is running for the given project.
///
/// Verifies: port file exists, PID is alive, TCP connect succeeds.
/// Returns `Some(port)` if running, `None` otherwise. Callers use the returned port
/// directly, avoiding a separate read_port_file call (TOCTOU elimination).
pub fn is_bridge_running(project_path: &Path) -> Option<u16> {
    let port = match read_port_file(project_path) {
        Ok(Some(p)) => p,
        _ => return None,
    };

    let pid = match read_pid_file(project_path) {
        Ok(Some(p)) => p,
        _ => return None,
    };

    if !is_pid_alive(pid) {
        return None;
    }

    // Verify TCP connect (with timeout to avoid long hangs on Windows)
    let addr: std::net::SocketAddr = format!("127.0.0.1:{}", port).parse().ok()?;
    TcpStream::connect_timeout(&addr, Duration::from_secs(5))
        .map(|_| Some(port))
        .unwrap_or(None)
}

/// Ensure a bridge is running for the given project.
/// Returns the port number to connect to.
///
/// Safe for concurrent callers: uses a per-project startup lock so that
/// only one process spawns analyzeHeadless. The others wait and reuse the
/// bridge that the winner started.
pub fn ensure_bridge_running(
    project_path: &Path,
    ghidra_install_dir: &Path,
    mode: BridgeStartMode,
) -> Result<u16> {
    // Fast path (no lock): if the bridge is clearly running, return immediately.
    if let Some(port) = is_bridge_running(project_path) {
        info!("Bridge already running on port {}", port);
        return Ok(port);
    }

    // Slow path: acquire the per-project startup lock so that concurrent
    // callers don't each launch their own analyzeHeadless (which would fail
    // with "Unable to lock project!" because Ghidra uses an exclusive lock).
    let _lock = acquire_startup_lock(project_path)?;

    // Re-check under the lock: another process may have started the bridge
    // while we were waiting.
    if let Some(port) = is_bridge_running(project_path) {
        info!(
            "Bridge already running on port {} (detected after lock)",
            port
        );
        return Ok(port);
    }

    // Clean up any stale port/pid/lock files before starting fresh.
    cleanup_stale_files(project_path)?;
    start_bridge(project_path, ghidra_install_dir, mode)
}

/// Stop the bridge for a project.
pub fn stop_bridge(project_path: &Path) -> Result<()> {
    // Read PID before sending TCP shutdown so we can wait for the JVM to
    // fully exit (release project lock) before returning.
    let pid = read_pid_file(project_path).ok().flatten();

    // Try graceful shutdown via TCP using BridgeClient
    if let Ok(Some(port)) = read_port_file(project_path) {
        let client = BridgeClient::new(port);
        if let Ok(()) = client.shutdown() {
            debug!("Graceful shutdown sent");
        }
    }

    // Wait for the process to drain accepted jobs and exit cleanly, then
    // force-kill only after the configured grace period. A value of 0 waits
    // indefinitely, which is useful for very large analysis jobs.
    if let Some(pid) = pid {
        let timed_out = match shutdown_timeout() {
            Some(timeout) => {
                let deadline = std::time::Instant::now() + timeout;
                while is_pid_alive(pid) && std::time::Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(100));
                }
                is_pid_alive(pid)
            }
            None => {
                while is_pid_alive(pid) {
                    std::thread::sleep(Duration::from_millis(100));
                }
                false
            }
        };

        if timed_out {
            warn!(
                "Bridge {} did not finish draining before GHIDRA_CLI_SHUTDOWN_TIMEOUT; killing as fallback",
                pid
            );
            #[cfg(unix)]
            unsafe {
                // Kill the whole process group (the JVM was spawned into the
                // analyzeHeadless wrapper's group). Fall back to a single-pid
                // kill if the group id can't be resolved.
                let pgid = libc::getpgid(pid as i32);
                if pgid > 0 {
                    libc::killpg(pgid, libc::SIGTERM);
                } else {
                    libc::kill(pid as i32, libc::SIGTERM);
                }
            }
            #[cfg(windows)]
            {
                let _ = std::process::Command::new("taskkill")
                    .args(["/PID", &pid.to_string(), "/F", "/T"])
                    .output();
            }

            // Wait for the process to actually die after SIGTERM/taskkill.
            // Without this, the JVM may still hold the project lock when the
            // next bridge tries to start (causes intermittent CI failures).
            for _ in 0..100 {
                if !is_pid_alive(pid) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }

            // Last resort: SIGKILL if SIGTERM wasn't enough
            #[cfg(unix)]
            if is_pid_alive(pid) {
                warn!("SIGKILL bridge process {} (SIGTERM didn't work)", pid);
                unsafe {
                    let pgid = libc::getpgid(pid as i32);
                    if pgid > 0 {
                        libc::killpg(pgid, libc::SIGKILL);
                    } else {
                        libc::kill(pid as i32, libc::SIGKILL);
                    }
                }
                // Brief wait for SIGKILL to take effect
                for _ in 0..20 {
                    if !is_pid_alive(pid) {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
    }

    // Clean up files
    cleanup_stale_files(project_path)?;

    info!("Bridge stopped");
    Ok(())
}

/// Get bridge status for a project.
pub fn bridge_status(project_path: &Path) -> Result<BridgeStatus> {
    let port = read_port_file(project_path)?;
    let pid = read_pid_file(project_path)?;

    if let (Some(port), Some(pid)) = (port, pid) {
        if is_pid_alive(pid) {
            let client = BridgeClient::new(port);
            if client.ping().unwrap_or(false) {
                return Ok(BridgeStatus::Running { port, pid });
            }
        }
        // Stale files
        cleanup_stale_files(project_path).ok();
    }

    Ok(BridgeStatus::Stopped)
}

/// Bridge status
#[derive(Debug)]
pub enum BridgeStatus {
    Running { port: u16, pid: u32 },
    Stopped,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shutdown_timeout_defaults_and_supports_unbounded_wait() {
        assert_eq!(
            parse_shutdown_timeout(None),
            Some(Duration::from_secs(DEFAULT_SHUTDOWN_TIMEOUT_SECS))
        );
        assert_eq!(
            parse_shutdown_timeout(Some(" 45 ")),
            Some(Duration::from_secs(45))
        );
        assert_eq!(parse_shutdown_timeout(Some("0")), None);
        assert_eq!(
            parse_shutdown_timeout(Some("invalid")),
            Some(Duration::from_secs(DEFAULT_SHUTDOWN_TIMEOUT_SECS))
        );
    }
}
