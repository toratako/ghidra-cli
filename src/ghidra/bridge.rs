//! Ghidra Bridge - manages a persistent Ghidra Java bridge process.
//!
//! The bridge runs a GhidraCliBridge.java script via `analyzeHeadless` that
//! starts a TCP socket server. The CLI connects directly to this server
//! to execute commands. No intermediate daemon process is needed.

use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use tracing::info;

use crate::ipc::client::BridgeClient;

pub mod archive;
pub mod diagnostics;
mod headless;
mod import;
mod sources;
mod startup;
pub use headless::compile_check;
pub use import::{import_oneshot, OneShotImportOptions};

/// Which program, if any, the bridge opens before reporting readiness.
pub enum BridgeStartMode {
    /// Open an existing program in the project
    Process { program_name: String },
    /// Open the project without loading a specific program
    Project,
}

/// Budget for requesting shutdown and letting Ghidra drain accepted jobs and
/// close the project. Expiry preserves the live process and its project state.
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
    let dir = data_dir_path()?;
    std::fs::create_dir_all(&dir)
        .map_err(|e| crate::error::path_io("bridge.state_directory", &dir, e))?;
    Ok(dir)
}

/// Resolve without creating anything, so doctor can report inaccessible paths.
pub fn data_dir_path() -> Result<PathBuf> {
    Ok(dirs::data_local_dir()
        .ok_or_else(|| anyhow::anyhow!("Could not determine data directory"))?
        .join("ghidra-cli"))
}

/// Use the same project identity for discovery and startup locking.
fn project_hash(project_path: &Path) -> Result<String> {
    let absolute = std::path::absolute(project_path)?;
    // The bare project path usually does not exist: Ghidra stores its database
    // in the sibling .rep directory. Identify that directory without folding
    // distinct names on case-sensitive volumes.
    let identity = match repository_identity(&absolute.with_added_extension("rep")) {
        Ok(identity) => identity,
        // Missing projects still support status, save, and stale-file cleanup.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            absolute.to_string_lossy().as_bytes().to_vec()
        }
        Err(error) => return Err(error.into()),
    };
    Ok(format!("{:x}", md5::compute(identity)))
}

#[cfg(not(windows))]
fn repository_identity(repository: &Path) -> std::io::Result<Vec<u8>> {
    repository_path_identity(repository)
}

fn repository_path_identity(repository: &Path) -> std::io::Result<Vec<u8>> {
    let mut identity = b"repository-directory\0".to_vec();
    identity.extend_from_slice(
        dunce::canonicalize(repository)?
            .to_string_lossy()
            .as_bytes(),
    );
    Ok(identity)
}

#[cfg(windows)]
fn repository_identity(repository: &Path) -> std::io::Result<Vec<u8>> {
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FileIdInfo, GetFileInformationByHandle, GetFileInformationByHandleEx,
        BY_HANDLE_FILE_INFORMATION, FILE_FLAG_BACKUP_SEMANTICS, FILE_ID_INFO,
    };

    let directory = std::fs::OpenOptions::new()
        .access_mode(0)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(repository)?;
    let mut info = std::mem::MaybeUninit::<FILE_ID_INFO>::uninit();
    // SAFETY: directory owns a live handle, and info has the exact type and
    // buffer size required by FileIdInfo. Read it only after a successful call.
    if unsafe {
        GetFileInformationByHandleEx(
            directory.as_raw_handle(),
            FileIdInfo,
            info.as_mut_ptr().cast(),
            std::mem::size_of::<FILE_ID_INFO>() as u32,
        )
    } != 0
    {
        // SAFETY: GetFileInformationByHandleEx initialized FILE_ID_INFO.
        let info = unsafe { info.assume_init() };
        if info.FileId.Identifier != [0; 16] {
            let mut identity = b"windows-repository\0".to_vec();
            identity.extend_from_slice(&info.VolumeSerialNumber.to_le_bytes());
            identity.extend_from_slice(&info.FileId.Identifier);
            return Ok(identity);
        }
    }

    // FAT and some network filesystems only provide the older 64-bit file ID.
    // Prefer 128 bits above because 64-bit IDs are not unique on ReFS.
    let mut info = std::mem::MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
    // SAFETY: directory is live and info points to the required writable type.
    if unsafe { GetFileInformationByHandle(directory.as_raw_handle(), info.as_mut_ptr()) } != 0 {
        // SAFETY: GetFileInformationByHandle initialized the entire structure.
        let info = unsafe { info.assume_init() };
        if info.nFileIndexHigh != 0 || info.nFileIndexLow != 0 {
            let mut identity = b"windows-repository-64\0".to_vec();
            identity.extend_from_slice(&info.dwVolumeSerialNumber.to_le_bytes());
            identity.extend_from_slice(&info.nFileIndexHigh.to_le_bytes());
            identity.extend_from_slice(&info.nFileIndexLow.to_le_bytes());
            return Ok(identity);
        }
    }

    // A zero/unsupported ID must never collapse unrelated projects to one key.
    repository_path_identity(repository)
}

/// Get the port file path for a project.
pub fn port_file_path(project_path: &Path) -> Result<PathBuf> {
    let data_dir = get_data_dir()?;
    let hash = project_hash(project_path)?;
    Ok(data_dir.join(format!("bridge-{}.port", hash)))
}

/// Get the PID file path for a project.
pub fn pid_file_path(project_path: &Path) -> Result<PathBuf> {
    let data_dir = get_data_dir()?;
    let hash = project_hash(project_path)?;
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
    if pid == 0 || pid > i32::MAX as u32 {
        return true; // Invalid identities are never evidence that cleanup is safe.
    }
    #[cfg(unix)]
    {
        unsafe {
            libc::kill(pid as i32, 0) == 0
                || std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
        }
    }
    #[cfg(windows)]
    {
        use std::process::Command;
        Command::new("tasklist")
            .args(["/FI", &format!("PID eq {}", pid), "/FO", "CSV", "/NH"])
            .output()
            .map(|output| {
                !output.status.success()
                    || String::from_utf8_lossy(&output.stdout).lines().any(|line| {
                        line.split("\",\"")
                            .nth(1)
                            .and_then(|field| field.trim_matches('"').parse::<u32>().ok())
                            == Some(pid)
                    })
            })
            .unwrap_or(true)
    }
}

/// Clean up discovery for a confirmed dead process under the lifecycle lock.
#[allow(dead_code)] // Public library recovery API; the CLI uses locked internal cleanup.
pub fn cleanup_stale_files(project_path: &Path) -> Result<()> {
    let _lock = acquire_startup_lock(project_path)?;
    cleanup_stale_files_locked(project_path)
}

fn cleanup_stale_files_locked(project_path: &Path) -> Result<()> {
    let pid = read_pid_file(project_path)?;
    if let Some(pid) = pid {
        anyhow::ensure!(
            !is_pid_alive(pid),
            "Bridge process {pid} is still alive; preserving discovery and project locks"
        );
    }
    // Ghidra owns its project lock artifacts. Even a dead recorded PID cannot
    // establish that a GUI or another process has not acquired the project since.
    remove_if_present(&port_file_path(project_path)?)?;
    remove_if_present(&pid_file_path(project_path)?)?;
    Ok(())
}

fn remove_if_present(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// The stable file must never be unlinked: otherwise waiters could lock a
/// detached inode while a new caller locks its replacement. Closing releases
/// the OS lock, including when the holder crashes before writing anything.
struct StartupLockGuard {
    _file: std::fs::File,
}

fn acquire_startup_lock(project_path: &Path) -> Result<StartupLockGuard> {
    acquire_lifecycle_lock(project_path, None)
}

fn acquire_lifecycle_lock(
    project_path: &Path,
    deadline: Option<std::time::Instant>,
) -> Result<StartupLockGuard> {
    let lock_path =
        get_data_dir()?.join(format!("bridge-{}.starting", project_hash(project_path)?));
    let timeout = deadline.map_or(Duration::from_secs(60), |end| {
        end.saturating_duration_since(std::time::Instant::now())
            .min(Duration::from_secs(60))
    });
    acquire_file_lock(&lock_path, timeout)
}

fn acquire_file_lock(path: &Path, timeout: Duration) -> Result<StartupLockGuard> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(|e| crate::error::path_io("bridge.lifecycle_lock", path, e))?;
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(StartupLockGuard { _file: file }),
            Err(std::fs::TryLockError::WouldBlock) => {
                let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                anyhow::ensure!(
                    !remaining.is_zero(),
                    "Timed out waiting for bridge lifecycle lock"
                );
                std::thread::sleep(remaining.min(Duration::from_millis(100)));
            }
            Err(std::fs::TryLockError::Error(error)) => {
                return Err(crate::error::path_io("bridge.lifecycle_lock", path, error).into());
            }
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
    start_bridge(project_path, ghidra_install_dir, mode)
}

/// Explicit startup shares the same lifecycle lock and recovery checks.
pub fn start_bridge(
    project_path: &Path,
    ghidra_install_dir: &Path,
    mode: BridgeStartMode,
) -> Result<u16> {
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

    // Clean up stale discovery files before starting fresh.
    cleanup_stale_files_locked(project_path)?;
    startup::start_bridge(project_path, ghidra_install_dir, mode)
}

/// Stop the bridge for a project.
pub fn stop_bridge(project_path: &Path) -> Result<()> {
    stop_bridge_with_timeout(project_path, shutdown_timeout())
}

fn stop_bridge_with_timeout(project_path: &Path, timeout: Option<Duration>) -> Result<()> {
    stop_bridge_then(project_path, timeout, || Ok(()))
}

fn stop_bridge_then<T>(
    project_path: &Path,
    timeout: Option<Duration>,
    after_stop: impl FnOnce() -> Result<T>,
) -> Result<T> {
    stop_bridge_with(
        project_path,
        timeout,
        is_pid_alive,
        |port, deadline| BridgeClient::new(port).shutdown_with_deadline(deadline),
        std::time::Instant::now,
        std::thread::sleep,
        after_stop,
    )
}

/// Stop and delete under the CLI lifecycle lock and Ghidra's own project lock.
pub fn delete_project(project_path: &Path, ghidra_install_dir: &Path) -> Result<bool> {
    stop_bridge_then(project_path, shutdown_timeout(), || {
        let Some(paths) = super::project::ProjectPaths::new(project_path) else {
            return Ok(false);
        };
        if !paths.exists() {
            return Ok(false);
        }
        // The bootstrap opens its own disposable project so it can acquire the
        // target's Ghidra lock without opening any target database files.
        let work = tempfile::Builder::new()
            .prefix("ghidra-cli-delete-")
            .tempdir()?;
        let result = import::run_bootstrap(
            &work.path().join("deletion"),
            ghidra_install_dir,
            &serde_json::json!({"delete_project": std::path::absolute(project_path)?}),
            None,
        )?;
        result["deleted"]
            .as_bool()
            .context("Deletion receipt did not confirm the result")
    })
}

// Keep shutdown dependencies injectable so lifecycle tests can control PID
// checks, acknowledgements, and elapsed time without a blocking mock server.
fn stop_bridge_with<T>(
    project_path: &Path,
    timeout: Option<Duration>,
    mut check_alive: impl FnMut(u32) -> bool,
    mut request_shutdown: impl FnMut(u16, Option<std::time::Instant>) -> Result<()>,
    mut now: impl FnMut() -> std::time::Instant,
    mut sleep: impl FnMut(Duration),
    after_stop: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let deadline = timeout.map(|timeout| now() + timeout);
    let timeout_error = || {
        anyhow::Error::new(crate::ipc::protocol::BridgeTimeoutError {
            command: "shutdown".to_string(),
            timeout_secs: timeout.map_or(0, |timeout| timeout.as_secs()),
        })
    };
    let _lock = acquire_lifecycle_lock(project_path, deadline).map_err(|error| {
        if deadline.is_some_and(|end| now() >= end) {
            timeout_error().context("Shutdown deadline expired waiting for the lifecycle lock; preserving project state")
        } else { error }
    })?;
    let pid = read_pid_file(project_path)?;
    if let Some(pid) = pid.filter(|pid| check_alive(*pid)) {
        let port = read_port_file(project_path)?.ok_or_else(||
            anyhow::anyhow!("Bridge process {pid} is alive but its port is unavailable; preserving project state"))?;
        let shutdown_result = request_shutdown(port, deadline);
        if shutdown_result.as_ref().err().is_some_and(|error| {
            error
                .downcast_ref::<crate::ipc::protocol::BridgeCommandError>()
                .is_some_and(|error| error.detail["save_failed"] == true)
        }) {
            return Err(shutdown_result.unwrap_err());
        }
        // Exit alone cannot confirm a successful final save: the JVM may have
        // crashed before replying. Preserve that uncertainty for archive callers.
        while check_alive(pid) {
            if deadline.is_some_and(|end| now() >= end) {
                return Err(timeout_error().context(format!("Bridge process {pid} did not exit before GHIDRA_CLI_SHUTDOWN_TIMEOUT; preserving discovery and project locks")));
            }
            if let Err(error) = shutdown_result {
                return Err(error.context(format!("Could not request shutdown of live bridge process {pid}; preserving project state")));
            }
            let remaining = deadline.map_or(Duration::from_millis(100), |end| {
                end.saturating_duration_since(now())
                    .min(Duration::from_millis(100))
            });
            sleep(remaining);
        }
        shutdown_result
            .context("Bridge exited without confirming its final save; preserving project state")?;
    }
    cleanup_stale_files_locked(project_path)?;
    info!("Bridge stopped");
    after_stop()
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
        // Status is observational. Cleanup belongs to locked lifecycle operations.
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
mod tests;
