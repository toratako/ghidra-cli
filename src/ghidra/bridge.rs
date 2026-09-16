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

pub mod diagnostics;
mod headless;
mod import;
mod sources;
mod startup;
pub use headless::{compile_check, find_headless_script};
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
    let deadline = timeout.map(|timeout| std::time::Instant::now() + timeout);
    let timeout_error = || {
        anyhow::Error::new(crate::ipc::protocol::BridgeTimeoutError {
            command: "shutdown".to_string(),
            timeout_secs: timeout.map_or(0, |timeout| timeout.as_secs()),
        })
    };
    let _lock = acquire_lifecycle_lock(project_path, deadline).map_err(|error| {
        if deadline.is_some_and(|end| std::time::Instant::now() >= end) {
            timeout_error().context("Shutdown deadline expired waiting for the lifecycle lock; preserving project state")
        } else { error }
    })?;
    let pid = read_pid_file(project_path)?;
    if let Some(pid) = pid.filter(|pid| is_pid_alive(*pid)) {
        let port = read_port_file(project_path)?.ok_or_else(||
            anyhow::anyhow!("Bridge process {pid} is alive but its port is unavailable; preserving project state"))?;
        let shutdown_result = BridgeClient::new(port).shutdown_with_deadline(deadline);
        // A response can be lost during successful shutdown. If the process
        // has already exited, cleanup is still safe; otherwise retain state.
        while is_pid_alive(pid) {
            if deadline.is_some_and(|end| std::time::Instant::now() >= end) {
                return Err(timeout_error().context(format!("Bridge process {pid} did not exit before GHIDRA_CLI_SHUTDOWN_TIMEOUT; preserving discovery and project locks")));
            }
            if let Err(error) = shutdown_result {
                return Err(error.context(format!("Could not request shutdown of live bridge process {pid}; preserving project state")));
            }
            let remaining = deadline.map_or(Duration::from_millis(100), |end| {
                end.saturating_duration_since(std::time::Instant::now())
                    .min(Duration::from_millis(100))
            });
            std::thread::sleep(remaining);
        }
    }
    cleanup_stale_files_locked(project_path)?;
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
mod tests {
    use super::*;

    #[test]
    fn shutdown_deadline_includes_lifecycle_lock_wait_and_retains_timeout_type() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("locked-project");
        let _holder = acquire_startup_lock(&project).unwrap();
        let started = std::time::Instant::now();
        let error =
            stop_bridge_with_timeout(&project, Some(Duration::from_millis(30))).unwrap_err();
        assert!(error
            .downcast_ref::<crate::ipc::protocol::BridgeTimeoutError>()
            .is_some());
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn shutdown_drain_deadline_preserves_live_discovery_and_timeout_type() {
        use std::io::{BufRead, BufReader, Write};
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("draining-project");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let pid_path = pid_file_path(&project).unwrap();
        let port_path = port_file_path(&project).unwrap();
        std::fs::write(&pid_path, std::process::id().to_string()).unwrap();
        std::fs::write(
            &port_path,
            listener.local_addr().unwrap().port().to_string(),
        )
        .unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = String::new();
            BufReader::new(&stream).read_line(&mut request).unwrap();
            assert!(request.contains("shutdown"));
            writeln!(stream, "{{\"status\":\"shutdown\"}}").unwrap();
        });
        let error =
            stop_bridge_with_timeout(&project, Some(Duration::from_millis(100))).unwrap_err();
        server.join().unwrap();
        assert!(error
            .downcast_ref::<crate::ipc::protocol::BridgeTimeoutError>()
            .is_some());
        assert!(pid_path.exists() && port_path.exists());
        std::fs::remove_file(pid_path).unwrap();
        std::fs::remove_file(port_path).unwrap();
    }

    #[test]
    fn lifecycle_lock_recovers_empty_file_and_excludes_waiters() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("bridge.starting");
        std::fs::write(&path, []).unwrap();
        let holder = acquire_file_lock(&path, Duration::from_millis(50)).unwrap();
        assert!(acquire_file_lock(&path, Duration::from_millis(30)).is_err());
        drop(holder);
        assert!(
            path.exists(),
            "the inode must remain stable for waiting callers"
        );
        let _next = acquire_file_lock(&path, Duration::from_millis(50)).unwrap();
    }

    #[test]
    fn cleanup_preserves_live_process_discovery_and_unknown_project_locks() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("Project.v1");
        let pid_path = pid_file_path(&project).unwrap();
        let port_path = port_file_path(&project).unwrap();
        let lock_path = project.with_added_extension("lock");
        std::fs::write(&pid_path, std::process::id().to_string()).unwrap();
        std::fs::write(&port_path, "1").unwrap();
        std::fs::write(&lock_path, "held").unwrap();
        assert!(cleanup_stale_files(&project).is_err());
        assert!(pid_path.exists() && port_path.exists() && lock_path.exists());
        std::fs::remove_file(pid_path).unwrap();
        cleanup_stale_files(&project).unwrap();
        assert!(
            lock_path.exists(),
            "missing discovery does not prove project lock ownership"
        );
        assert!(!port_path.exists());
    }

    #[test]
    fn discovery_keys_normalize_missing_project_paths() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("missing/project");
        let alias = root.path().join("missing/./project");
        assert_eq!(
            project_hash(&project).unwrap(),
            project_hash(&alias).unwrap()
        );
        assert_eq!(
            project_hash(Path::new("missing/./project")).unwrap(),
            project_hash(&std::env::current_dir().unwrap().join("missing/project")).unwrap()
        );
    }

    #[test]
    fn discovery_keys_preserve_dotted_names_and_resolve_repository_paths() {
        let root = tempfile::tempdir().unwrap();
        let directory = dunce::canonicalize(root.path()).unwrap();
        let project = directory.join("Project.v1");
        let repository = directory.join("Project.v1.rep");
        std::fs::create_dir(&repository).unwrap();
        let original_hash = project_hash(&project).unwrap();
        assert_eq!(
            project_hash(&directory.join("./Project.v1")).unwrap(),
            original_hash
        );
        #[cfg(windows)]
        assert_eq!(
            project_hash(Path::new(&project.to_string_lossy().replace('\\', "/"))).unwrap(),
            original_hash
        );
        std::fs::write(directory.join("Project.v1.gpr"), []).unwrap();
        assert_eq!(project_hash(&project).unwrap(), original_hash);
        std::fs::create_dir(directory.join("Project.v2.rep")).unwrap();
        assert_ne!(
            project_hash(&directory.join("Project.v2")).unwrap(),
            original_hash
        );
    }

    #[test]
    fn discovery_keys_respect_filesystem_case_sensitivity() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("Project");
        let alias = root.path().join("project");
        std::fs::create_dir(root.path().join("Project.rep")).unwrap();
        if root.path().join("project.rep").exists() {
            assert_eq!(
                project_hash(&project).unwrap(),
                project_hash(&alias).unwrap()
            );
        } else {
            std::fs::create_dir(root.path().join("project.rep")).unwrap();
            assert_ne!(
                project_hash(&project).unwrap(),
                project_hash(&alias).unwrap()
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn discovery_keys_resolve_directory_symlinks() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("projects");
        std::fs::create_dir_all(directory.join("project.rep")).unwrap();
        let alias = root.path().join("alias");
        std::os::unix::fs::symlink(&directory, &alias).unwrap();
        assert_eq!(
            project_hash(&directory.join("project")).unwrap(),
            project_hash(&alias.join("project")).unwrap()
        );

        // Repository symlink targets need not themselves end in .rep.
        for name in ["store.v1", "store.v2", "store.rep"] {
            std::fs::create_dir(root.path().join(name)).unwrap();
        }
        std::os::unix::fs::symlink(root.path().join("store.v1"), root.path().join("first.rep"))
            .unwrap();
        std::os::unix::fs::symlink(root.path().join("store.v2"), root.path().join("second.rep"))
            .unwrap();
        let first_hash = project_hash(&root.path().join("first")).unwrap();
        assert_ne!(
            first_hash,
            project_hash(&root.path().join("second")).unwrap()
        );
        assert_ne!(
            first_hash,
            project_hash(&root.path().join("store")).unwrap()
        );
    }

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
