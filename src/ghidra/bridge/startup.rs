//! Persistent bridge launch: child process, output readers, readiness, and failure cleanup.

use super::headless::{bridge_failure_hint, headless_command};
#[cfg(unix)]
use super::is_pid_alive;
use super::{cleanup_stale_files_locked, pid_file_path, port_file_path, read_port_file};
use super::{sources, BridgeStartMode};
use crate::ghidra::installation::Installation;
use crate::ipc::client::BridgeClient;
use anyhow::Result;
use std::collections::VecDeque;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;
use tracing::{debug, info};

/// Start a new bridge process.
/// Returns the port number once the bridge is ready.
pub fn start_bridge(
    project_path: &Path,
    installation: &Installation,
    mode: BridgeStartMode,
) -> Result<u16> {
    info!("Starting Ghidra bridge...");

    let scripts_dir = sources::install()?;

    // Compute port file path
    let port_file = port_file_path(project_path)?;

    // analyzeHeadless expects: <parent_directory> <project_name>
    let ghidra_project_dir = std::path::absolute(project_path.parent().unwrap_or(project_path))?;
    let ghidra_project_name = project_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "project".to_string());

    // Script-only headless mode would otherwise create a missing project.
    anyhow::ensure!(
        ghidra_project_dir
            .join(format!("{ghidra_project_name}.gpr"))
            .is_file()
            && ghidra_project_dir
                .join(format!("{ghidra_project_name}.rep"))
                .is_dir(),
        "Ghidra project not found: {}",
        project_path.display()
    );

    // Run only the bridge script, without -process/-import. Otherwise the
    // headless analyzer retains its own Program consumer until the bridge exits,
    // preventing deletion even after ProgramSession closes that program.
    // The bridge opens the optional program itself before publishing readiness.
    let mut arguments = vec![
        ghidra_project_dir.into_os_string(),
        ghidra_project_name.into(),
        "-noanalysis".into(),
        "-scriptPath".into(),
        scripts_dir.into_os_string(),
        "-preScript".into(),
        "GhidraCliBridge.java".into(),
        port_file.into_os_string(),
    ];
    if let BridgeStartMode::Process { program_name } = &mode {
        arguments.push(program_name.into());
    }

    let mut cmd = headless_command(installation, &arguments)?;
    let executable = std::path::PathBuf::from(cmd.get_program());
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // Spawn the JVM tree in its own process group so the whole tree (the
    // analyzeHeadless wrapper AND the java grandchild) is killable as a unit.
    // Without this, killing only the direct child leaves an orphaned JVM that
    // holds the stdout/stderr pipes open — which previously hung the CLI.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // New group whose id equals the child (wrapper) pid — the group leader.
        cmd.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        cmd.creation_flags(CREATE_NEW_PROCESS_GROUP);
    }

    info!("Ghidra command: {:?}", cmd);

    // Spawn the process
    let mut child = cmd
        .spawn()
        .map_err(|e| crate::error::path_io("bridge.launch", &executable, e))?;
    info!("Ghidra process started with PID: {:?}", child.id());

    // Write PID file immediately so orphan cleanup is possible if Java crashes
    // before the ready signal (Java overwrites this once it binds the ServerSocket)
    write_pid_file(project_path, child.id()).ok();

    // Drain stderr continuously while retaining only diagnostic output.
    let stderr = child.stderr.take().expect("stderr should be piped");
    let stderr_handle = std::thread::spawn(move || capture_stderr(stderr));

    // Wait for bridge to become ready.
    //
    // Two mechanisms run in parallel:
    // 1. Stdout reader thread - watches for the JSON ready signal (fast path)
    // 2. Port file poller - polls port file + TCP ping as fallback
    //
    // On Windows, stdout piping through analyzeHeadless.bat → cmd.exe → java.exe
    // can fail due to buffering, so the port file fallback is essential.
    let stdout = child.stdout.take().expect("stdout should be piped");
    let (stdout_tx, stdout_rx) = std::sync::mpsc::channel();
    let stdout_handle = std::thread::spawn(move || {
        let reader = BufReader::new(stdout);
        let mut last_error = String::new();
        let mut captured = CapturedOutput::default();
        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => break,
            };
            info!("[Ghidra stdout] {}", line);

            if line.contains("ERROR") || line.contains("Exception") || line.contains("SEVERE") {
                last_error = line.clone();
            }

            let start_marker = line.contains("---GHIDRA_CLI_START---");
            let ready = line.contains("\"status\"") && line.contains("\"ready\"");
            let end_marker = line.contains("---GHIDRA_CLI_END---");
            captured.push(line);
            if start_marker {
                continue;
            }
            if ready {
                info!("Bridge is ready (stdout signal)");
                let _ = stdout_tx.send(true);
                return (true, last_error, captured);
            }
            if end_marker {
                break;
            }
        }
        let _ = stdout_tx.send(false);
        (false, last_error, captured)
    });

    // Wait for the bridge to become ready.
    //
    // The wait is liveness-aware: we keep waiting as long as the child process
    // is alive (loading a large binary is part of this bounded launch) and only
    // give up if the process exits before becoming ready, or a generous absolute
    // safety cap (`launch_timeout_secs`) is exceeded. The cap is a safety net,
    // NOT the normal exit path — analysis runs afterwards as an unbounded TCP op.
    //
    // Primary readiness signal: port file present + TCP ping succeeds (robust on
    // Windows, where stdout piped through analyzeHeadless.bat → cmd.exe → java.exe
    // is unreliable). The stdout JSON ready signal is kept only as a fast path.
    let launch_timeout = crate::config::Config::load()
        .map(|c| c.get_launch_timeout())
        .unwrap_or_else(|_| Duration::from_secs(180));

    let mut ready_port: Option<u16> = None;
    let check_ready = || {
        let signaled = matches!(stdout_rx.try_recv(), Ok(true));
        if let Ok(Some(port)) = read_port_file(project_path) {
            if signaled || BridgeClient::new(port).ping().unwrap_or(false) {
                ready_port = Some(port);
                return true;
            }
        }
        false
    };
    let check_alive = || matches!(child.try_wait(), Ok(None));

    let outcome = poll_until_ready(
        Duration::from_millis(250),
        launch_timeout,
        check_ready,
        check_alive,
    );

    match outcome {
        ReadyOutcome::Ready => {
            let port = ready_port
                .or_else(|| read_port_file(project_path).ok().flatten())
                .ok_or_else(|| anyhow::anyhow!("Port file not created by bridge"))?;
            // Success path: DETACH the reader threads — do NOT join. The JVM
            // keeps the pipes open for its whole lifetime, so joining here would
            // block forever. They terminate on their own when the bridge exits.
            drop(stdout_handle);
            drop(stderr_handle);
            // A directly launched JVM is our child. Reap it after shutdown so
            // PID-based liveness checks cannot mistake a zombie for a running
            // bridge while this CLI process remains alive (doctor --runtime).
            std::thread::spawn(move || {
                if let Err(error) = child.wait() {
                    tracing::warn!("Failed to reap Ghidra process: {error}");
                }
            });
            info!("Ghidra bridge started on port {}", port);
            Ok(port)
        }
        ReadyOutcome::Exited | ReadyOutcome::TimedOut => {
            // Kill the ENTIRE process tree FIRST so the pipes close; only then is
            // it safe to join the reader threads. Joining before killing was the
            // original hang: a surviving JVM held the pipes open forever.
            kill_process_tree(&mut child);
            cleanup_stale_files_locked(project_path).ok();

            let (_, last_error, stdout_output) = stdout_handle.join().unwrap_or_default();
            let stderr_output = stderr_handle.join().unwrap_or_default();
            let CapturedOutput {
                tail: stdout_tail,
                startup_error: stdout_error,
                hint_markers: stdout_markers,
            } = stdout_output;
            let CapturedOutput {
                tail: stderr_tail,
                startup_error: stderr_error,
                hint_markers: stderr_markers,
            } = stderr_output;
            let stdout_lines: Vec<_> = stdout_tail.into_iter().collect();
            let stderr_output: Vec<_> = stderr_tail.into_iter().collect();
            let detail = if !last_error.is_empty() {
                format!(": {}", last_error)
            } else if !stderr_output.is_empty() {
                let last_stderr: Vec<_> =
                    stderr_output.iter().rev().take(5).rev().cloned().collect();
                format!(": stderr: {}", last_stderr.join("\n"))
            } else {
                let last_stdout: Vec<_> =
                    stdout_lines.iter().rev().take(10).rev().cloned().collect();
                format!("\nLast stdout:\n{}", last_stdout.join("\n"))
            };
            // Surface an actionable hint when the failure is the (otherwise
            // opaque) OSGi script compile/load failure.
            let combined = format!(
                "{}\n{}\n{}\n{}",
                stdout_lines.join("\n"),
                stderr_output.join("\n"),
                stdout_markers.join("\n"),
                stderr_markers.join("\n")
            );
            if let Some(error) = stdout_error.or(stderr_error) {
                return Err(error.into());
            }
            let hint = bridge_failure_hint(&combined);

            let message = match outcome {
                ReadyOutcome::Exited => format!(
                    "Ghidra process exited before the bridge became ready{}{}",
                    detail, hint
                ),
                ReadyOutcome::TimedOut => format!(
                    "Ghidra bridge did not become ready within {}s{}{}",
                    launch_timeout.as_secs(),
                    detail,
                    hint
                ),
                ReadyOutcome::Ready => unreachable!(),
            };
            Err(crate::ipc::protocol::BridgeCommandError {
                message,
                detail: serde_json::json!({
                    "stage": "bridge.startup", "project": project_path,
                    "stdout": stdout_lines.iter().rev().take(10).rev().cloned().collect::<Vec<_>>(),
                    "stderr": stderr_output.iter().rev().take(10).rev().cloned().collect::<Vec<_>>()
                }),
            }
            .into())
        }
    }
}

#[derive(Default)]
struct CapturedOutput {
    tail: VecDeque<String>,
    startup_error: Option<crate::ipc::protocol::BridgeCommandError>,
    hint_markers: Vec<&'static str>,
}

impl CapturedOutput {
    const TAIL_LINES: usize = 30;
    const HINT_MARKERS: [&str; 4] = [
        "Failed to get OSGi bundle",
        "GhidraScriptLoadException",
        "ClassNotFoundException",
        "GhidraCliBridge",
    ];

    fn push(&mut self, line: String) {
        if self.startup_error.is_none() {
            self.startup_error = startup_diagnostic(&line);
        }
        for marker in Self::HINT_MARKERS {
            if line.contains(marker) && !self.hint_markers.contains(&marker) {
                self.hint_markers.push(marker);
            }
        }
        if self.tail.len() == Self::TAIL_LINES {
            self.tail.pop_front();
        }
        self.tail.push_back(line);
    }
}

fn capture_stderr(stream: impl std::io::Read) -> CapturedOutput {
    let mut captured = CapturedOutput::default();
    for line in BufReader::new(stream).lines().map_while(Result::ok) {
        info!("[Ghidra stderr] {}", line);
        captured.push(line);
    }
    captured
}

fn startup_diagnostic(line: &str) -> Option<crate::ipc::protocol::BridgeCommandError> {
    let (_, payload) = line.split_once("GHIDRA_CLI_STARTUP_ERROR ")?;
    // GhidraScript.println goes through the logger, which can append a class
    // name after the JSON. Decode one value without consuming that decoration.
    let value = serde_json::Deserializer::from_str(payload)
        .into_iter::<serde_json::Value>()
        .next()?
        .ok()?;
    Some(crate::ipc::protocol::BridgeCommandError {
        message: value.get("message")?.as_str()?.to_owned(),
        detail: serde_json::Value::Object(value.get("detail")?.as_object()?.clone()),
    })
}

/// Outcome of the bridge readiness wait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadyOutcome {
    /// The bridge bound its socket and responded.
    Ready,
    /// The child process exited before the bridge became ready.
    Exited,
    /// The absolute launch safety cap was exceeded while the child was alive.
    TimedOut,
}

/// Liveness-aware readiness state machine. Factored out (closures injected) so
/// the three outcomes can be unit-tested without a real Ghidra process.
///
/// - `check_ready`: returns true once the bridge is listening (port + ping).
/// - `check_alive`: returns true while the launched process is still running.
fn poll_until_ready(
    poll_interval: Duration,
    launch_timeout: Duration,
    mut check_ready: impl FnMut() -> bool,
    mut check_alive: impl FnMut() -> bool,
) -> ReadyOutcome {
    let start = std::time::Instant::now();
    loop {
        if check_ready() {
            return ReadyOutcome::Ready;
        }
        if !check_alive() {
            // Re-check readiness once: the socket may have bound in the same
            // instant the process record flipped to exited (it shouldn't, but
            // this avoids a benign race reporting a false failure).
            if check_ready() {
                return ReadyOutcome::Ready;
            }
            return ReadyOutcome::Exited;
        }
        if start.elapsed() >= launch_timeout {
            return ReadyOutcome::TimedOut;
        }
        std::thread::sleep(poll_interval);
    }
}

/// Kill an entire spawned process tree (group), then reap the direct child.
///
/// Safe to call whether or not the process is still alive. On unix this relies
/// on the child having been spawned with `process_group(0)` (the child is the
/// group leader, so its pid is the group id). On windows `taskkill /T` walks
/// the tree. After this returns, the child's stdio pipes are closed, so any
/// reader threads can be joined without blocking.
pub(super) fn kill_process_tree(child: &mut std::process::Child) {
    #[cfg(unix)]
    {
        let pgid = child.id() as i32;
        unsafe {
            libc::killpg(pgid, libc::SIGTERM);
        }
        // Brief grace window for the group to exit on SIGTERM.
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while std::time::Instant::now() < deadline {
            if !is_pid_alive(child.id()) {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        // Force-kill the whole group. ESRCH on an already-dead group is harmless.
        unsafe {
            libc::killpg(pgid, libc::SIGKILL);
        }
    }
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("taskkill")
            .args(["/PID", &child.id().to_string(), "/T", "/F"])
            .output();
    }
    let _ = child.wait();
}

/// Write PID to the PID file for a project.
/// Enables orphan cleanup when Java crashes before writing its own PID file.
/// Java overwrites this value once it binds the ServerSocket.
fn write_pid_file(project_path: &Path, pid: u32) -> Result<()> {
    let path = pid_file_path(project_path)?;
    std::fs::write(&path, pid.to_string())?;
    debug!("Wrote PID {} to {}", pid, path.display());
    Ok(())
}

#[cfg(test)]
mod tests;
