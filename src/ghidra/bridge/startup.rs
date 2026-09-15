//! Persistent bridge launch: child process, output readers, readiness, and failure cleanup.

use super::headless::{apply_java_home, bridge_failure_hint, find_headless_script};
#[cfg(unix)]
use super::is_pid_alive;
use super::{cleanup_stale_files_locked, pid_file_path, port_file_path, read_port_file};
use super::{sources, BridgeStartMode};
use crate::ipc::client::BridgeClient;
use anyhow::{Context, Result};
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;
use tracing::{debug, info};

/// Start a new bridge process.
/// Returns the port number once the bridge is ready.
pub fn start_bridge(
    project_path: &Path,
    ghidra_install_dir: &Path,
    mode: BridgeStartMode,
) -> Result<u16> {
    info!("Starting Ghidra bridge...");

    let scripts_dir = sources::install()?;

    // Find analyzeHeadless
    let headless_script = find_headless_script(ghidra_install_dir)?;

    // Compute port file path
    let port_file = port_file_path(project_path)?;

    // Build command
    let mut cmd = Command::new(&headless_script);

    // analyzeHeadless expects: <parent_directory> <project_name>
    let ghidra_project_dir = project_path.parent().unwrap_or(project_path);
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

    cmd.arg(ghidra_project_dir).arg(&ghidra_project_name);

    // Run only the bridge script, without -process/-import. Otherwise the
    // headless analyzer retains its own Program consumer until the bridge exits,
    // preventing deletion even after ProgramSession closes that program.
    // The bridge opens the optional program itself before publishing readiness.
    cmd.arg("-noanalysis")
        .arg("-scriptPath")
        .arg(scripts_dir.to_str().unwrap())
        .arg("-preScript")
        .arg("GhidraCliBridge.java")
        .arg(port_file.to_str().unwrap());
    if let BridgeStartMode::Process { program_name } = &mode {
        cmd.arg(program_name);
    }

    apply_java_home(&mut cmd, ghidra_install_dir);

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
    let mut child = cmd.spawn().context("Failed to spawn Ghidra headless")?;
    info!("Ghidra process started with PID: {:?}", child.id());

    // Write PID file immediately so orphan cleanup is possible if Java crashes
    // before the ready signal (Java overwrites this once it binds the ServerSocket)
    write_pid_file(project_path, child.id()).ok();

    // Spawn a thread to capture stderr
    let stderr = child.stderr.take().expect("stderr should be piped");
    let stderr_handle = std::thread::spawn(move || {
        let reader = BufReader::new(stderr);
        let mut stderr_output = Vec::new();
        for line in reader.lines().map_while(Result::ok) {
            info!("[Ghidra stderr] {}", line);
            stderr_output.push(line);
        }
        stderr_output
    });

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
        let mut stdout_lines = Vec::new();
        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => break,
            };
            info!("[Ghidra stdout] {}", line);
            stdout_lines.push(line.clone());

            if line.contains("ERROR") || line.contains("Exception") || line.contains("SEVERE") {
                last_error = line.clone();
            }

            if line.contains("---GHIDRA_CLI_START---") {
                continue;
            }
            if line.contains("\"status\"") && line.contains("\"ready\"") {
                info!("Bridge is ready (stdout signal)");
                let _ = stdout_tx.send(true);
                return (true, last_error, stdout_lines);
            }
            if line.contains("---GHIDRA_CLI_END---") {
                break;
            }
        }
        let _ = stdout_tx.send(false);
        (false, last_error, stdout_lines)
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
            info!("Ghidra bridge started on port {}", port);
            Ok(port)
        }
        ReadyOutcome::Exited | ReadyOutcome::TimedOut => {
            // Kill the ENTIRE process tree FIRST so the pipes close; only then is
            // it safe to join the reader threads. Joining before killing was the
            // original hang: a surviving JVM held the pipes open forever.
            kill_process_tree(&mut child);
            cleanup_stale_files_locked(project_path).ok();

            let (_, last_error, stdout_lines) = stdout_handle.join().unwrap_or_default();
            let stderr_output = stderr_handle.join().unwrap_or_default();
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
            let combined = format!("{}\n{}", stdout_lines.join("\n"), stderr_output.join("\n"));
            let hint = bridge_failure_hint(&combined);

            match outcome {
                ReadyOutcome::Exited => anyhow::bail!(
                    "Ghidra process exited before the bridge became ready{}{}",
                    detail,
                    hint
                ),
                ReadyOutcome::TimedOut => anyhow::bail!(
                    "Ghidra bridge did not become ready within {}s{}{}",
                    launch_timeout.as_secs(),
                    detail,
                    hint
                ),
                ReadyOutcome::Ready => unreachable!(),
            }
        }
    }
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
fn kill_process_tree(child: &mut std::process::Child) {
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
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn ready_when_socket_binds_while_alive() {
        // Becomes ready on the 3rd poll; process stays alive throughout.
        let polls = Cell::new(0);
        let outcome = poll_until_ready(
            Duration::from_millis(1),
            Duration::from_secs(5),
            || {
                polls.set(polls.get() + 1);
                polls.get() >= 3
            },
            || true,
        );
        assert_eq!(outcome, ReadyOutcome::Ready);
    }

    #[test]
    fn exited_when_process_dies_before_ready() {
        let alive = Cell::new(true);
        let outcome = poll_until_ready(
            Duration::from_millis(1),
            Duration::from_secs(5),
            || false, // never ready
            || {
                let was = alive.get();
                alive.set(false); // dies after the first liveness check
                was
            },
        );
        assert_eq!(outcome, ReadyOutcome::Exited);
    }

    #[test]
    fn timed_out_when_never_ready_but_alive() {
        let outcome = poll_until_ready(
            Duration::from_millis(5),
            Duration::from_millis(30), // tiny cap
            || false,                  // never ready
            || true,                   // always alive
        );
        assert_eq!(outcome, ReadyOutcome::TimedOut);
    }

    #[test]
    fn readiness_wins_before_liveness_and_timeout_checks() {
        let outcome = poll_until_ready(
            Duration::ZERO,
            Duration::ZERO,
            || true,
            || panic!("a ready bridge must not need a liveness check"),
        );
        assert_eq!(outcome, ReadyOutcome::Ready);
    }

    #[test]
    fn process_exit_rechecks_readiness_before_reporting_failure() {
        // Both the process and timeout are already exhausted. The final ready
        // probe still wins if the socket appeared during the liveness check.
        for ready_after_exit in [false, true] {
            let polls = Cell::new(0);
            let outcome = poll_until_ready(
                Duration::ZERO,
                Duration::ZERO,
                || {
                    polls.set(polls.get() + 1);
                    polls.get() == 2 && ready_after_exit
                },
                || false,
            );
            assert_eq!(polls.get(), 2);
            assert_eq!(
                outcome,
                if ready_after_exit {
                    ReadyOutcome::Ready
                } else {
                    ReadyOutcome::Exited
                }
            );
        }
    }

    /// Spawn a shell that itself spawns a long-lived child, then prove
    /// `kill_process_tree` takes out the whole group (not just the wrapper).
    #[cfg(unix)]
    #[test]
    fn kill_process_tree_kills_whole_group() {
        use std::os::unix::process::CommandExt;

        let mut cmd = std::process::Command::new("sh");
        // Print the grandchild's pid, then sleep both shell and grandchild.
        cmd.arg("-c").arg("sleep 300 & echo $! ; wait");
        cmd.stdout(Stdio::piped());
        cmd.process_group(0);
        let mut child = cmd.spawn().expect("spawn sh");

        // Read the grandchild (sleep) pid that the shell printed.
        let mut line = String::new();
        {
            let stdout = child.stdout.take().unwrap();
            let mut reader = BufReader::new(stdout);
            reader.read_line(&mut line).expect("read grandchild pid");
        }
        let grandchild: u32 = line.trim().parse().expect("parse grandchild pid");

        assert!(is_pid_alive(grandchild), "grandchild should be alive");
        kill_process_tree(&mut child);

        // The group-kill should have reaped the grandchild too. Allow a brief
        // moment for the kernel to deliver SIGKILL.
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while std::time::Instant::now() < deadline && is_pid_alive(grandchild) {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            !is_pid_alive(grandchild),
            "grandchild {} should be dead after kill_process_tree",
            grandchild
        );
    }
}
