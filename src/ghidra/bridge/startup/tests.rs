use super::*;
use std::cell::Cell;

#[test]
fn startup_diagnostics_accept_ghidra_log_decoration() {
    let payload = serde_json::json!({
        "status": "error", "message": "Program not found",
        "detail": {"stage": "bridge.program_open", "path": "missing-program"}
    });
    for line in [
        format!("GHIDRA_CLI_STARTUP_ERROR {payload}"),
        format!("INFO GhidraCliBridge.java> GHIDRA_CLI_STARTUP_ERROR {payload} (GhidraScript)"),
    ] {
        let error = startup_diagnostic(&line).unwrap();
        assert_eq!(error.message, "Program not found");
        assert_eq!(error.detail["stage"], "bridge.program_open");
        assert_eq!(error.detail["path"], "missing-program");
    }
    assert!(startup_diagnostic("GHIDRA_CLI_STARTUP_ERROR {invalid").is_none());
    assert!(startup_diagnostic("unrelated error").is_none());
}
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
