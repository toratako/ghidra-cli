use super::*;
use std::cell::Cell;

#[cfg(target_os = "linux")]
#[test]
fn startup_rejects_non_utf8_name_before_selecting_a_lossy_collision() {
    use crate::ghidra::installation::InstallationKind;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile::tempdir().unwrap();
    let requested = root
        .path()
        .join(std::ffi::OsStr::from_bytes(b"project-\xff"));
    let collision = root.path().join("project-\u{fffd}");
    let descriptor = collision.with_added_extension("gpr");
    let data = collision.with_added_extension("rep");
    std::fs::write(&descriptor, "untouched project").unwrap();
    std::fs::create_dir(&data).unwrap();

    let installation = Installation {
        path: root.path().join("distribution"),
        kind: InstallationKind::Directory,
        version: "12.1.4".into(),
        source: "test".into(),
        min_java: 21,
    };
    let launcher = installation.launcher().unwrap();
    std::fs::create_dir_all(launcher.parent().unwrap()).unwrap();
    std::fs::write(
        &launcher,
        "#!/bin/sh\nprintf launched > \"$0.launched\"\nexit 1\n",
    )
    .unwrap();
    std::fs::set_permissions(&launcher, std::fs::Permissions::from_mode(0o755)).unwrap();

    let error =
        start_bridge(&requested, &installation, BridgeStartMode::Project, None).unwrap_err();

    assert!(error.to_string().contains("UTF-8"), "{error:#}");
    assert!(!launcher.with_added_extension("launched").exists());
    assert_eq!(
        std::fs::read_to_string(descriptor).unwrap(),
        "untouched project"
    );
    assert_eq!(std::fs::read_dir(data).unwrap().count(), 0);
}

#[test]
fn launcher_pid_never_overwrites_java_publication() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("bridge.pid");
    // Java may have finished publication or only created/truncated the file
    // while the parent was descheduled immediately after spawning the child.
    for java_contents in ["67890", ""] {
        std::fs::write(&path, java_contents).unwrap();
        write_pid_file(&path, 12345).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), java_contents);
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    }
}

#[test]
fn java_pid_replaces_the_provisional_launcher_pid() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("bridge.pid");
    write_pid_file(&path, 12345).unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "12345");
    std::fs::write(&path, "678").unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "678");
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
}

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
fn stderr_capture_bounds_history_and_preserves_early_diagnostics() {
    let error = serde_json::json!({
        "message": "Program not found",
        "detail": {"stage": "bridge.program_open"}
    });
    let mut output = format!("GHIDRA_CLI_STARTUP_ERROR {error}\nFailed to get OSGi bundle\n");
    for index in 0..100 {
        output.push_str(&format!("ordinary line {index}\n"));
    }

    let captured = capture_stderr(output.as_bytes());
    assert_eq!(captured.tail.len(), 30);
    assert_eq!(captured.tail.front().unwrap(), "ordinary line 70");
    assert_eq!(captured.tail.back().unwrap(), "ordinary line 99");
    assert_eq!(captured.startup_error.unwrap().message, "Program not found");
    assert!(captured.hint_markers.contains(&"Failed to get OSGi bundle"));
}

#[test]
fn stdout_keeps_draining_after_ready_and_end_marker() {
    let output = concat!(
        "---GHIDRA_CLI_START---\n",
        "{\"status\":\"ready\",\"port\":12345}\n",
        "---GHIDRA_CLI_END---\n",
        "ERROR failed after readiness publication\n",
        "last stdout line\n",
    );
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (last_error, captured) = capture_stdout(output.as_bytes(), ready_tx);

    assert_eq!(ready_rx.into_iter().count(), 1);
    assert_eq!(last_error, "ERROR failed after readiness publication");
    assert_eq!(captured.tail.back().unwrap(), "last stdout line");
}

#[test]
fn encoded_launcher_output_does_not_hide_later_bridge_signals() {
    let output = concat!(
        "launcher caf",
        "\n",
        "{\"status\":\"ready\",\"port\":12345}\r\n",
        "GHIDRA_CLI_STARTUP_ERROR {\"message\":\"open failed\",",
        "\"detail\":{\"stage\":\"bridge.program_open\"}}\n",
        "last output line\r",
    );
    let mut bytes = output.as_bytes().to_vec();
    bytes.insert("launcher caf".len(), 0xe9);
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (_, stdout) = capture_stdout(bytes.as_slice(), ready_tx);
    let stderr = capture_stderr(bytes.as_slice());

    assert_eq!(ready_rx.into_iter().count(), 1);
    for captured in [stdout, stderr] {
        assert_eq!(captured.tail.front().unwrap(), "launcher caf\u{fffd}");
        assert_eq!(captured.tail.back().unwrap(), "last output line\r");
        assert_eq!(
            captured.startup_error.unwrap().detail["stage"],
            "bridge.program_open"
        );
    }
}

#[test]
fn ready_when_socket_binds_while_alive() {
    // Becomes ready on the 3rd poll; process stays alive throughout.
    let polls = Cell::new(0);
    let outcome = poll_until_ready(
        Duration::from_millis(1),
        Duration::from_secs(5),
        |_| {
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
        |_| false, // never ready
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
        |_| false,                 // never ready
        || true,                   // always alive
    );
    assert_eq!(outcome, ReadyOutcome::TimedOut);
}

#[test]
fn readiness_wins_before_liveness_and_timeout_checks() {
    let outcome = poll_until_ready(
        Duration::ZERO,
        Duration::ZERO,
        |_| true,
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
            |_| {
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

#[test]
fn readiness_probes_and_poll_sleep_share_launch_budget() {
    let elapsed = Cell::new(Duration::ZERO);
    let mut probes = Vec::new();
    let mut sleeps = Vec::new();
    let outcome = poll_until_ready_with_clock(
        Duration::from_millis(250),
        Duration::from_millis(50),
        |remaining| {
            probes.push(remaining);
            // A failed readiness probe consumes part of the launch budget.
            elapsed.set(elapsed.get() + Duration::from_millis(20));
            false
        },
        || true,
        || elapsed.get(),
        |duration| {
            sleeps.push(duration);
            elapsed.set(elapsed.get() + duration);
        },
    );

    assert_eq!(outcome, ReadyOutcome::TimedOut);
    assert_eq!(probes, [Duration::from_millis(50), Duration::ZERO]);
    assert_eq!(sleeps, [Duration::from_millis(30)]);
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
