//! CLI output format tests that do not require Ghidra or a JDK installation.

#[path = "support/json.rs"]
mod json_output;

#[path = "output/config.rs"]
mod config;
#[path = "output/installation.rs"]
mod installation;
#[path = "support/installation.rs"]
mod installation_fixture;
#[path = "output/project.rs"]
mod project;
#[path = "output/validation.rs"]
mod validation;

#[test]
fn test_format_detection_tty() {
    // Test that --help shows both --json and --pretty flags
    let mut cmd = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli");
    cmd.arg("--help");
    cmd.assert().success();

    let output = cmd.output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--json"), "Help should show --json flag");
    assert!(
        stdout.contains("--pretty"),
        "Help should show --pretty flag"
    );
}

#[test]
fn test_json_flag() {
    // Test --json flag is recognized
    let mut cmd = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli");
    cmd.arg("--json").arg("--help");
    cmd.assert().success();
}

#[test]
fn test_pretty_flag() {
    // Test --pretty flag is recognized
    let mut cmd = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli");
    cmd.arg("--pretty").arg("--help");
    cmd.assert().success();
}

fn isolated_command(temp: &tempfile::TempDir) -> assert_cmd::Command {
    let mut command = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli");
    command
        .env("GHIDRA_CLI_CONFIG", temp.path().join("config.yaml"))
        .env("XDG_DATA_HOME", temp.path().join("data"))
        .env("GHIDRA_PROJECT_DIR", temp.path().join("projects"));
    command
}

#[test]
fn configured_json_default_and_explicit_flags_choose_presentation() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(
        temp.path().join("config.yaml"),
        "default_output_format: json\n",
    )
    .unwrap();
    for (flags, pretty) in [
        (vec![], true),
        (vec!["--json"], false),
        (vec!["--pretty"], true),
    ] {
        let output = isolated_command(&temp)
            .args(flags)
            .args(["config", "list"])
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        crate::json_output::from_slice::<serde_json::Value>(&output.stdout).unwrap();
        assert_eq!(
            output.stdout.iter().filter(|&&c| c == b'\n').count() > 1,
            pretty,
            "{output:?}"
        );
    }
}

#[test]
fn local_results_obey_json_modes() {
    let temp = tempfile::tempdir().unwrap();
    for flags in [vec![], vec!["--json"], vec!["--pretty"]] {
        for args in [
            vec!["config", "list"],
            vec!["config", "get", "default_limit"],
            vec!["bridge", "status", "--project", "missing"],
            vec!["bridge", "stop", "--project", "missing"],
            vec!["program", "save", "--project", "missing"],
        ] {
            let output = isolated_command(&temp)
                .args(&flags)
                .args(&args)
                .output()
                .unwrap();
            assert!(output.status.success(), "{flags:?} {args:?}: {output:?}");
            let result: serde_json::Value = crate::json_output::from_slice(&output.stdout).unwrap();
            if args[0] == "bridge" {
                assert_eq!(result["state"], "stopped", "{args:?}: {result}");
            }
            assert!(output.stderr.is_empty(), "{output:?}");
            let lines = output.stdout.iter().filter(|&&c| c == b'\n').count();
            if flags != ["--pretty"] {
                assert_eq!(lines, 1, "compact JSON must occupy one line: {output:?}");
            }
        }
    }
}

#[test]
fn failures_have_nonzero_status_and_json_diagnostics() {
    let temp = tempfile::tempdir().unwrap();
    for flags in [vec![], vec!["--json"], vec!["--pretty"]] {
        for (args, code) in [
            (vec!["config", "get", "unknown_key"], 1),
            (vec!["bridge", "ping", "--project", "missing"], 1),
            (vec!["job", "list", "--project", "missing"], 1),
            (vec!["job", "get", "42", "--project", "missing"], 1),
            (vec!["job", "cancel", "--project", "missing"], 1),
            (vec!["job", "cancel", "42", "--project", "missing"], 1),
            (vec!["--unknown-option"], 2),
            (vec!["config", "get"], 2),
            (vec!["function", "list", "--filter", "bad"], 1),
        ] {
            let output = isolated_command(&temp)
                .args(&flags)
                .args(&args)
                .output()
                .unwrap();
            assert_eq!(
                output.status.code(),
                Some(code),
                "{flags:?} {args:?}: {output:?}"
            );
            assert!(output.stdout.is_empty(), "{output:?}");
            let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
            assert_eq!(error["status"], "error");
            assert_eq!(error["exit_code"], code);
            assert!(!error["message"].as_str().unwrap().is_empty());
            if matches!(args[0], "bridge" | "job") {
                assert!(
                    error["message"]
                        .as_str()
                        .unwrap()
                        .contains("No bridge running"),
                    "{args:?}: {error}"
                );
            }
        }
    }
}

#[test]
fn quiet_mutations_keep_results_and_apply_changes() {
    let temp = tempfile::tempdir().unwrap();
    let output = isolated_command(&temp)
        .args(["--quiet", "config", "set", "default_limit", "7"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let result: serde_json::Value = crate::json_output::from_slice(&output.stdout).unwrap();
    assert_eq!(result["key"], "default_limit");
    assert!(temp.path().join("config.yaml").exists());

    let output = isolated_command(&temp)
        .args(["config", "get", "default_limit"])
        .output()
        .unwrap();
    assert_eq!(
        crate::json_output::from_slice::<usize>(&output.stdout).unwrap(),
        7
    );
}

#[cfg(unix)]
#[test]
fn closed_stdout_pipe_does_not_panic() {
    use std::os::{fd::OwnedFd, unix::net::UnixStream};
    use std::process::{Command, Stdio};
    let temp = tempfile::tempdir().unwrap();
    let (reader, writer) = UnixStream::pair().unwrap();
    drop(reader); // No reader exists before the child can attempt a write.
    let writer: OwnedFd = writer.into();
    let output = Command::new(assert_cmd::cargo::cargo_bin!("ghidra-cli"))
        .env("GHIDRA_CLI_CONFIG", temp.path().join("config.yaml"))
        .env("XDG_DATA_HOME", temp.path().join("data"))
        .args(["config", "list"])
        .stdout(Stdio::from(writer))
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
}

#[cfg(unix)]
#[test]
fn terminal_defaults_and_explicit_json_and_quiet() {
    use std::io::Read;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::process::{Command, Stdio};
    let temp = tempfile::tempdir().unwrap();
    for flags in [vec![], vec!["--json"], vec!["--pretty"], vec!["--quiet"]] {
        let mut master = -1;
        let mut slave = -1;
        // openpty initializes both descriptors; File takes sole ownership.
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            },
            0
        );
        let mut master = unsafe { std::fs::File::from_raw_fd(master) };
        let slave = unsafe { std::fs::File::from_raw_fd(slave) };
        let mut command = Command::new(assert_cmd::cargo::cargo_bin!("ghidra-cli"));
        command
            .env("GHIDRA_CLI_CONFIG", temp.path().join("config.yaml"))
            .env("XDG_DATA_HOME", temp.path().join("data"))
            .args(&flags)
            .args(["config", "set", "default_limit", "7"])
            .stdout(Stdio::from(slave))
            .stderr(Stdio::piped());
        let child = command.spawn().unwrap();
        // Keep the parent's slave open: macOS discards unread output on final close.
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success(), "{output:?}");
        // The child has exited; drain its output without waiting for slave EOF.
        let mut nonblocking: libc::c_int = 1;
        assert_eq!(
            unsafe { libc::ioctl(master.as_raw_fd(), libc::FIONBIO, &mut nonblocking) },
            0
        );
        let mut stdout = String::new();
        if let Err(error) = master.read_to_string(&mut stdout) {
            assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
        }
        drop(command);
        if flags == ["--json"] || flags == ["--pretty"] {
            serde_json::from_str::<serde_json::Value>(&stdout).unwrap();
            assert!(output.stderr.is_empty());
            if flags == ["--pretty"] {
                assert!(stdout.contains("\n  \"data\""), "{stdout}");
            }
        } else {
            assert!(stdout.starts_with("Configuration updated"), "{stdout}");
            assert!(output.stderr.is_empty());
        }
    }
}
