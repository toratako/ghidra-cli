//! Integration tests for output format
//! Tests require real Ghidra installation

/// Helper to verify Ghidra is installed before running tests
fn require_ghidra() {
    let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("doctor")
        .output()
        .expect("Failed to run ghidra-cli doctor");

    if !output.status.success() {
        panic!("Ghidra is not installed. Tests require Ghidra installation per AGENTS.md");
    }
}

#[test]
fn test_format_detection_tty() {
    require_ghidra();

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
    require_ghidra();

    // Test --json flag is recognized
    let mut cmd = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli");
    cmd.arg("--json").arg("--help");
    cmd.assert().success();
}

#[test]
fn test_pretty_flag() {
    require_ghidra();

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
fn local_results_obey_json_modes() {
    let temp = tempfile::tempdir().unwrap();
    for flags in [vec![], vec!["--json"], vec!["--pretty"]] {
        for args in [
            vec!["version"],
            vec!["config", "list"],
            vec!["config", "get", "default_limit"],
            vec!["status", "--project", "missing"],
            vec!["stop", "--project", "missing"],
            vec!["program", "save", "--project", "missing"],
        ] {
            let output = isolated_command(&temp)
                .args(&flags)
                .args(&args)
                .output()
                .unwrap();
            assert!(output.status.success(), "{flags:?} {args:?}: {output:?}");
            serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap();
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
            (vec!["ping", "--project", "missing"], 1),
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
        }
    }
}

#[test]
fn quiet_mutations_keep_results_and_apply_changes() {
    let temp = tempfile::tempdir().unwrap();
    let output = isolated_command(&temp)
        .args(["--quiet", "init"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(std::path::Path::new(result["config_path"].as_str().unwrap()).exists());

    isolated_command(&temp)
        .args(["--quiet", "config", "set", "default_limit", "7"])
        .assert()
        .success();
    let output = isolated_command(&temp)
        .args(["config", "get", "default_limit"])
        .output()
        .unwrap();
    assert_eq!(serde_json::from_slice::<usize>(&output.stdout).unwrap(), 7);
}

#[test]
fn doctor_failure_is_reported_in_both_result_and_exit_status() {
    let temp = tempfile::tempdir().unwrap();
    let output = isolated_command(&temp)
        .env("GHIDRA_INSTALL_DIR", temp.path().join("missing-ghidra"))
        .args(["--json", "doctor"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["ok"], false);
    assert!(!result["failures"].as_array().unwrap().is_empty());
    let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["exit_code"], 1);
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
    use std::os::fd::FromRawFd;
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
                    std::ptr::null(),
                    std::ptr::null(),
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
            .arg("init")
            .stdout(Stdio::from(slave))
            .stderr(Stdio::piped());
        let child = command.spawn().unwrap();
        drop(command); // Close the parent's copy of the slave so reads see EOF.
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success(), "{output:?}");
        let mut stdout = String::new();
        // Linux signals the final PTY close with EIO rather than EOF.
        if let Err(error) = master.read_to_string(&mut stdout) {
            assert_eq!(error.raw_os_error(), Some(libc::EIO));
        }
        if flags == ["--json"] || flags == ["--pretty"] {
            serde_json::from_str::<serde_json::Value>(&stdout).unwrap();
            assert!(output.stderr.is_empty());
            if flags == ["--pretty"] {
                assert!(stdout.contains("\n  \"config_path\""), "{stdout}");
            }
        } else {
            assert!(stdout.starts_with("Configuration saved to:"), "{stdout}");
            if flags.is_empty() {
                assert!(String::from_utf8_lossy(&output.stderr).contains("Run 'ghidra-cli doctor'"));
            } else {
                assert!(output.stderr.is_empty());
            }
        }
    }
}
