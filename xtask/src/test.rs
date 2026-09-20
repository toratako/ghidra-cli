//! Own run-scoped fixtures while Cargo executes its test targets normally.

use anyhow::{Context, Result};
use std::ffi::{OsStr, OsString};
use std::process::{Command, ExitCode};

const RUN_DIR_ENV: &str = "GHIDRA_TEST_RUN_DIR";

pub fn run(args: Vec<OsString>) -> Result<ExitCode> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    run_command(&mut cargo_command(&cargo, args))
}

fn cargo_command(cargo: &OsStr, args: Vec<OsString>) -> Command {
    let mut command = Command::new(cargo);
    // Preserve Cargo's caller-relative paths and package selection.
    command.arg("test").args(args);
    command
}

fn run_command(command: &mut Command) -> Result<ExitCode> {
    let run_dir = tempfile::Builder::new()
        .prefix("ghidra-test-run-")
        .tempdir()?;
    let started = std::time::Instant::now();
    let status = command
        .env(RUN_DIR_ENV, run_dir.path())
        .status()
        .context("Failed to run cargo test")?;
    eprintln!(
        "[test run] completed in {:.2}s",
        started.elapsed().as_secs_f64()
    );
    // Wait for all suites before deleting their shared, closed fixture source.
    run_dir
        .close()
        .context("Failed to remove test run fixtures")?;
    Ok(ExitCode::from(status.code().unwrap_or(1) as u8))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::process::Stdio;

    const CHILD_EXIT: &str = "XTASK_TEST_CHILD_EXIT";
    const CHILD_CWD: &str = "XTASK_TEST_CHILD_CWD";

    #[test]
    fn cargo_child() {
        let Some(exit) = std::env::var_os(CHILD_EXIT) else {
            return;
        };
        let arguments: Vec<_> = std::env::args_os().skip(1).collect();
        assert_eq!(arguments.len(), 8);
        for (index, argument) in arguments.iter().enumerate() {
            assert_eq!(
                argument,
                &std::env::var_os(format!("XTASK_TEST_ARG_{index}")).unwrap()
            );
        }
        assert_eq!(
            std::env::current_dir().unwrap(),
            PathBuf::from(std::env::var_os(CHILD_CWD).unwrap())
        );
        let run_dir = PathBuf::from(std::env::var_os(RUN_DIR_ENV).unwrap());
        assert!(run_dir.is_dir(), "Run fixture must live until Cargo exits");
        std::fs::create_dir(run_dir.join("analyzed")).unwrap();
        std::fs::write(run_dir.join("analyzed").join("fixture"), b"fixture").unwrap();
        std::process::exit(exit.to_str().unwrap().parse().unwrap());
    }

    fn run_dir(command: &Command) -> PathBuf {
        command
            .get_envs()
            .find_map(|(key, value)| (key == RUN_DIR_ENV).then(|| PathBuf::from(value.unwrap())))
            .unwrap()
    }

    #[test]
    fn cargo_status_and_fixture_lifetime_are_preserved() {
        for exit in [0, 7] {
            let args = [
                "--exact",
                "test::tests::cargo_child",
                "--nocapture",
                "--",
                "--nocapture",
                "path with 'quotes' and \\slashes",
                "日本語",
            ]
            .into_iter()
            .map(OsString::from)
            .collect();
            let mut command = cargo_command(std::env::current_exe().unwrap().as_os_str(), args);
            assert!(command.get_current_dir().is_none());
            let arguments: Vec<_> = command.get_args().map(OsStr::to_owned).collect();
            for (index, argument) in arguments.iter().enumerate() {
                command.env(format!("XTASK_TEST_ARG_{index}"), argument);
            }
            command
                .env(CHILD_EXIT, exit.to_string())
                .env(CHILD_CWD, std::env::current_dir().unwrap())
                .env(RUN_DIR_ENV, "must-be-replaced")
                .stdin(Stdio::null());

            assert_eq!(run_command(&mut command).unwrap(), ExitCode::from(exit));
            assert!(!run_dir(&command).exists(), "Run fixture leaked after exit");
        }
    }

    #[test]
    fn spawn_failure_removes_fixtures() {
        let root = tempfile::tempdir().unwrap();
        let mut command = cargo_command(root.path().join("missing-cargo").as_os_str(), vec![]);
        let error = run_command(&mut command).unwrap_err();
        assert!(error.to_string().contains("Failed to run cargo test"));
        assert!(
            !run_dir(&command).exists(),
            "Run fixture leaked on spawn failure"
        );
    }

    #[test]
    fn cargo_arguments_are_not_interpreted_or_reordered() {
        let args: Vec<_> = [
            "--help",
            "-h",
            "--manifest-path",
            "path with 'quotes' and \\slashes/Cargo.toml",
            "--",
            "--nocapture",
            "",
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        let command = cargo_command(OsStr::new("cargo"), args.clone());
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            std::iter::once(OsStr::new("test"))
                .chain(args.iter().map(OsString::as_os_str))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    #[cfg(any(unix, windows))]
    fn non_unicode_arguments_are_preserved() {
        #[cfg(unix)]
        let argument = {
            use std::os::unix::ffi::OsStringExt;
            OsString::from_vec(b"filter-\xff".to_vec())
        };
        #[cfg(windows)]
        let argument = {
            use std::os::windows::ffi::OsStringExt;
            OsString::from_wide(&[b'f' as u16, 0xd800])
        };
        let input = vec![OsString::from("test"), argument.clone()];
        let crate::Task::Test(args) = crate::parse(input).unwrap() else {
            panic!("test arguments must bypass parsing");
        };
        let command = cargo_command(OsStr::new("cargo"), args);
        assert_eq!(command.get_args().nth(1), Some(argument.as_os_str()));
    }
}
