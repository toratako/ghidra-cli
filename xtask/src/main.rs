use anyhow::{bail, Result};
use std::ffi::OsString;
use std::process::ExitCode;

mod test;

const HELP: &str = "Repository development tasks

Usage: cargo xtask <COMMAND>

Commands:
  test [ARGS]       Run cargo test with shared temporary fixtures

Options:
  -h, --help       Show this help

All arguments after test are forwarded unchanged to cargo test, including --help.
Tests inherit the current directory.

Examples:
  cargo xtask test --test comment_tests -- --nocapture";

#[derive(Debug, PartialEq, Eq)]
enum Task {
    Test(Vec<OsString>),
    Help(&'static str),
}

fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Task> {
    let mut args = args.into_iter();
    let Some(command) = args.next() else {
        return Ok(Task::Help(HELP));
    };
    if command == "test" {
        return Ok(Task::Test(args.collect()));
    }
    if command == "--help" || command == "-h" {
        if let Some(arg) = args.next() {
            bail!("unexpected argument: {arg:?}");
        }
        return Ok(Task::Help(HELP));
    }
    bail!("unknown command: {command:?}")
}

fn run() -> Result<ExitCode> {
    let task = parse(std::env::args_os().skip(1))
        .map_err(|error| anyhow::anyhow!("{error}\nRun `cargo xtask --help` for usage."))?;
    match task {
        Task::Test(args) => test::run(args),
        Task::Help(help) => {
            println!("{help}");
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("xtask: {error:#}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn test_arguments_bypass_option_parsing() {
        for values in [
            vec!["test"],
            vec!["test", "--help"],
            vec!["test", "-h"],
            vec!["test", "--test", "comment_tests", "--", "--nocapture"],
            vec!["test", "filter", "--unknown", "--", "--"],
        ] {
            let arguments = args(&values);
            assert_eq!(
                parse(arguments.clone()).unwrap(),
                Task::Test(arguments[1..].to_vec())
            );
        }
    }

    #[test]
    fn help_is_explicit() {
        for values in [vec![], vec!["--help"], vec!["-h"]] {
            assert_eq!(parse(args(&values)).unwrap(), Task::Help(HELP));
        }
    }

    #[test]
    fn unknown_commands_and_help_arguments_fail() {
        for values in [vec!["unknown"], vec!["--unknown"], vec!["--help", "extra"]] {
            assert!(parse(args(&values)).is_err(), "{values:?}");
        }
    }
}
