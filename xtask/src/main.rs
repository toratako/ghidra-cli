use anyhow::{bail, Result};
use std::ffi::OsString;
use std::path::Path;
use std::process::ExitCode;

mod gen_tree;
mod test;

const HELP: &str = "Repository development tasks

Usage: cargo xtask <COMMAND>

Commands:
  test [ARGS]       Run cargo test with shared temporary fixtures
  gen-tree [--check] Generate docs/tree.md, or check that it is up to date

Options:
  -h, --help       Show this help

All arguments after test are forwarded unchanged to cargo test, including --help.
Tests inherit the current directory; gen-tree always uses the workspace root.

Examples:
  cargo xtask test --test comment_tests -- --nocapture
  cargo xtask gen-tree --check";

const GEN_TREE_HELP: &str = "Generate the CLI command tree in docs/tree.md

Usage: cargo xtask gen-tree [--check]

Options:
  --check          Fail if docs/tree.md differs; do not modify it
  -h, --help       Show this help";

#[derive(Debug, PartialEq, Eq)]
enum Task {
    Test(Vec<OsString>),
    GenTree { check: bool },
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
    if command == "gen-tree" {
        let mut check = false;
        let mut help = false;
        for arg in args {
            if arg == "--check" && !check {
                check = true;
            } else if (arg == "--help" || arg == "-h") && !help {
                help = true;
            } else {
                bail!("unexpected gen-tree argument: {arg:?}");
            }
        }
        return Ok(if help {
            Task::Help(GEN_TREE_HELP)
        } else {
            Task::GenTree { check }
        });
    }
    bail!("unknown command: {command:?}")
}

fn run() -> Result<ExitCode> {
    let task = parse(std::env::args_os().skip(1))
        .map_err(|error| anyhow::anyhow!("{error}\nRun `cargo xtask --help` for usage."))?;
    match task {
        Task::Test(args) => test::run(args),
        Task::GenTree { check } => {
            let root = Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .expect("xtask must be a workspace subdirectory");
            gen_tree::run(root, check)?;
            Ok(ExitCode::SUCCESS)
        }
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
            vec!["test", "gen-tree", "--check", "unknown", "--", "--"],
        ] {
            let arguments = args(&values);
            assert_eq!(
                parse(arguments.clone()).unwrap(),
                Task::Test(arguments[1..].to_vec())
            );
        }
    }

    #[test]
    fn help_and_tree_options_are_explicit() {
        for values in [vec![], vec!["--help"], vec!["-h"]] {
            assert_eq!(parse(args(&values)).unwrap(), Task::Help(HELP));
        }
        assert_eq!(
            parse(args(&["gen-tree"])).unwrap(),
            Task::GenTree { check: false }
        );
        assert_eq!(
            parse(args(&["gen-tree", "--check"])).unwrap(),
            Task::GenTree { check: true }
        );
        for help in ["--help", "-h"] {
            assert_eq!(
                parse(args(&["gen-tree", help])).unwrap(),
                Task::Help(GEN_TREE_HELP)
            );
        }
    }

    #[test]
    fn unknown_commands_and_tree_arguments_fail() {
        for values in [
            vec!["unknown"],
            vec!["--check"],
            vec!["--help", "extra"],
            vec!["gen-tree", "unexpected"],
            vec!["gen-tree", "--checks"],
            vec!["gen-tree", "--check", "--check"],
            vec!["gen-tree", "--", "--check"],
        ] {
            assert!(parse(args(&values)).is_err(), "{values:?}");
        }
    }
}
