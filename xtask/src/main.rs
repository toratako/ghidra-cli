use anyhow::{bail, Result};
use std::ffi::OsString;
use std::path::Path;
use std::process::ExitCode;

mod fmt_java;
mod gen_tree;
mod test;

const HELP: &str = "Repository development tasks

Usage: cargo xtask <COMMAND>

Commands:
  test [ARGS]         Run cargo test with shared temporary fixtures
  gen-tree [--check]   Generate docs/tree.md, or check that it is up to date
  fmt-java [--check]   Format Java sources, or check their formatting

Options:
  -h, --help       Show this help

All arguments after test are forwarded unchanged to cargo test, including --help.
Tests inherit the current directory; other tasks use the workspace root.

Examples:
  cargo xtask test --test comment_tests -- --nocapture
  cargo xtask gen-tree --check
  cargo xtask fmt-java --check";

const GEN_TREE_HELP: &str = "Generate the CLI command tree in docs/tree.md

Usage: cargo xtask gen-tree [--check]

Options:
  --check          Fail if docs/tree.md differs; do not modify it
  -h, --help       Show this help";

const FMT_JAVA_HELP: &str = "Format Java sources under src/ and tests/ with google-java-format

Usage: cargo xtask fmt-java [--check]

Options:
  --check          List files needing formatting and fail; do not modify sources
  -h, --help       Show this help

Requires JDK 21+ and curl. The pinned formatter JAR is cached under target/.";

#[derive(Debug, PartialEq, Eq)]
enum Task {
    Test(Vec<OsString>),
    GenTree { check: bool },
    FmtJava { check: bool },
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
    if command == "gen-tree" || command == "fmt-java" {
        let mut check = false;
        let mut help = false;
        for arg in args {
            if arg == "--check" && !check {
                check = true;
            } else if (arg == "--help" || arg == "-h") && !help {
                help = true;
            } else {
                bail!("unexpected {} argument: {arg:?}", command.to_string_lossy());
            }
        }
        return Ok(if command == "gen-tree" {
            if help {
                Task::Help(GEN_TREE_HELP)
            } else {
                Task::GenTree { check }
            }
        } else if help {
            Task::Help(FMT_JAVA_HELP)
        } else {
            Task::FmtJava { check }
        });
    }
    bail!("unknown command: {command:?}")
}

fn run() -> Result<ExitCode> {
    let task = parse(std::env::args_os().skip(1))
        .map_err(|error| anyhow::anyhow!("{error}\nRun `cargo xtask --help` for usage."))?;
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask must be a workspace subdirectory");
    match task {
        Task::Test(args) => test::run(args),
        Task::GenTree { check } => {
            gen_tree::run(root, check)?;
            Ok(ExitCode::SUCCESS)
        }
        Task::FmtJava { check } => fmt_java::run(root, check),
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
    fn java_formatting_options_select_writing_checking_and_help() {
        assert_eq!(
            parse(args(&["fmt-java"])).unwrap(),
            Task::FmtJava { check: false }
        );
        assert_eq!(
            parse(args(&["fmt-java", "--check"])).unwrap(),
            Task::FmtJava { check: true }
        );
        for help in ["--help", "-h"] {
            assert_eq!(
                parse(args(&["fmt-java", help])).unwrap(),
                Task::Help(FMT_JAVA_HELP)
            );
        }
        assert!(parse(args(&["fmt-java", "unexpected"])).is_err());
        assert!(parse(args(&["fmt-java", "--check", "--check"])).is_err());
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
