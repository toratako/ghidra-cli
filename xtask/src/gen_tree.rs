use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use anyhow::{bail, ensure, Context, Result};
use clap::{Command, CommandFactory};
use ghidra_cli::cli::Cli;

const HEADER: &str = "\
# ghidra-cli command tree

Generated from `src/cli.rs` and `src/cli/*.rs` using Clap's `CommandFactory`.
Automatically generated `help` commands, arguments, and options are omitted.
Command aliases are not supported.
For command details, run `ghidra-cli <command> --help`.

Regenerate from the repository root with `cargo xtask gen-tree`.
Run `cargo xtask gen-tree --check` to verify that this document is current.

```text
";

pub(crate) fn run(workspace_root: &Path, check: bool) -> Result<()> {
    let path = workspace_root.join("docs").join("tree.md");
    let generated = render_document(Cli::command())?;

    match fs::read_to_string(&path) {
        // Git may check out CRLF on Windows. Preserve those files when their
        // content is current; other whitespace remains significant.
        Ok(current) if current.replace("\r\n", "\n") == generated => return Ok(()),
        Ok(_) if check => {
            bail!(
                "{} is out of date; run `cargo xtask gen-tree` from the repository root",
                path.display()
            );
        }
        Ok(_) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {
            if check {
                bail!(
                    "{} is missing; run `cargo xtask gen-tree` from the repository root",
                    path.display()
                );
            }
        }
        Err(error) => {
            return Err(error).with_context(|| format!("failed to read {}", path.display()));
        }
    }

    fs::write(&path, generated).with_context(|| format!("failed to write {}", path.display()))
}

fn render_document(mut command: Command) -> Result<String> {
    // Build the CLI before introspection; rendering omits automatic help branches.
    command.build();

    let mut document = String::from(HEADER);
    document.push_str(command.get_name());
    document.push('\n');
    let count = append_subcommands(&command, "", &mut document)?;
    document.push_str(&format!(
        "```\n\n{count} command nodes (excluding the root), 0 aliases.\n"
    ));
    Ok(document)
}

fn append_subcommands(command: &Command, prefix: &str, output: &mut String) -> Result<usize> {
    ensure!(
        command.get_all_aliases().next().is_none()
            && command.get_all_short_flag_aliases().next().is_none()
            && command.get_all_long_flag_aliases().next().is_none(),
        "command `{}` declares aliases, but command aliases are not supported",
        command.get_name()
    );

    // Introspection retains declaration order, unlike sorting help output.
    let mut subcommands = command
        .get_subcommands()
        .filter(|subcommand| subcommand.get_name() != "help")
        .peekable();
    let mut count = 0;
    while let Some(subcommand) = subcommands.next() {
        let last = subcommands.peek().is_none();
        output.push_str(prefix);
        output.push_str(if last { "└── " } else { "├── " });
        output.push_str(subcommand.get_name());
        output.push('\n');

        let child_prefix = format!("{prefix}{}", if last { "    " } else { "│   " });
        count += 1 + append_subcommands(subcommand, &child_prefix, output)?;
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use std::fs::{FileTimes, OpenOptions};
    use std::time::{Duration, SystemTime};

    use clap::Arg;

    use super::*;

    #[test]
    fn renders_declaration_order_and_count_without_help_branches_or_arguments() {
        let command = Command::new("demo")
            .arg(Arg::new("ignored-option").long("ignored-option"))
            .subcommand(
                Command::new("zeta")
                    .display_order(99)
                    .subcommand(Command::new("second").arg(Arg::new("ignored-argument")))
                    .subcommand(Command::new("first")),
            )
            .subcommand(Command::new("alpha").display_order(0));
        let expected_tree = "\
demo
├── zeta
│   ├── second
│   └── first
└── alpha
```

4 command nodes (excluding the root), 0 aliases.
";

        assert_eq!(
            render_document(command).unwrap(),
            format!("{HEADER}{expected_tree}")
        );
    }

    #[test]
    fn a_leaf_command_does_not_count_the_root_or_invent_help_commands() {
        assert_eq!(
            render_document(Command::new("demo")).unwrap(),
            format!("{HEADER}demo\n```\n\n0 command nodes (excluding the root), 0 aliases.\n")
        );
    }

    #[test]
    fn generation_creates_and_replaces_the_document_from_the_real_cli() {
        let workspace = tempfile::tempdir().unwrap();
        fs::create_dir(workspace.path().join("docs")).unwrap();
        let path = workspace.path().join("docs").join("tree.md");
        let expected = render_document(Cli::command()).unwrap();

        run(workspace.path(), false).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), expected);
        assert!(expected.contains("```text\nghidra-cli\n├── project\n"));

        fs::write(&path, "outdated documentation\n").unwrap();
        run(workspace.path(), false).unwrap();
        assert_eq!(fs::read_to_string(path).unwrap(), expected);
    }

    #[test]
    fn current_documents_are_not_written_in_either_mode_with_lf_or_crlf() {
        let workspace = tempfile::tempdir().unwrap();
        fs::create_dir(workspace.path().join("docs")).unwrap();
        let path = workspace.path().join("docs").join("tree.md");
        let generated = render_document(Cli::command()).unwrap();

        for contents in [generated.clone(), generated.replace('\n', "\r\n")] {
            for check in [false, true] {
                fs::write(&path, &contents).unwrap();
                let modified = set_old_modified_time(&path);

                run(workspace.path(), check).unwrap();

                assert_eq!(fs::read_to_string(&path).unwrap(), contents);
                assert_eq!(fs::metadata(&path).unwrap().modified().unwrap(), modified);
            }
        }
    }

    #[test]
    fn check_rejects_stale_content_without_writing_or_ignoring_whitespace() {
        let workspace = tempfile::tempdir().unwrap();
        fs::create_dir(workspace.path().join("docs")).unwrap();
        let path = workspace.path().join("docs").join("tree.md");
        let mut stale = render_document(Cli::command()).unwrap();
        stale.push('\n');
        fs::write(&path, &stale).unwrap();
        let modified = set_old_modified_time(&path);

        let error = run(workspace.path(), true).unwrap_err().to_string();

        assert!(error.contains("out of date"), "{error}");
        assert!(error.contains("cargo xtask gen-tree"), "{error}");
        assert!(error.contains(&path.display().to_string()), "{error}");
        assert_eq!(fs::read_to_string(&path).unwrap(), stale);
        assert_eq!(fs::metadata(path).unwrap().modified().unwrap(), modified);
    }

    #[test]
    fn check_rejects_a_missing_document_without_creating_files_or_directories() {
        let workspace = tempfile::tempdir().unwrap();
        let error = run(workspace.path(), true).unwrap_err().to_string();

        assert!(error.contains("missing"), "{error}");
        assert!(error.contains("cargo xtask gen-tree"), "{error}");
        assert_eq!(fs::read_dir(workspace.path()).unwrap().count(), 0);

        // Also cover a missing file in an existing docs directory.
        let docs = workspace.path().join("docs");
        fs::create_dir(&docs).unwrap();
        assert!(run(workspace.path(), true).is_err());
        assert_eq!(fs::read_dir(docs).unwrap().count(), 0);
    }

    fn set_old_modified_time(path: &Path) -> SystemTime {
        let file = OpenOptions::new().write(true).open(path).unwrap();
        file.set_times(
            FileTimes::new()
                .set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000)),
        )
        .unwrap();
        fs::metadata(path).unwrap().modified().unwrap()
    }
}
