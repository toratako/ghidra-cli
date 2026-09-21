use crate::cli::{BatchErrorPolicy, Cli, Commands};
use crate::ipc::protocol::{BridgeCommandError, BridgeTimeoutError};
use clap::Parser;
use serde_json::json;
use std::path::{Path, PathBuf};

/// Parsed commands and nested files are retained until execution finishes.
pub(super) struct PreparedBatch {
    lines: Vec<PreparedLine>,
    commands_parsed: usize,
}

pub(super) struct PreparedLine {
    number: usize,
    text: String,
    pub cli: Cli,
    pub nested: Option<PreparedBatch>,
}

struct SourceLine<'a> {
    file: &'a Path,
    number: usize,
    text: &'a str,
}

/// Validate the whole tree before starting a bridge or executing any command.
pub(super) fn prepare(
    file: &Path,
    validate: impl Fn(&Cli) -> anyhow::Result<()>,
) -> anyhow::Result<PreparedBatch> {
    let mut errors = Vec::new();
    let batch = read_batch(file, None, &mut Vec::new(), &mut errors, &validate);
    if !errors.is_empty() {
        let count = batch.as_ref().map_or(0, |batch| batch.commands_parsed);
        let diagnostics = errors
            .iter()
            .map(|error| {
                let file = error["file"].as_str().unwrap_or_default();
                let location = error["line"]
                    .as_u64()
                    .map_or_else(|| file.to_owned(), |line| format!("{file}:{line}"));
                format!(
                    "{location}: {}",
                    error["error"].as_str().unwrap_or_default()
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        return Err(BridgeCommandError {
            message: format!(
                "Batch validation failed: {} error(s); no commands executed.\n{diagnostics}",
                errors.len()
            ),
            detail: json!({
                "validation_failed": true,
                "commands_parsed": count,
                "commands_executed": 0,
                "failed": errors.len(),
                "not_executed": count,
                "results": [],
                "validation_errors": errors,
            }),
        }
        .into());
    }
    Ok(batch.expect("a missing batch has a validation error"))
}

fn read_batch(
    file: &Path,
    source: Option<&SourceLine<'_>>,
    active: &mut Vec<PathBuf>,
    errors: &mut Vec<serde_json::Value>,
    validate: &impl Fn(&Cli) -> anyhow::Result<()>,
) -> Option<PreparedBatch> {
    let loaded = (|| -> anyhow::Result<_> {
        // Resolve aliases only for cycle detection. Relative paths, including
        // nested batch paths, continue to use the invocation's working directory.
        let canonical = dunce::canonicalize(file).map_err(|error| {
            anyhow::anyhow!("Failed to read batch file {}: {error}", file.display())
        })?;
        anyhow::ensure!(
            !active.contains(&canonical),
            "Batch include cycle involving {}",
            file.display()
        );
        let content = std::fs::read_to_string(&canonical).map_err(|error| {
            anyhow::anyhow!("Failed to read batch file {}: {error}", file.display())
        })?;
        Ok((canonical, content))
    })();
    let (canonical, content) = match loaded {
        Ok(loaded) => loaded,
        Err(error) => {
            errors.push(json!({
                "file": source.map_or(file, |source| source.file),
                "line": source.map(|source| source.number),
                "command": source.map(|source| source.text),
                "error": error.to_string(),
            }));
            return None;
        }
    };
    active.push(canonical);
    let mut lines = Vec::new();
    let mut commands_parsed = 0;
    for (number, text) in command_lines(&content) {
        commands_parsed += 1;
        let parsed = split_arguments(text).and_then(|arguments| {
            Cli::try_parse_from(std::iter::once("ghidra-cli".to_owned()).chain(arguments))
                .map_err(anyhow::Error::from)
        });
        match parsed {
            Ok(cli) => {
                let source = SourceLine { file, number, text };
                if let Err(error) = validate(&cli) {
                    errors.push(json!({
                        "file": file, "line": number, "command": text.trim(),
                        "error": error.to_string(),
                    }));
                }
                let nested = if let Commands::Batch(args) = &cli.command {
                    read_batch(
                        Path::new(&args.script_file),
                        Some(&source),
                        active,
                        errors,
                        validate,
                    )
                } else {
                    None
                };
                lines.push(PreparedLine {
                    number,
                    text: text.to_owned(),
                    cli,
                    nested,
                });
            }
            Err(error) => {
                errors.push(json!({
                    "file": file, "line": number, "command": text.trim(),
                    "error": error.to_string(),
                }));
            }
        }
    }
    active.pop();
    Some(PreparedBatch {
        lines,
        commands_parsed,
    })
}

fn command_lines(content: &str) -> impl Iterator<Item = (usize, &str)> {
    content
        .lines()
        .enumerate()
        .map(|(index, line)| (index + 1, line.trim_start()))
        .filter(|(_, line)| !line.is_empty() && !line.starts_with('#'))
}

/// Split one command with shell-style quoting, without evaluating shell syntax.
pub(super) fn split_arguments(line: &str) -> anyhow::Result<Vec<String>> {
    let mut arguments = Vec::new();
    let mut argument = String::new();
    let mut started = false;
    let mut quote = None;
    let mut characters = line.chars();
    while let Some(character) = characters.next() {
        match (quote, character) {
            (Some('\''), '\'') | (Some('"'), '"') => quote = None,
            (Some('\''), _) => argument.push(character),
            (_, '\\') => {
                let escaped = characters
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("Invalid batch syntax: trailing escape"))?;
                // Within double quotes, backslashes only escape shell-special
                // characters; preserve them in paths and text such as "C:\temp".
                if quote == Some('"') && !matches!(escaped, '"' | '\\' | '$' | '`') {
                    argument.push('\\');
                }
                argument.push(escaped);
                started = true;
            }
            (None, '\'' | '"') => {
                quote = Some(character);
                started = true;
            }
            (None, _) if character.is_whitespace() => {
                if started {
                    arguments.push(std::mem::take(&mut argument));
                    started = false;
                }
            }
            _ => {
                argument.push(character);
                started = true;
            }
        }
    }
    if let Some(quote) = quote {
        let kind = if quote == '\'' { "single" } else { "double" };
        anyhow::bail!("Invalid batch syntax: unterminated {kind} quote");
    }
    if started {
        arguments.push(argument);
    }
    Ok(arguments)
}

/// Retain attempted results; transaction/save failures and timeouts always stop.
pub(super) fn execute_batch(
    batch: &PreparedBatch,
    on_error: BatchErrorPolicy,
    mut execute: impl FnMut(&PreparedLine) -> anyhow::Result<serde_json::Value>,
) -> anyhow::Result<serde_json::Value> {
    let lines = &batch.lines;
    let mut results = Vec::new();
    let mut failed = 0;
    let mut save_failed = false;
    let mut transaction_failed = false;
    let mut last_error = None;
    for line in lines {
        let mut row = json!({"line": line.number, "command": line.text.trim()});
        match execute(line) {
            Ok(value) => row["result"] = value,
            Err(error) => {
                failed += 1;
                row["error"] = json!(error.to_string());
                let timeout = error.downcast_ref::<BridgeTimeoutError>().is_some();
                let mut stop = timeout || on_error == BatchErrorPolicy::Stop;
                if let Some(error) = error.downcast_ref::<BridgeCommandError>() {
                    row["detail"] = error.detail.clone();
                    save_failed |=
                        error.detail.get("save_failed").and_then(|v| v.as_bool()) == Some(true);
                    transaction_failed |= error
                        .detail
                        .get("transaction_failed")
                        .and_then(|v| v.as_bool())
                        == Some(true);
                    stop |= save_failed || transaction_failed;
                }
                row["exit_code"] = json!(if timeout { 75 } else { 1 });
                last_error = Some(error);
                if stop {
                    results.push(row);
                    break;
                }
            }
        }
        results.push(row);
    }
    let not_executed = lines.len() - results.len();
    let mut detail = json!({
        "commands_parsed": lines.len(),
        "commands_executed": results.len(),
        "failed": failed,
        "not_executed": not_executed,
        "results": results,
    });
    if save_failed {
        detail["save_failed"] = json!(true);
    }
    if transaction_failed {
        detail["transaction_failed"] = json!(true);
    }
    match last_error {
        Some(error) => {
            let message = format!(
                "Batch failed: {failed} command(s) failed, {not_executed} not executed. \
                 Do not replay completed edits. Last error: {error}"
            );
            // Context preserves the timeout's type (exit 75) while the outer
            // error carries the batch report for the outer CLI output boundary.
            Err(error.context(BridgeCommandError { message, detail }))
        }
        None => Ok(detail),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn execute_test_batch(
        content: &str,
        policy: BatchErrorPolicy,
        mut execute: impl FnMut(&str) -> anyhow::Result<serde_json::Value>,
    ) -> anyhow::Result<serde_json::Value> {
        let lines: Vec<_> = command_lines(content)
            .map(|(number, text)| PreparedLine {
                number,
                text: text.to_owned(),
                cli: Cli::try_parse_from(["ghidra-cli", "program", "info"]).unwrap(),
                nested: None,
            })
            .collect();
        let batch = PreparedBatch {
            commands_parsed: lines.len(),
            lines,
        };
        execute_batch(&batch, policy, |line| execute(&line.text))
    }

    #[test]
    fn batch_arguments_preserve_quoted_and_escaped_values() {
        for (line, expected) in [
            ("  first\tsecond  ", vec!["first", "second"]),
            (
                r#"'' "" before"two words"after"#,
                vec!["", "", "beforetwo wordsafter"],
            ),
            (r#"'literal \ " $value'"#, vec![r#"literal \ " $value"#]),
            (
                r#"escaped\ space \'quote\' back\\slash"#,
                vec!["escaped space", "'quote'", r"back\slash"],
            ),
            (
                r#""say \"yes\" \$value \`name\` C:\temp \\""#,
                vec![r#"say "yes" $value `name` C:\temp \"#],
            ),
            (r#""日本語 のコメント""#, vec!["日本語 のコメント"]),
            (
                "$value $(command) `command` *.bin ; | >",
                vec!["$value", "$(command)", "`command`", "*.bin", ";", "|", ">"],
            ),
        ] {
            assert_eq!(split_arguments(line).unwrap(), expected, "{line}");
        }
    }

    #[test]
    fn prepared_batches_execute_the_validated_content_after_files_change() {
        let directory = tempfile::tempdir().unwrap();
        let outer = directory.path().join("outer.txt");
        let child = directory.path().join("child.txt");
        let child_argument = serde_json::to_string(&child).unwrap();
        std::fs::write(&outer, format!("batch {child_argument}\nprogram stats\n")).unwrap();
        std::fs::write(&child, "program info\n").unwrap();
        let prepared = prepare(&outer, |_| Ok(())).unwrap();

        // Replacing either source after preflight must not change what executes.
        std::fs::write(&outer, "comment set 0x1000 changed\n").unwrap();
        std::fs::remove_file(&child).unwrap();
        let mut executed = Vec::new();
        let report = execute_batch(&prepared, BatchErrorPolicy::Continue, |line| {
            if let Some(nested) = &line.nested {
                execute_batch(nested, BatchErrorPolicy::Continue, |line| {
                    executed.push(line.text.clone());
                    assert!(matches!(
                        line.cli.command,
                        Commands::Program(crate::cli::ProgramCommands::Info(_))
                    ));
                    Ok(json!({"name": "original"}))
                })
            } else {
                executed.push(line.text.clone());
                assert!(matches!(
                    line.cli.command,
                    Commands::Program(crate::cli::ProgramCommands::Stats(_))
                ));
                Ok(json!({"functions": 1}))
            }
        })
        .unwrap();
        assert_eq!(executed, ["program info", "program stats"]);
        assert_eq!(report["results"][0]["result"]["commands_executed"], 1);
        assert_eq!(report["results"][1]["result"]["functions"], 1);
    }

    #[test]
    fn batch_keeps_successes_and_error_detail_and_returns_failure() {
        for (policy, executed) in [(BatchErrorPolicy::Continue, 3), (BatchErrorPolicy::Stop, 2)] {
            let mut calls = Vec::new();
            let error = execute_test_batch("# commands\nfirst\n\nconflict\nlast", policy, |command| {
                calls.push(command.to_owned());
                if command == "conflict" {
                    Err(BridgeCommandError {
                        message: "Already exists".to_owned(),
                        detail: serde_json::json!({"address": "0x1000", "partial_changes_saved": true}),
                    }
                    .into())
                } else {
                    Ok(serde_json::json!({"executed": command}))
                }
            })
            .unwrap_err();
            let detail = &error.downcast_ref::<BridgeCommandError>().unwrap().detail;
            assert_eq!(calls.len(), executed);
            assert_eq!(detail["commands_parsed"], 3);
            assert_eq!(detail["commands_executed"], executed);
            assert_eq!(detail["failed"], 1);
            assert_eq!(detail["not_executed"], 3 - executed);
            assert_eq!(detail["results"][0]["result"]["executed"], "first");
            assert_eq!(detail["results"][1]["line"], 4);
            assert_eq!(detail["results"][1]["detail"]["address"], "0x1000");
            assert_eq!(
                detail["results"][1]["detail"]["partial_changes_saved"],
                true
            );
            if policy == BatchErrorPolicy::Continue {
                assert_eq!(detail["results"][2]["result"]["executed"], "last");
            }
        }
    }

    #[test]
    fn batch_stops_on_transaction_or_save_failure_including_at_end_of_nested_batch() {
        for flag in ["save_failed", "transaction_failed"] {
            for policy in [BatchErrorPolicy::Continue, BatchErrorPolicy::Stop] {
                let mut calls = 0;
                let error = execute_test_batch("nested\nmust-not-run", policy, |_| {
                    calls += 1;
                    execute_test_batch("edit", policy, |_| {
                        Err(BridgeCommandError {
                            message: "Request finalization failed".to_owned(),
                            detail: serde_json::json!({
                                flag: true,
                                "command_response": {"status": "success", "data": {"created": true}},
                            }),
                        }
                        .into())
                    })
                })
                .unwrap_err();
                let detail = &error.downcast_ref::<BridgeCommandError>().unwrap().detail;
                assert_eq!(calls, 1);
                assert_eq!(detail["not_executed"], 1);
                assert_eq!(detail[flag], true);
                assert_eq!(detail["results"][0]["detail"][flag], true);
                assert_eq!(
                    detail["results"][0]["detail"]["results"][0]["detail"]["command_response"]
                        ["data"]["created"],
                    true
                );
            }
        }
    }

    #[test]
    fn batch_can_continue_after_completed_request_rollback() {
        let mut calls = 0;
        let error =
            execute_test_batch("failed-edit\nnext-edit", BatchErrorPolicy::Continue, |_| {
                calls += 1;
                if calls == 1 {
                    Err(BridgeCommandError {
                        message: "Edit failed".to_owned(),
                        detail: serde_json::json!({"rolled_back": true}),
                    }
                    .into())
                } else {
                    Ok(serde_json::json!({"created": true}))
                }
            })
            .unwrap_err();
        let detail = &error.downcast_ref::<BridgeCommandError>().unwrap().detail;
        assert_eq!(calls, 2);
        assert_eq!(detail["not_executed"], 0);
        assert_eq!(detail["results"][0]["detail"]["rolled_back"], true);
        assert_eq!(detail["results"][1]["result"]["created"], true);
        assert!(detail.get("save_failed").is_none());
        assert!(detail.get("transaction_failed").is_none());
    }

    #[test]
    fn batch_timeout_retains_exit_classification_and_stops() {
        for policy in [BatchErrorPolicy::Continue, BatchErrorPolicy::Stop] {
            let mut calls = 0;
            let error = execute_test_batch("nested\nmust-not-run", policy, |_| {
                calls += 1;
                execute_test_batch("slow\nmust-not-run", policy, |command| {
                    assert_eq!(command, "slow");
                    Err(BridgeTimeoutError {
                        command: "slow".to_owned(),
                        timeout_secs: 1,
                    }
                    .into())
                })
            })
            .unwrap_err();
            assert_eq!(calls, 1);
            assert!(error.downcast_ref::<BridgeTimeoutError>().is_some());
            let detail = &error.downcast_ref::<BridgeCommandError>().unwrap().detail;
            assert_eq!(detail["results"][0]["exit_code"], 75);
            assert_eq!(
                detail["results"][0]["detail"]["results"][0]["exit_code"],
                75
            );
            assert_eq!(detail["results"][0]["detail"]["not_executed"], 1);
            assert_eq!(detail["not_executed"], 1);
        }
    }

    #[test]
    fn successful_batch_returns_all_results() {
        for policy in [BatchErrorPolicy::Continue, BatchErrorPolicy::Stop] {
            let result = execute_test_batch("first\nsecond", policy, |command| {
                Ok(serde_json::json!(command))
            })
            .unwrap();
            assert_eq!(result["failed"], 0);
            assert_eq!(result["commands_executed"], 2);
            assert_eq!(result["results"][1]["result"], "second");
        }
    }
}
