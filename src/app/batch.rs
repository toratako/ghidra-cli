mod recovery;

pub(super) use recovery::{add_recovery, in_project};

use crate::cli::{BatchErrorPolicy, Cli, Commands};
use crate::ipc::protocol::{BridgeCommandError, BridgeOutcomeUnknownError, BridgeTimeoutError};
use clap::Parser;
use serde_json::json;
use std::path::{Path, PathBuf};

/// Parsed commands and nested files are retained until execution finishes.
pub(super) struct PreparedBatch {
    file: PathBuf,
    from_line: usize,
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
    from_line: Option<usize>,
    validate: impl Fn(&Cli) -> anyhow::Result<()>,
) -> anyhow::Result<PreparedBatch> {
    let mut errors = Vec::new();
    let batch = read_batch(
        file,
        from_line,
        None,
        &mut Vec::new(),
        &mut errors,
        &validate,
    );
    report_validation_errors(file, from_line, batch.as_ref(), errors)?;
    Ok(batch.expect("a missing batch has a validation error"))
}

/// Check configuration-dependent bounds on the already frozen command tree.
pub(super) fn validate_prepared(
    batch: &PreparedBatch,
    validate: impl Fn(&Cli) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    fn visit(
        batch: &PreparedBatch,
        errors: &mut Vec<serde_json::Value>,
        validate: &impl Fn(&Cli) -> anyhow::Result<()>,
    ) {
        for line in &batch.lines {
            if let Err(error) = validate(&line.cli) {
                errors.push(json!({
                    "file": batch.file, "line": line.number,
                    "command": line.text.trim(), "error": error.to_string(),
                }));
            }
            if let Some(nested) = &line.nested {
                visit(nested, errors, validate);
            }
        }
    }

    let mut errors = Vec::new();
    visit(batch, &mut errors, &validate);
    report_validation_errors(&batch.file, Some(batch.from_line), Some(batch), errors)
}

fn report_validation_errors(
    file: &Path,
    from_line: Option<usize>,
    batch: Option<&PreparedBatch>,
    errors: Vec<serde_json::Value>,
) -> anyhow::Result<()> {
    if !errors.is_empty() {
        let count = batch.map_or(0, |batch| batch.commands_parsed);
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
                "Batch validation failed: {} error(s); no commands executed.\n{diagnostics}\n\
                 Fix the validation errors, then rerun the same batch range.",
                errors.len()
            ),
            detail: json!({
                "file": file,
                "from_line": from_line.unwrap_or(1),
                "validation_failed": true,
                "commands_parsed": count,
                "commands_executed": 0,
                "failed": errors.len(),
                "not_executed": count,
                "results": [],
                "validation_errors": errors,
                "recovery": {
                    "action": "fix_input",
                    "file": file,
                    "from_line": from_line.unwrap_or(1),
                    "message": "Fix the validation errors, then rerun the same batch range; no commands were executed.",
                },
            }),
        }
        .into());
    }
    Ok(())
}

fn read_batch(
    file: &Path,
    from_line: Option<usize>,
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
    if let Some(start) = from_line {
        let count = content.lines().count();
        if start == 0 || start > count {
            errors.push(json!({
                "file": file, "line": start,
                "error": format!("Starting line {start} is outside this file ({count} source lines)"),
            }));
        }
    }
    let mut lines = Vec::new();
    let mut commands_parsed = 0;
    for (number, text) in command_lines(&content).filter(|(n, _)| *n >= from_line.unwrap_or(1)) {
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
                        args.from_line.map(|line| line.get()),
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
        file: file.to_owned(),
        from_line: from_line.unwrap_or(1),
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

/// Retain attempted results; transaction/save failures and unknown outcomes stop.
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
    let mut outcome_unknown = false;
    let mut last_error = None;
    for line in lines {
        let mut row = json!({"line": line.number, "command": line.text.trim()});
        match execute(line) {
            Ok(value) => row["result"] = value,
            Err(error) => {
                failed += 1;
                row["error"] = json!(error.to_string());
                if let Some(target) = error.downcast_ref::<recovery::CommandTarget>() {
                    row["project"] = json!(target.project);
                }
                let timeout = error.downcast_ref::<BridgeTimeoutError>().is_some();
                let unknown = error.downcast_ref::<BridgeOutcomeUnknownError>().is_some();
                outcome_unknown |= timeout || unknown;
                let mut stop = timeout || unknown || on_error == BatchErrorPolicy::Stop;
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
                if timeout || unknown {
                    if !row["detail"].is_object() {
                        row["detail"] = json!({});
                    }
                    row["detail"]["outcome_unknown"] = json!(true);
                    if let Some(job) = error.downcast_ref::<crate::ipc::protocol::BridgeJob>() {
                        row["detail"]["job_id"] = json!(job.id);
                        row["detail"]["command"] = json!(job.command);
                    }
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
        "file": batch.file,
        "from_line": batch.from_line,
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
    if outcome_unknown {
        detail["outcome_unknown"] = json!(true);
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
mod tests;
