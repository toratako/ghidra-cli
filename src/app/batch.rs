use crate::cli::BatchErrorPolicy;
use crate::ipc::protocol::{BridgeCommandError, BridgeTimeoutError};

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

/// Retain attempted results; save failures and timeouts always stop execution.
pub(super) fn execute_batch(
    content: &str,
    on_error: BatchErrorPolicy,
    mut execute: impl FnMut(&str) -> anyhow::Result<serde_json::Value>,
) -> anyhow::Result<serde_json::Value> {
    use serde_json::json;
    let lines: Vec<_> = content
        .lines()
        .enumerate()
        .map(|(index, line)| (index + 1, line.trim_start()))
        .filter(|(_, line)| !line.is_empty() && !line.starts_with('#'))
        .collect();
    let mut results = Vec::new();
    let mut failed = 0;
    let mut save_failed = false;
    let mut last_error = None;
    for (number, line) in &lines {
        let mut row = json!({"line": number, "command": line.trim()});
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
                    stop |= save_failed;
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
    fn batch_keeps_successes_and_error_detail_and_returns_failure() {
        for (policy, executed) in [(BatchErrorPolicy::Continue, 3), (BatchErrorPolicy::Stop, 2)] {
            let mut calls = Vec::new();
            let error = execute_batch("# commands\nfirst\n\nconflict\nlast", policy, |command| {
                calls.push(command.to_owned());
                if command == "conflict" {
                    Err(BridgeCommandError {
                        message: "Already exists".to_owned(),
                        detail: serde_json::json!({"address": "1000", "partial_changes_saved": true}),
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
            assert_eq!(detail["results"][1]["detail"]["address"], "1000");
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
    fn batch_stops_on_save_failure_including_at_end_of_nested_batch() {
        for policy in [BatchErrorPolicy::Continue, BatchErrorPolicy::Stop] {
            let mut calls = 0;
            let error = execute_batch("nested\nmust-not-run", policy, |_| {
                calls += 1;
                execute_batch("edit", policy, |_| {
                    Err(BridgeCommandError {
                        message: "Auto-save failed".to_owned(),
                        detail: serde_json::json!({
                            "save_failed": true,
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
            assert_eq!(detail["save_failed"], true);
            assert_eq!(
                detail["results"][0]["detail"]["results"][0]["detail"]["command_response"]["data"]
                    ["created"],
                true
            );
        }
    }

    #[test]
    fn batch_timeout_retains_exit_classification_and_stops() {
        for policy in [BatchErrorPolicy::Continue, BatchErrorPolicy::Stop] {
            let mut calls = 0;
            let error = execute_batch("nested\nmust-not-run", policy, |_| {
                calls += 1;
                execute_batch("slow\nmust-not-run", policy, |command| {
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
            let result = execute_batch("first\nsecond", policy, |command| {
                Ok(serde_json::json!(command))
            })
            .unwrap();
            assert_eq!(result["failed"], 0);
            assert_eq!(result["commands_executed"], 2);
            assert_eq!(result["results"][1]["result"], "second");
        }
    }
}
