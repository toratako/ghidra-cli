use crate::ipc::protocol::{BridgeCommandError, BridgeTimeoutError};

/// Retain every attempted result; stop on an unresolved save or running job.
pub(super) fn execute_batch(
    content: &str,
    mut execute: impl FnMut(&str) -> anyhow::Result<serde_json::Value>,
) -> anyhow::Result<serde_json::Value> {
    use serde_json::json;
    let lines: Vec<_> = content
        .lines()
        .enumerate()
        .map(|(index, line)| (index + 1, line.trim()))
        .filter(|(_, line)| !line.is_empty() && !line.starts_with('#'))
        .collect();
    let mut results = Vec::new();
    let mut failed = 0;
    let mut save_failed = false;
    let mut last_error = None;
    for (number, line) in &lines {
        let mut row = json!({"line": number, "command": line});
        match execute(line) {
            Ok(value) => row["result"] = value,
            Err(error) => {
                failed += 1;
                row["error"] = json!(error.to_string());
                let timeout = error.downcast_ref::<BridgeTimeoutError>().is_some();
                let mut stop = timeout;
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
            // error carries the batch results for normal JSON error rendering.
            Err(error.context(BridgeCommandError { message, detail }))
        }
        None => Ok(detail),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_keeps_successes_and_error_detail_and_returns_failure() {
        let error = execute_batch("# commands\nfirst\n\nconflict\nlast", |command| {
            if command == "conflict" {
                Err(BridgeCommandError {
                    message: "Already exists".to_owned(),
                    detail: serde_json::json!({"address": "1000"}),
                }
                .into())
            } else {
                Ok(serde_json::json!({"executed": command}))
            }
        })
        .unwrap_err();
        let detail = &error.downcast_ref::<BridgeCommandError>().unwrap().detail;
        assert_eq!(detail["commands_executed"], 3);
        assert_eq!(detail["failed"], 1);
        assert_eq!(detail["not_executed"], 0);
        assert_eq!(detail["results"][0]["result"]["executed"], "first");
        assert_eq!(detail["results"][1]["line"], 4);
        assert_eq!(detail["results"][1]["detail"]["address"], "1000");
        assert_eq!(detail["results"][2]["result"]["executed"], "last");
    }

    #[test]
    fn batch_stops_on_save_failure_including_at_end_of_nested_batch() {
        let mut calls = 0;
        let error = execute_batch("nested\nmust-not-run", |_| {
            calls += 1;
            execute_batch("edit", |_| Err(BridgeCommandError {
                message: "Auto-save failed".to_owned(),
                detail: serde_json::json!({"save_failed": true, "command_response": {"status": "success", "data": {"created": true}}}),
            }.into()))
        }).unwrap_err();
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

    #[test]
    fn batch_timeout_retains_exit_classification_and_stops() {
        let mut calls = 0;
        let error = execute_batch("slow\nmust-not-run", |_| {
            calls += 1;
            Err(BridgeTimeoutError {
                command: "slow".to_owned(),
                timeout_secs: 1,
            }
            .into())
        })
        .unwrap_err();
        assert_eq!(calls, 1);
        assert!(error.downcast_ref::<BridgeTimeoutError>().is_some());
        let detail = &error.downcast_ref::<BridgeCommandError>().unwrap().detail;
        assert_eq!(detail["results"][0]["exit_code"], 75);
        assert_eq!(detail["not_executed"], 1);
    }

    #[test]
    fn successful_batch_returns_all_results() {
        let result =
            execute_batch("first\nsecond", |command| Ok(serde_json::json!(command))).unwrap();
        assert_eq!(result["failed"], 0);
        assert_eq!(result["commands_executed"], 2);
        assert_eq!(result["results"][1]["result"], "second");
    }
}
