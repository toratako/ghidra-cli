use super::PreparedBatch;
use crate::app::recovery::render_command;
use crate::app::{options, project};
use crate::cli::Cli;
use crate::ipc::protocol::BridgeCommandError;
use serde::Serialize;
use serde_json::Value;
use std::path::{Path, PathBuf};

/// Preserve the resolved project even when the command fails before returning data.
#[derive(Debug)]
pub(crate) struct CommandTarget {
    pub project: PathBuf,
    message: String,
}

impl std::fmt::Display for CommandTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

pub(crate) fn in_project(error: anyhow::Error, project: &Path) -> anyhow::Error {
    let message = if error.downcast_ref::<BridgeCommandError>().is_some() {
        error.to_string()
    } else {
        format!("{error:#}")
    };
    error.context(CommandTarget {
        project: project.to_owned(),
        message,
    })
}

#[derive(Clone, Serialize)]
struct Location {
    file: String,
    line: u64,
}

struct Failure<'a> {
    row: &'a Value,
    location: Location,
    parents: Vec<Location>,
}

#[derive(Serialize)]
struct Recovery {
    action: &'static str,
    reason: &'static str,
    #[serde(flatten)]
    location: Location,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    parents: Vec<Location>,
    project: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    program: Option<String>,
    working_directory: PathBuf,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    argv: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    job_id: Option<String>,
}

fn failures<'a>(report: &'a Value, parents: &[Location], found: &mut Vec<Failure<'a>>) {
    let Some(rows) = report["results"].as_array() else {
        return;
    };
    for row in rows.iter().filter(|row| row.get("error").is_some()) {
        let location = Location {
            file: report["file"].as_str().unwrap_or_default().to_owned(),
            line: row["line"].as_u64().unwrap_or_default(),
        };
        if row["detail"]["results"].is_array() {
            let mut parents = parents.to_vec();
            parents.push(location);
            failures(&row["detail"], &parents, found);
        } else {
            found.push(Failure {
                row,
                location,
                parents: parents.to_vec(),
            });
        }
    }
}

fn inspection_reason(row: &Value) -> Option<&'static str> {
    let detail = &row["detail"];
    if row["exit_code"] == 75 {
        Some("timeout")
    } else if detail["outcome_unknown"] == true {
        Some("outcome_unknown")
    } else if detail["save_failed"] == true {
        Some("save_failed")
    } else if detail["transaction_failed"] == true {
        Some("transaction_failed")
    } else if detail["partial_changes_saved"] == true {
        Some("partial_changes_saved")
    } else if detail["rolled_back"] == true {
        None
    } else {
        Some("unconfirmed_failure")
    }
}

fn continued_after_failure(report: &Value) -> bool {
    let Some(rows) = report["results"].as_array() else {
        return false;
    };
    rows.iter().enumerate().any(|(index, row)| {
        row.get("error").is_some()
            && (index + 1 < rows.len() || continued_after_failure(&row["detail"]))
    })
}

fn describe(report: &Value, project: &Path) -> Option<Recovery> {
    let mut found = Vec::new();
    failures(report, &[], &mut found);
    let first = found.first()?;
    // An earlier failed script or partially saved command also matters when a
    // later ordinary error was rolled back under --on-error continue.
    let unsafe_failure = found
        .iter()
        .rev()
        .find_map(|failure| inspection_reason(failure.row).map(|reason| (failure, reason)));
    let (failure, action, reason, message) = if let Some((failure, reason)) = unsafe_failure {
        let message = match reason {
            "timeout" | "outcome_unknown" => "The command may still be running or may already have completed. Inspect jobs and the program state before choosing a restart line.",
            "save_failed" => "Changes may remain in memory. Keep the bridge running, resolve the save failure, then retry program save for this project. Inspect the command result before choosing a restart line; do not repeat the edit.",
            "transaction_failed" => "Rollback is unconfirmed. Keep the bridge running and close outstanding transactions through their owner before saving or retrying.",
            "partial_changes_saved" => "Partial changes were saved. Inspect the program and any external effects before choosing a restart line.",
            _ => "Rollback has not been confirmed. Inspect this command's result and any program or external effects before retrying.",
        };
        (failure, "inspect_state", reason, message)
    } else if found.len() > 1 || continued_after_failure(report) {
        (first, "review_results", "continued_execution", "Other commands ran after a failure. Review all results and retry only failed or unexecuted operations; restarting at the first failure would replay completed commands.")
    } else if !first.parents.is_empty() {
        (first, "review_results", "nested_batch", "Resume the failed child batch first, then the unexecuted parent commands. Review the nested results; restarting the parent's batch line would replay completed child commands.")
    } else {
        (first, "resume_from_line", "rolled_back", "Changes from the failed command were rolled back. Fix the indicated source line, then resume from that line.")
    };
    Some(Recovery {
        action,
        reason,
        location: failure.location.clone(),
        parents: failure.parents.clone(),
        project: failure.row["project"]
            .as_str()
            .map(PathBuf::from)
            .unwrap_or_else(|| project.to_owned()),
        program: failure.row["detail"]["program"]
            .as_str()
            .filter(|name| !name.is_empty())
            .map(str::to_owned),
        working_directory: std::env::current_dir().ok()?,
        message: message.to_owned(),
        argv: None,
        job_id: failure.row["detail"]["job_id"].as_str().map(str::to_owned),
    })
}

/// A single --program can restore one project's selection. Do not suggest it
/// for a suffix that depends on other projects' independently selected programs.
fn same_project(
    batch: &PreparedBatch,
    from_line: u64,
    root: &Path,
    projects_dir: &Option<PathBuf>,
) -> bool {
    batch
        .lines
        .iter()
        .filter(|line| line.number as u64 >= from_line)
        .all(|line| {
            let cli = &line.cli;
            let dir = cli.projects_dir.as_ref().or(projects_dir.as_ref()).cloned();
            let target =
                options::extract_project_from_command(&cli.command).or_else(|| cli.project.clone());
            let path = match target {
                Some(target) => project::load_config(&dir)
                    .and_then(|config| project::resolve_project_path(&Some(target), &config)),
                None => Ok(root.to_owned()),
            };
            path.is_ok_and(|path| path == root)
                && line
                    .nested
                    .as_ref()
                    .is_none_or(|nested| same_project(nested, nested.from_line as u64, root, &dir))
        })
}

fn command(cli: &Cli, args: &[&str], project: &Path) -> Vec<String> {
    let mut argv = vec!["ghidra-cli".to_owned()];
    if let Some(dir) = &cli.projects_dir {
        argv.push(format!("--projects-dir={}", dir.display()));
    }
    argv.extend(args.iter().map(|arg| (*arg).to_owned()));
    argv.extend([
        "--project".to_owned(),
        project.to_string_lossy().into_owned(),
    ]);
    argv
}

pub(crate) fn add_recovery(
    error: anyhow::Error,
    batch: &PreparedBatch,
    cli: &Cli,
    project: &Path,
) -> anyhow::Error {
    let Some(report) = error.downcast_ref::<BridgeCommandError>() else {
        return error;
    };
    let Some(mut recovery) = describe(&report.detail, project) else {
        return error;
    };
    if recovery.action == "resume_from_line" {
        let same_target = recovery.project == project
            && same_project(batch, recovery.location.line, project, &cli.projects_dir);
        if let Some(program) = recovery.program.as_ref().filter(|_| same_target) {
            let mut argv = command(cli, &["batch"], project);
            argv.extend([
                "--from-line".to_owned(),
                recovery.location.line.to_string(),
                "--on-error".to_owned(),
                "stop".to_owned(),
                "--program".to_owned(),
                program.clone(),
                "--".to_owned(),
                batch.file.to_string_lossy().into_owned(),
            ]);
            recovery.argv = Some(argv);
        } else {
            recovery.action = "review_results";
            recovery.reason = "target_context";
            recovery.message = "Changes from the failed command were rolled back. Verify the selected program in every project used by the remaining commands before resuming; a single restart command cannot restore the target context.".to_owned();
        }
    } else if matches!(recovery.reason, "timeout" | "outcome_unknown") {
        if let Some(id) = recovery.job_id.as_deref() {
            recovery.action = "retrieve_result";
            recovery.message = "Retrieve this bridge operation's result before choosing a restart line. One batch line can send multiple operations; check the returned command before resuming.".to_owned();
            recovery.argv = Some(command(cli, &["job", "result", id], &recovery.project));
        } else {
            recovery.argv = Some(command(cli, &["job", "list"], &recovery.project));
        }
    } else if recovery.reason == "save_failed" {
        recovery.argv = Some(command(cli, &["program", "save"], &recovery.project));
    }
    let mut message = format!(
        "{}\n{}:{}: {}",
        report.message, recovery.location.file, recovery.location.line, recovery.message
    );
    if let Some(argv) = &recovery.argv {
        message.push_str(&format!(
            "\nRun from {}:\n{}",
            recovery.working_directory.display(),
            render_command(argv)
        ));
    }
    let mut detail = report.detail.clone();
    detail["recovery"] = serde_json::to_value(recovery).expect("batch recovery is serializable");
    error.context(BridgeCommandError { message, detail })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn partial_or_unconfirmed_edits_take_precedence_over_later_rollbacks() {
        for (detail, reason) in [
            (
                json!({"partial_changes_saved": true}),
                "partial_changes_saved",
            ),
            (json!({"transaction_failed": true}), "transaction_failed"),
            (json!({}), "unconfirmed_failure"),
        ] {
            let report = json!({"file": "edits.ghidra", "results": [
                {"line": 4, "error": "first", "detail": detail},
                {"line": 5, "error": "later", "detail": {"rolled_back": true, "program": "/B"}},
            ]});
            let recovery = describe(&report, Path::new("project")).unwrap();
            assert_eq!(recovery.action, "inspect_state");
            assert_eq!(recovery.reason, reason);
            assert_eq!(recovery.location.line, 4);
            assert!(recovery.argv.is_none());
        }
    }

    #[test]
    fn nested_continuation_is_not_a_contiguous_restart() {
        let report = json!({"file": "parent.ghidra", "results": [
            {"line": 2, "error": "child failed", "detail": {
                "file": "child.ghidra", "results": [
                    {"line": 10, "error": "rejected", "detail": {"rolled_back": true}},
                    {"line": 11, "result": {}},
                ]
            }}
        ]});
        let recovery = describe(&report, Path::new("project")).unwrap();
        assert_eq!(recovery.reason, "continued_execution");
        assert_eq!(recovery.location.file, "child.ghidra");
        assert_eq!(recovery.location.line, 10);
        assert!(recovery.argv.is_none());
    }

    #[test]
    fn rendered_commands_quote_paths_and_shell_syntax() {
        let argv = vec![
            "ghidra-cli",
            "batch",
            "日本語's batch.ghidra",
            r"C:\a b\",
            "$(echo injected)",
            "",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        let rendered = render_command(&argv);
        if cfg!(windows) {
            assert_eq!(
                rendered,
                "& ghidra-cli batch '日本語''s batch.ghidra' 'C:\\a b\\' '$(echo injected)' ''"
            );
        } else {
            assert_eq!(super::super::split_arguments(&rendered).unwrap(), argv);
        }
    }
}
