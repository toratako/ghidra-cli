use crate::ipc::protocol::{BridgeCommandError, BridgeJob};
use serde_json::json;
use std::path::Path;

/// Attach actionable recovery only to sent program requests with unknown outcomes.
pub(super) fn job_result(
    error: anyhow::Error,
    project: &Path,
    projects_dir: Option<&Path>,
) -> anyhow::Error {
    // The batch report owns its per-line recovery and nesting information.
    if error
        .downcast_ref::<BridgeCommandError>()
        .is_some_and(|report| {
            report.detail["results"].is_array()
                || report.detail["recovery"]["action"] == "retrieve_result"
        })
    {
        return error;
    }
    let Some(job) = error.downcast_ref::<BridgeJob>() else {
        return error;
    };
    let mut argv = vec!["ghidra-cli".to_owned()];
    if let Some(dir) = projects_dir {
        argv.push(format!("--projects-dir={}", dir.display()));
    }
    argv.extend([
        "job".to_owned(),
        "result".to_owned(),
        job.id.clone(),
        "--project".to_owned(),
        project.to_string_lossy().into_owned(),
    ]);
    let mut detail = crate::error::diagnostic_detail(&error);
    let working_directory = std::env::current_dir().ok();
    detail["recovery"] = json!({
        "action": "retrieve_result",
        "argv": argv,
        "working_directory": working_directory,
    });
    detail["project"] = json!(project);
    let location = working_directory
        .map(|path| format!(" from {}", path.display()))
        .unwrap_or_default();
    let message = format!(
        "{error:#}\nRetrieve the result{location}:\n{}",
        render_command(&argv)
    );
    error.context(BridgeCommandError { message, detail })
}

pub(super) fn render_command(argv: &[String]) -> String {
    let quote = |arg: &String| {
        if !arg.is_empty()
            && arg
                .bytes()
                .all(|ch| ch.is_ascii_alphanumeric() || b"_./:=+-".contains(&ch))
        {
            arg.clone()
        } else if cfg!(windows) {
            format!("'{}'", arg.replace('\'', "''"))
        } else {
            format!("'{}'", arg.replace('\'', "'\\''"))
        }
    };
    let rendered = argv.iter().map(quote).collect::<Vec<_>>().join(" ");
    if cfg!(windows) {
        format!("& {rendered}")
    } else {
        rendered
    }
}
