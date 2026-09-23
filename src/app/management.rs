use super::output::Output;
use super::project::{load_config, resolve_project_path};
use crate::cli::{self, BridgeCommands, Cli, Commands, JobCommands};
use crate::ghidra::bridge::{self, BridgeStartMode, BridgeStatus};
use crate::ipc::client::BridgeClient;
use crate::terminal::write_stdout;
use serde_json::{json, Value};
use std::path::PathBuf;

/// Dispatch bridge lifecycle and job commands without auto-starting a bridge.
pub(crate) fn handle_management_command(cli: Cli) -> anyhow::Result<()> {
    // Global --project/--program flags serve as fallbacks for subcommand-level args
    let global_project = cli.project.clone();
    let global_program = cli.program.clone();
    let projects_dir = cli.projects_dir.clone();
    let output = Output::new(&cli);
    let result = match cli.command {
        Commands::Bridge(BridgeCommands::Start { project, program }) => handle_bridge_start(
            project.or(global_project),
            program.or(global_program),
            &projects_dir,
            output,
        ),
        Commands::Bridge(BridgeCommands::Stop { project }) => {
            handle_bridge_stop(project.or(global_project), &projects_dir, output)
        }
        Commands::Bridge(BridgeCommands::Restart { project, program }) => {
            let proj = project.or(global_project);
            let prog = program.or(global_program);
            handle_bridge_stop(proj.clone(), &projects_dir, output)?;
            std::thread::sleep(std::time::Duration::from_secs(1));
            handle_bridge_start(proj, prog, &projects_dir, output)
        }
        Commands::Bridge(BridgeCommands::Status { project }) => {
            handle_bridge_status(project.or(global_project), &projects_dir)
        }
        Commands::Bridge(BridgeCommands::Ping { project }) => {
            handle_bridge_ping(project.or(global_project), &projects_dir)
        }
        Commands::Job(JobCommands::List { project }) => {
            return handle_job_query(project.or(global_project), &projects_dir, None, output)
        }
        Commands::Job(JobCommands::Get { job_id, project }) => {
            return handle_job_query(
                project.or(global_project),
                &projects_dir,
                Some(job_id),
                output,
            )
        }
        Commands::Job(JobCommands::Cancel { job_id, project }) => {
            return handle_job_cancel(project.or(global_project), &projects_dir, job_id, output)
        }
        _ => unreachable!(),
    }?;
    output.result(&result, result["message"].as_str().unwrap_or_default())
}

/// Start the bridge for a project.
fn handle_bridge_start(
    project: Option<String>,
    program: Option<String>,
    projects_dir: &Option<PathBuf>,
    output: Output,
) -> anyhow::Result<Value> {
    let config = load_config(projects_dir)?;
    let project_path = resolve_project_path(&project, &config)?;

    let ghidra_install_dir = config.get_ghidra_install_dir()?;

    // Check if bridge is already running
    if let Some(port) = bridge::is_bridge_running(&project_path) {
        return Ok(
            json!({"state": "running", "project": project_path, "port": port,
            "message": format!("Bridge is already running for project: {}", project_path.display())}),
        );
    }

    // Determine start mode
    let mode = if let Some(prog) = program {
        BridgeStartMode::Process { program_name: prog }
    } else if let Some(prog) = config.default_program.clone() {
        BridgeStartMode::Process { program_name: prog }
    } else {
        BridgeStartMode::Project
    };

    output.progress(&format!(
        "Starting bridge for project: {}",
        project_path.display()
    ));

    let port = bridge::ensure_bridge_running(&project_path, &ghidra_install_dir, mode)?;

    Ok(
        json!({"state": "running", "project": project_path, "port": port,
        "message": format!("Bridge started on port {}", port)}),
    )
}

/// Stop the bridge for a project.
fn handle_bridge_stop(
    project: Option<String>,
    projects_dir: &Option<PathBuf>,
    output: Output,
) -> anyhow::Result<Value> {
    let config = load_config(projects_dir)?;
    let project_path = resolve_project_path(&project, &config)?;

    output.progress("Stopping bridge...");
    bridge::stop_bridge(&project_path)?;
    let message = "Bridge stopped";
    Ok(json!({"state": "stopped", "project": project_path, "message": message}))
}

/// Flush pending changes in place; a stopped bridge has nothing pending.
pub(super) fn handle_program_save(cli: Cli) -> anyhow::Result<()> {
    let output = Output::new(&cli);
    let (result, message) = program_save_result(&cli)?;
    output.result(&result, &message)
}

pub(super) fn program_save_result(cli: &Cli) -> anyhow::Result<(Value, String)> {
    let Commands::Program(cli::ProgramCommands::Save(args)) = &cli.command else {
        unreachable!("handle_program_save dispatched for a non-Save Program command");
    };
    let project = args.project.clone().or_else(|| cli.project.clone());
    let program = args
        .name
        .clone()
        .or_else(|| args.program.clone())
        .or_else(|| cli.program.clone());
    let config = load_config(&cli.projects_dir)?;
    let project_path = resolve_project_path(&project, &config)?;
    let Some(port) = bridge::is_bridge_running(&project_path) else {
        return Ok((
            json!({"saved": false, "state": "stopped", "project": project_path}),
            format!(
                "No bridge running for project: {} — nothing pending to save.",
                project_path.display()
            ),
        ));
    };
    // Recovery must remain available before upgrading a bridge's capabilities.
    // Never restart or replay an edit merely to retry a pending save.
    let client = BridgeClient::new(port);
    if let Some(program) = program {
        client.open_program(&program)?;
    }
    let mut result = client.program_save()?;
    result["project"] = json!(project_path);
    let message = if result["saved"] == true {
        "Saved."
    } else {
        "No program open — nothing pending to save."
    };
    Ok((result, message.to_owned()))
}

/// Get bridge status for a project. A stopped bridge is a valid status result.
fn handle_bridge_status(
    project: Option<String>,
    projects_dir: &Option<PathBuf>,
) -> anyhow::Result<Value> {
    use std::fmt::Write;
    let config = load_config(projects_dir)?;
    let project_path = resolve_project_path(&project, &config)?;
    match bridge::bridge_status(&project_path)? {
        BridgeStatus::Running { port, pid } => {
            let mut result =
                json!({"state": "running", "pid": pid, "port": port, "project": project_path});
            let mut human = format!(
                "Bridge is running:\n  PID: {}\n  Port: {}\n  Project: {}",
                pid,
                port,
                project_path.display()
            );
            if let Ok(info) = BridgeClient::new(port).bridge_info() {
                for (key, label) in [
                    ("current_program", "Current program"),
                    ("program_count", "Programs"),
                    ("bridge_state", "State"),
                    ("queue_depth", "Queue depth"),
                ] {
                    if let Some(value) = info.get(key).filter(|v| !v.is_null()) {
                        write!(
                            human,
                            "\n  {label}: {}",
                            value
                                .as_str()
                                .map(str::to_string)
                                .unwrap_or_else(|| value.to_string())
                        )?;
                    }
                }
                if let Some(job) = info.get("active_job").filter(|v| !v.is_null()) {
                    write!(human, "\n  {}", format_bridge_job("Active job", job))?;
                }
                result["info"] = info;
            }
            result["message"] = json!(human);
            Ok(result)
        }
        BridgeStatus::Stopped => Ok(json!({"state": "stopped", "project": project_path,
            "message": format!("No bridge running for project: {}", project_path.display())})),
    }
}

/// Ping is a health probe: absence or a negative response is a failure.
fn handle_bridge_ping(
    project: Option<String>,
    projects_dir: &Option<PathBuf>,
) -> anyhow::Result<Value> {
    let config = load_config(projects_dir)?;
    let project_path = resolve_project_path(&project, &config)?;
    let port = bridge::is_bridge_running(&project_path).ok_or_else(|| {
        anyhow::anyhow!(
            "No bridge running for project: {}. Run 'ghidra-cli bridge start --project {}'.",
            project_path.display(),
            project_path.display()
        )
    })?;
    anyhow::ensure!(
        BridgeClient::new(port).ping()?,
        "Bridge is not responding. Check 'ghidra-cli bridge status' and restart the bridge."
    );
    Ok(
        json!({"responsive": true, "project": project_path, "port": port, "message": "Bridge is responsive"}),
    )
}

fn handle_job_query(
    project: Option<String>,
    projects_dir: &Option<PathBuf>,
    job_id: Option<u64>,
    output: Output,
) -> anyhow::Result<()> {
    let config = load_config(projects_dir)?;
    let project_path = resolve_project_path(&project, &config)?;
    let port = bridge::is_bridge_running(&project_path).ok_or_else(|| {
        anyhow::anyhow!("No bridge running for project: {}", project_path.display())
    })?;
    let client = BridgeClient::new(port);
    let jobs = if job_id.is_some() {
        client.job_status(job_id)?
    } else {
        client.status()?
    };
    if output.json {
        output.result(&jobs, "")?;
    } else if let Some(job) = jobs.get("job") {
        write_stdout(&format_bridge_job("Job", job))?;
    } else if jobs.get("found").and_then(|v| v.as_bool()) == Some(false) {
        write_stdout(&format!("Job {} was not found", job_id.unwrap_or_default()))?;
    } else {
        let state = jobs
            .get("bridge_state")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let depth = jobs
            .get("queue_depth")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        write_stdout(&format!("Bridge: {} ({} queued)", state, depth))?;

        match jobs.get("active_job").filter(|v| !v.is_null()) {
            Some(job) => write_stdout(&format_bridge_job("Active", job))?,
            None => write_stdout("Active: none")?,
        }

        if let Some(queued) = jobs.get("queued_jobs").and_then(|v| v.as_array()) {
            for job in queued {
                write_stdout(&format_bridge_job("Queued", job))?;
            }
        }
        if let Some(recent) = jobs.get("recent_jobs").and_then(|v| v.as_array()) {
            for job in recent {
                write_stdout(&format_bridge_job("Recent", job))?;
            }
        }
    }
    Ok(())
}

fn format_bridge_job(label: &str, job: &serde_json::Value) -> String {
    let id = job.get("id").and_then(|v| v.as_u64()).unwrap_or(0);
    let command = job
        .get("command")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let state = job
        .get("state")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let elapsed = job.get("elapsed_ms").and_then(|v| v.as_u64()).unwrap_or(0);
    let mut details = format!(
        "{label}: {id} {command} ({state}, {:.1}s",
        elapsed as f64 / 1000.0
    );

    let progress = job.get("progress").and_then(|v| v.as_u64()).unwrap_or(0);
    let maximum = job.get("maximum").and_then(|v| v.as_u64()).unwrap_or(0);
    if maximum > 0 {
        details.push_str(&format!(", {progress}/{maximum}"));
    }
    details.push(')');
    if let Some(message) = job.get("progress_message").and_then(|v| v.as_str()) {
        details.push_str(": ");
        details.push_str(message);
    } else if let Some(error) = job.get("error").and_then(|v| v.as_str()) {
        details.push_str(": ");
        details.push_str(error);
    }
    details
}

fn handle_job_cancel(
    project: Option<String>,
    projects_dir: &Option<PathBuf>,
    job_id: Option<u64>,
    output: Output,
) -> anyhow::Result<()> {
    let config = load_config(projects_dir)?;
    let project_path = resolve_project_path(&project, &config)?;
    let port = bridge::is_bridge_running(&project_path).ok_or_else(|| {
        anyhow::anyhow!("No bridge running for project: {}", project_path.display())
    })?;
    let result = BridgeClient::new(port).cancel_job(job_id)?;
    if output.json {
        output.result(&result, "")?;
    } else {
        let id = result
            .get("job_id")
            .and_then(|v| v.as_u64())
            .unwrap_or_default();
        let state = result
            .get("state")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let message = result
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("Cancellation request handled");
        write_stdout(&format!("Job {id}: {state} - {message}"))?;
    }
    Ok(())
}
