use super::output::Output;
use super::project::{load_config, resolve_project_path};
use crate::cli::{self, Cli, Commands};
use crate::ghidra::bridge::{self, BridgeStartMode, BridgeStatus};
use crate::ipc::client::BridgeClient;
use crate::terminal::write_stdout;
use serde_json::{json, Value};
use std::path::PathBuf;

/// Dispatch bridge management commands.
pub(crate) fn handle_bridge_command(cli: Cli) -> anyhow::Result<()> {
    // Global --project/--program flags serve as fallbacks for subcommand-level args
    let global_project = cli.project.clone();
    let global_program = cli.program.clone();
    let projects_dir = cli.projects_dir.clone();
    let output = Output::new(&cli);
    let result = match cli.command {
        Commands::Start { project, program } => handle_bridge_start(
            project.or(global_project),
            program.or(global_program),
            &projects_dir,
            output,
        ),
        Commands::Stop { project } => {
            handle_bridge_stop(project.or(global_project), &projects_dir, output)
        }
        Commands::Restart { project, program } => {
            let proj = project.or(global_project);
            let prog = program.or(global_program);
            handle_bridge_stop(proj.clone(), &projects_dir, output)?;
            std::thread::sleep(std::time::Duration::from_secs(1));
            handle_bridge_start(proj, prog, &projects_dir, output)
        }
        Commands::Status { project } => {
            handle_bridge_status(project.or(global_project), &projects_dir)
        }
        Commands::Ping { project } => handle_bridge_ping(project.or(global_project), &projects_dir),
        Commands::Jobs { job_id, project } => {
            return handle_bridge_jobs(project.or(global_project), &projects_dir, job_id, output)
        }
        Commands::Cancel { job_id, project } => {
            return handle_bridge_cancel(project.or(global_project), &projects_dir, job_id, output)
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

    let ghidra_install_dir = config.get_ghidra_install_dir().map_err(|_| {
        anyhow::anyhow!(
            "Ghidra installation directory not configured. Run 'ghidra-cli setup' first."
        )
    })?;

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
    } else if let Some(prog) = config.get_default_program() {
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

    let message = if bridge::is_bridge_running(&project_path).is_some() {
        output.progress("Stopping bridge...");
        bridge::stop_bridge(&project_path)?;
        "Bridge stopped".to_string()
    } else {
        format!("No bridge running for project: {}", project_path.display())
    };
    Ok(json!({"state": "stopped", "project": project_path, "message": message}))
}

/// Flush pending changes in place; a stopped bridge has nothing pending.
pub(super) fn handle_program_save(cli: Cli) -> anyhow::Result<()> {
    let output = Output::new(&cli);
    let Commands::Program(cli::ProgramCommands::Save(args)) = &cli.command else {
        unreachable!("handle_program_save dispatched for a non-Save Program command");
    };
    let project = args.project.clone().or_else(|| cli.project.clone());
    let program = args.program.clone().or_else(|| cli.program.clone());
    let config = load_config(&cli.projects_dir)?;
    let project_path = resolve_project_path(&project, &config)?;
    let Some(port) = bridge::is_bridge_running(&project_path) else {
        return output.result(
            &json!({"saved": false, "state": "stopped", "project": project_path}),
            &format!(
                "No bridge running for project: {} — nothing pending to save.",
                project_path.display()
            ),
        );
    };
    let ghidra_install_dir = config.get_ghidra_install_dir()?;
    let client = super::ensure_autosave_bridge(port, &project_path, &ghidra_install_dir, output)?;
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
    output.result(&result, message)
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
            "No bridge running for project: {}. Run 'ghidra-cli start --project {}'.",
            project_path.display(),
            project_path.display()
        )
    })?;
    anyhow::ensure!(
        BridgeClient::new(port).ping()?,
        "Bridge is not responding. Check 'ghidra-cli status' and restart the bridge."
    );
    Ok(
        json!({"responsive": true, "project": project_path, "port": port, "message": "Bridge is responsive"}),
    )
}

fn handle_bridge_jobs(
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
        write_stdout(&output.json_string(&jobs)?)?;
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

fn handle_bridge_cancel(
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
        write_stdout(&output.json_string(&result)?)?;
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
