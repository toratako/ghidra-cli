mod batch;
mod execute;
mod import;
mod installation;
mod local;
mod management;
mod options;
mod output;
mod project;

use crate::cli::{self, Cli, Commands};
use crate::format::OutputFormat;
use crate::ghidra::bridge::{self, BridgeStartMode};
use crate::ipc::client::BridgeClient;
use crate::query::{Query, QueryPlan};
use clap::{CommandFactory, FromArgMatches};
use execute::execute_via_bridge;
use installation::handle_doctor;
pub(super) use installation::run_setup;
use local::{handle_config_command, handle_init, handle_project_command, handle_version};
pub(super) use management::handle_bridge_command;
use management::handle_program_save;
use options::{
    extract_program_from_command, extract_project_from_command, extract_query_options,
    requires_bridge,
};
use output::describe_query_error;
pub(crate) use output::Output;
use project::{load_config, resolve_project_path};

/// Run a command, starting the bridge if needed.
pub(super) fn run_command(cli: Cli) -> anyhow::Result<()> {
    let output = Output::new(&cli);
    match &cli.command {
        // Non-bridge commands
        Commands::Init => handle_init(output),
        Commands::Doctor { runtime } => handle_doctor(&cli.projects_dir, *runtime, output),
        Commands::Version => handle_version(output),
        Commands::Config(cmd) => handle_config_command(cmd.clone(), output),
        Commands::Project(args) => handle_project_command(
            args.command.clone(),
            &cli.project,
            &cli.projects_dir,
            output,
        ),
        // Saving a stopped project is a no-op; do not auto-start it.
        Commands::Program(cli::ProgramCommands::Save(_)) => handle_program_save(cli),
        // Commands requiring bridge
        _ if requires_bridge(&cli.command) => run_with_bridge(cli),
        _ => anyhow::bail!("Command not yet implemented"),
    }
}

/// Run a command that requires the bridge.
fn run_with_bridge(cli: Cli) -> anyhow::Result<()> {
    match execute_bridge_command(&cli) {
        Ok(result) => output::print_result(&cli, result),
        Err(error) => {
            if matches!(cli.command, Commands::Batch(_)) {
                if let Some(batch) =
                    error.downcast_ref::<crate::ipc::protocol::BridgeCommandError>()
                {
                    if batch.detail.get("results").is_some() {
                        // A batch report is a result even when some rows failed. Only
                        // the outer invocation writes it; nested reports stay in rows.
                        output::print_result(
                            &cli,
                            CommandResult {
                                value: batch.detail.clone(),
                                query: None,
                            },
                        )?;
                        let mut summary = batch.detail.clone();
                        summary.as_object_mut().unwrap().remove("results");
                        let message = batch.message.clone();
                        return Err(error.context(crate::ipc::protocol::BridgeCommandError {
                            message,
                            detail: summary,
                        }));
                    }
                }
            }
            Err(error)
        }
    }
}

struct CommandResult {
    value: serde_json::Value,
    query: Option<Query>,
}

fn execute_bridge_command(cli: &Cli) -> anyhow::Result<CommandResult> {
    if matches!(
        cli.command,
        Commands::Program(cli::ProgramCommands::Save(_))
    ) {
        return management::program_save_result(cli)
            .map(|(value, _)| CommandResult { value, query: None });
    }
    let output = Output::new(cli);
    // Parse once, before any bridge work. The same plan travels with the result
    // through standalone and batch output, so paging is never applied twice.
    let mut query_options = extract_query_options(&cli.command);
    if matches!(
        cli.command,
        Commands::Symbol(cli::SymbolCommands::Delete(_))
    ) {
        // This filter selects mutation targets, not rows in the deletion receipt.
        // Still validate it before config loading, program selection, or bridge work.
        if let Some(filter) = query_options.as_mut().and_then(|opts| opts.filter.take()) {
            crate::filter::Filter::parse(&filter).map_err(describe_query_error)?;
        }
    }
    let query = query_options
        .as_ref()
        .map(|opts| Query::from_options(opts, OutputFormat::JsonCompact))
        .transpose()
        .map_err(describe_query_error)?
        .flatten();
    let config = load_config(&cli.projects_dir)?;
    let plan = QueryPlan::new(
        query,
        query_options.as_ref().and(config.default_limit),
        options::query_fetch_support(&cli.command),
    );

    // Extract project from command args, fall back to global --project, then config default
    let project_from_cmd =
        extract_project_from_command(&cli.command).or_else(|| cli.project.clone());
    let project_path = resolve_project_path(&project_from_cmd, &config)?;

    let ghidra_install_dir = config.get_ghidra_install_dir().map_err(|_| {
        anyhow::anyhow!(
            "Ghidra installation directory not configured. Run 'ghidra-cli setup' first."
        )
    })?;

    // Import and Quick produce their own result and don't need execute_via_bridge.
    // Other commands (including Analyze) produce a result via execute_via_bridge.
    let result = match &cli.command {
        Commands::Import(args) => {
            import::run_import(cli, args, &project_path, &ghidra_install_dir)?
        }

        _ => {
            // A deletion target is a project file, not a program to select.
            let deleting_program = matches!(
                &cli.command,
                Commands::Program(cli::ProgramCommands::Delete(_))
            );
            let selected_program = if deleting_program {
                None
            } else {
                extract_program_from_command(&cli.command).or_else(|| cli.program.clone())
            };
            let startup_program = if deleting_program {
                None
            } else {
                selected_program
                    .clone()
                    .or_else(|| config.get_default_program())
            };
            // For all bridge commands (including Analyze), ensure bridge is running
            let client = if let Some(port) = bridge::is_bridge_running(&project_path) {
                // bridge_info is a responsive control request, including while
                // analysis or another program job is running.
                ensure_autosave_bridge(port, &project_path, &ghidra_install_dir, output)?
            } else {
                // Auto-start bridge - use specific program if available, otherwise project mode
                let mode = if let Some(program) = startup_program.clone() {
                    BridgeStartMode::Process {
                        program_name: program,
                    }
                } else {
                    BridgeStartMode::Project
                };

                output.progress("Starting Ghidra bridge...");
                let port = bridge::ensure_bridge_running(&project_path, &ghidra_install_dir, mode)?;
                output.progress("Bridge ready.");
                BridgeClient::new(port)
            };

            // Let the bridge compare project files. Internal Program names can
            // be identical across different files, so program_info is not an
            // identity check. Opening the selected file again is a no-op.
            if let Some(requested_program) = &selected_program {
                client.open_program(requested_program)?;
            }

            let execute = |client: &BridgeClient| {
                if let Commands::Batch(args) = &cli.command {
                    let content = std::fs::read_to_string(&args.script_file)
                        .map_err(|e| anyhow::anyhow!("Failed to read batch file: {}", e))?;
                    let on_error = args.on_error.unwrap_or(cli::BatchErrorPolicy::Continue);
                    batch::execute_batch(&content, on_error, |line| {
                        let mut sub_cli = parse_batch_command(
                            std::iter::once("ghidra-cli".to_owned())
                                .chain(batch::split_arguments(line)?),
                        )?;
                        // Unspecified targets retain the batch's project and current
                        // selection. Explicit per-line targets use normal routing.
                        if sub_cli.project.is_none() {
                            sub_cli.project = Some(project_path.to_string_lossy().into_owned());
                        }
                        if sub_cli.projects_dir.is_none() {
                            sub_cli.projects_dir = cli.projects_dir.clone();
                        }
                        if let Commands::Batch(nested) = &mut sub_cli.command {
                            nested.on_error.get_or_insert(on_error);
                        }
                        sub_cli.quiet = true;
                        let result = execute_bridge_command(&sub_cli)?;
                        output::process_batch_result(result)
                    })
                } else {
                    execute_via_bridge(
                        client,
                        &cli.command,
                        output.quiet || output.json,
                        &plan.fetch,
                    )
                }
            };
            let first_attempt = execute(&client);
            // Restart on "Unknown command" (old bridge lacks the handler) OR on a
            // stale list_functions response: an old bridge silently ignores the
            // newer tags/untagged args and returns a successful, UNFILTERED list.
            let needs_restart = match &first_attempt {
                Ok(value) => stale_tags_response(&cli.command, value),
                Err(err) => is_unknown_command_error(err),
            };
            match first_attempt {
                Ok(value) if !needs_restart => value,
                Err(err) if !needs_restart => return Err(err),
                _ => {
                    output.progress(
                            "Bridge command not supported by running instance. Restarting bridge and retrying..."
                        );

                    // Running bridge may be from an older script; force restart to load
                    // the embedded bridge matching this CLI version.
                    let selected_path = if let Some(program) = &selected_program {
                        Some(program.clone())
                    } else {
                        current_program_path(&client)?
                    };
                    let mode = match selected_path {
                        Some(program_name) => BridgeStartMode::Process { program_name },
                        None => BridgeStartMode::Project,
                    };
                    bridge::stop_bridge(&project_path)?;
                    let port =
                        bridge::ensure_bridge_running(&project_path, &ghidra_install_dir, mode)?;
                    let retry_client = BridgeClient::new(port);

                    if let Some(requested_program) = &selected_program {
                        retry_client.open_program(requested_program)?;
                    }

                    // One restart per invocation: the retry result is accepted
                    // (or its error propagated) without re-probing.
                    execute(&retry_client)?
                }
            }
        }
    };

    Ok(CommandResult {
        value: output::limit_response_rows(result, plan.fallback_limit),
        query: plan.post,
    })
}

fn parse_batch_command(args: impl IntoIterator<Item = String>) -> anyhow::Result<Cli> {
    use clap::parser::ValueSource;
    let matches = Cli::command().try_get_matches_from(args)?;
    let mut cli = Cli::from_arg_matches(&matches)?;
    if let Commands::Query(query) = &mut cli.command {
        let query_matches = matches.subcommand().expect("query has command matches").1;
        // Environment defaults apply to standalone queries; an omitted batch
        // target inherits the batch project and its current program instead.
        if query_matches.value_source("project") == Some(ValueSource::EnvVariable) {
            query.project = None;
            cli.project = None;
        }
        if query_matches.value_source("program") == Some(ValueSource::EnvVariable) {
            query.program = None;
            cli.program = None;
        }
    }
    Ok(cli)
}

fn current_program_path(client: &BridgeClient) -> anyhow::Result<Option<String>> {
    let info = client.bridge_info()?;
    if let Some(path) = info.get("current_program_path") {
        return selected_path(path);
    }
    // Older auto-save bridges do not advertise the file path. Never use their
    // internal Program name as a file identity, or fall back to config defaults.
    let programs = client.list_programs()?;
    if programs
        .get("has_current_program")
        .and_then(|v| v.as_bool())
        == Some(false)
    {
        return Ok(None);
    }
    let current = programs
        .get("programs")
        .and_then(|v| v.as_array())
        .and_then(|rows| {
            rows.iter()
                .find(|row| row.get("current").and_then(|v| v.as_bool()) == Some(true))
        })
        .and_then(|row| row.get("path"));
    match current {
        Some(path) if !path.is_null() => selected_path(path),
        _ => anyhow::bail!(
            "Could not determine the selected program file before restarting; bridge left running"
        ),
    }
}

fn selected_path(value: &serde_json::Value) -> anyhow::Result<Option<String>> {
    match value {
        serde_json::Value::Null => Ok(None),
        serde_json::Value::String(path) if !path.is_empty() => Ok(Some(path.clone())),
        _ => anyhow::bail!("Invalid selected program path; bridge left running"),
    }
}

fn is_unknown_command_error(err: &anyhow::Error) -> bool {
    // Never replay an executed command whose save failed, even if a script's
    // captured error happens to contain this compatibility message.
    if err
        .downcast_ref::<crate::ipc::protocol::BridgeCommandError>()
        .is_some_and(|err| err.detail.get("save_failed").and_then(|v| v.as_bool()) == Some(true))
    {
        return false;
    }
    err.to_string().starts_with("Unknown command:")
}

/// Upgrade a running pre-auto-save bridge before sending any editing command.
pub(super) fn ensure_autosave_bridge(
    port: u16,
    project_path: &std::path::Path,
    ghidra_install_dir: &std::path::Path,
    output: Output,
) -> anyhow::Result<BridgeClient> {
    let client = BridgeClient::new(port);
    let info = client.bridge_info()?;
    if info.get("auto_save").and_then(|v| v.as_bool()) == Some(true) {
        return Ok(client);
    }
    output.progress("Updating the running bridge to enable automatic saving...");
    // Old bridge_info reports the internal program name, which can differ from
    // its project file path. Also flush an explicitly opened program: the old
    // headless shutdown only guarantees saving the initially loaded program.
    let checkpoint = client.script_run_source(
        r#"
import ghidra.app.script.GhidraScript;
import ghidra.util.task.TaskMonitor;
public class PrepareAutoSaveUpgrade extends GhidraScript {
    public void run() throws Exception {
        if (currentProgram == null) return;
        end(true);
        if (currentProgram.getCurrentTransactionInfo() == null && currentProgram.isChanged()) {
            currentProgram.save("ghidra-cli bridge upgrade", TaskMonitor.DUMMY);
        }
        writer.println(currentProgram.getDomainFile().getPathname());
    }
}
"#,
        &[],
        &[],
        false,
    )?;
    let program = checkpoint
        .get("stdout")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Could not determine the current program before upgrading; bridge left running."
            )
        })?
        .trim();
    let mode = if program.is_empty() {
        BridgeStartMode::Project
    } else {
        BridgeStartMode::Process {
            program_name: program.to_owned(),
        }
    };
    bridge::stop_bridge(project_path)?;
    let port = bridge::ensure_bridge_running(project_path, ghidra_install_dir, mode)?;
    let client = BridgeClient::new(port);
    anyhow::ensure!(
        client
            .bridge_info()?
            .get("auto_save")
            .and_then(|v| v.as_bool())
            == Some(true),
        "The restarted bridge does not support automatic saving; no editing command was sent."
    );
    Ok(client)
}

/// Detects a stale bridge that ignored the `tags`/`untagged` args on
/// `list_functions`: an old handler returns a successful but UNFILTERED
/// response whose rows lack the `"tags"` key (the current row builder always
/// emits it). Probes the raw bridge envelope, before `unwrap_bridge_response`
/// and any client-side field projection, so nothing can strip the key first.
///
/// Empty row sets pass vacuously: an old bridge ignoring the args returns the
/// FULL function list, which is only empty when the program has no functions —
/// where filtered and unfiltered output coincide anyway. Without this rule,
/// every legitimately empty result would trigger a bridge restart.
fn stale_tags_response(command: &Commands, value: &serde_json::Value) -> bool {
    let tag_filter_requested = matches!(
        command,
        Commands::Function(cli::FunctionCommands::List(args))
            if !args.tags.is_empty() || args.untagged
    );
    if !tag_filter_requested {
        return false;
    }
    value
        .get("functions")
        .and_then(|f| f.as_array())
        .is_some_and(|rows| {
            rows.iter()
                .any(|row| row.is_object() && row.get("tags").is_none())
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::{BufRead, BufReader, Write};

    #[test]
    fn restart_resolves_selected_file_path_and_refuses_unknown_identity() {
        for (responses, expected) in [
            (
                vec![
                    json!({"current_program_path": "/nested/actual-file", "program_name": "internal-name"}),
                ],
                Some(Some("/nested/actual-file")),
            ),
            (vec![json!({"current_program_path": null})], Some(None)),
            (
                vec![
                    json!({"auto_save": true}),
                    json!({"has_current_program": true, "programs": [{"name": "internal-name", "path": "/actual-file", "current": true}]}),
                ],
                Some(Some("/actual-file")),
            ),
            (
                vec![
                    json!({"auto_save": true}),
                    json!({"has_current_program": false, "programs": []}),
                ],
                Some(None),
            ),
            (
                vec![
                    json!({"auto_save": true}),
                    json!({"has_current_program": true, "current_program_name": "internal-name", "programs": []}),
                ],
                None,
            ),
            (vec![json!({"current_program_path": ""})], None),
        ] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let worker = std::thread::spawn(move || {
                for (index, response) in responses.into_iter().enumerate() {
                    let (mut stream, _) = listener.accept().unwrap();
                    let mut line = String::new();
                    BufReader::new(&stream).read_line(&mut line).unwrap();
                    let request: serde_json::Value = serde_json::from_str(&line).unwrap();
                    assert_eq!(
                        request["command"],
                        if index == 0 {
                            "bridge_info"
                        } else {
                            "list_programs"
                        }
                    );
                    writeln!(stream, "{}", json!({"status": "success", "data": response})).unwrap();
                }
            });
            let actual = current_program_path(&BridgeClient::new(port));
            worker.join().unwrap();
            match expected {
                Some(path) => assert_eq!(actual.unwrap().as_deref(), path),
                None => assert!(actual
                    .unwrap_err()
                    .to_string()
                    .contains("bridge left running")),
            }
        }
    }
}
