mod batch;
mod execute;
mod import;
mod installation;
mod local;
mod management;
mod options;
mod output;
mod project;
mod recovery;
mod result;

use crate::cli::{self, Cli, Commands};
use crate::ghidra::bridge::{self, BridgeStartMode};
use crate::ipc::client::BridgeClient;
use crate::query::{Page, Query, QueryPlan};
use execute::execute_via_bridge;
use installation::handle_doctor;
use local::{handle_config_command, handle_project_command};
pub(super) use management::handle_management_command;
use management::handle_program_save;
use options::{
    extract_program_from_command, extract_project_from_command, extract_query_options,
    requires_bridge,
};
use output::describe_query_error;
pub(crate) use output::Output;
use project::{load_config, resolve_project_path};
use result::ResultShape;

/// Run a command, starting the bridge if needed.
pub(super) fn run_command(cli: Cli) -> anyhow::Result<()> {
    let output = Output::new(&cli);
    match &cli.command {
        // Non-bridge commands
        Commands::Doctor { runtime } => handle_doctor(&cli.projects_dir, *runtime, output),
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
    let result = (|| {
        let prepared = if let Commands::Batch(args) = &cli.command {
            Some(batch::prepare(
                std::path::Path::new(&args.script_file),
                args.from_line.map(|line| line.get()),
                |sub_cli| {
                    anyhow::ensure!(
                        requires_bridge(&sub_cli.command),
                        "This command cannot run inside a batch"
                    );
                    if let Commands::Program(cli::ProgramCommands::Import(args)) = &sub_cli.command
                    {
                        import::validate_options(args)?;
                    }
                    parse_command_query(&sub_cli.command)?
                        .plan(&sub_cli.command, None)
                        .map(|_| ())
                },
            )?)
        } else {
            None
        };
        execute_bridge_command(&cli, prepared.as_ref(), false)
    })();
    match result {
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
                                shape: ResultShape::Value,
                                page: None,
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
    shape: ResultShape,
    page: Option<Page>,
}

struct CommandQuery {
    query: Option<Query>,
    has_options: bool,
}

impl CommandQuery {
    fn plan(self, command: &Commands, default_limit: Option<usize>) -> anyhow::Result<QueryPlan> {
        let plan = QueryPlan::new(
            self.query,
            default_limit.filter(|_| {
                self.has_options && ResultShape::for_command(command).supports_paging()
            }),
            options::query_fetch_support(command),
        );
        options::validate_query_bounds(command, &plan)?;
        Ok(plan)
    }
}

fn parse_command_query(command: &Commands) -> anyhow::Result<CommandQuery> {
    execute::validate_command_syntax(command)?;
    let query_options = extract_query_options(command);
    let query = query_options
        .as_ref()
        .map(Query::from_options)
        .transpose()
        .map_err(describe_query_error)?
        .flatten();
    Ok(CommandQuery {
        query,
        has_options: query_options.is_some(),
    })
}

fn execute_bridge_command(
    cli: &Cli,
    prepared_batch: Option<&batch::PreparedBatch>,
    batch_line: bool,
) -> anyhow::Result<CommandResult> {
    let output = Output::new(cli);
    let query = parse_command_query(&cli.command)?;
    let shape = ResultShape::for_command(&cli.command);
    let paged = shape.supports_paging() && query.has_options;
    let config = load_config(&cli.projects_dir)?;
    // The same plan travels with the result through standalone and batch output,
    // so paging is never applied twice. Preflight has already checked batch input.
    let plan = query.plan(&cli.command, config.default_limit)?;

    // Extract project from command args, fall back to global --project, then config default
    let project_from_cmd =
        extract_project_from_command(&cli.command).or_else(|| cli.project.clone());
    let project_path = resolve_project_path(&project_from_cmd, &config)?;

    if matches!(
        cli.command,
        Commands::Program(cli::ProgramCommands::Save(_))
    ) {
        return management::program_save_result(cli)
            .map(|(value, _)| CommandResult {
                value,
                query: None,
                shape,
                page: None,
            })
            .map_err(|error| {
                let error = recovery::job_result(error, &project_path, cli.projects_dir.as_deref());
                if batch_line {
                    batch::in_project(error, &project_path)
                } else {
                    error
                }
            });
    }

    let ghidra_install_dir = config.get_ghidra_install_dir()?;

    // Import owns its workflow; other commands dispatch through the bridge.
    let result = (|| -> anyhow::Result<serde_json::Value> {
        match &cli.command {
            Commands::Program(cli::ProgramCommands::Import(args)) => {
                import::run_import(cli, args, &project_path, &ghidra_install_dir)
            }

            _ => {
                // Project-wide file operations do not select a program.
                let project_operation = matches!(
                    &cli.command,
                    Commands::Program(
                        cli::ProgramCommands::Delete(_) | cli::ProgramCommands::List(_)
                    )
                );
                let selected_program = if project_operation {
                    None
                } else {
                    extract_program_from_command(&cli.command).or_else(|| cli.program.clone())
                };
                let startup_program = if project_operation {
                    None
                } else {
                    selected_program
                        .clone()
                        .or_else(|| config.default_program.clone())
                };
                // For all bridge commands (including analysis run), ensure bridge is running
                let client = if let Some(port) = bridge::is_bridge_running(&project_path) {
                    // bridge_info is a responsive control request, including while
                    // analysis or another program job is running.
                    connect_program_bridge(port)?
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
                    let port =
                        bridge::ensure_bridge_running(&project_path, &ghidra_install_dir, mode)?;
                    output.progress("Bridge ready.");
                    BridgeClient::new(port)
                };

                // Let the bridge compare project files. Internal Program names can
                // be identical across different files, so program_info is not an
                // identity check. Opening the selected file again is a no-op.
                if let Some(requested_program) = &selected_program {
                    client.open_program(requested_program)?;
                }

                if let Commands::Batch(args) = &cli.command {
                    let on_error = args.on_error.unwrap_or(cli::BatchErrorPolicy::Continue);
                    let prepared =
                        prepared_batch.expect("batch input was validated before execution");
                    batch::execute_batch(prepared, on_error, |line| {
                        let mut sub_cli = line.cli.clone();
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
                        let result = execute_bridge_command(&sub_cli, line.nested.as_ref(), true)?;
                        output::process_batch_result(result)
                    })
                    .map_err(|error| {
                        if !batch_line {
                            batch::add_recovery(error, prepared, cli, &project_path)
                        } else {
                            error
                        }
                    })
                } else {
                    execute_via_bridge(
                        &client,
                        &cli.command,
                        output.quiet || output.json,
                        &plan.fetch,
                    )
                }
            }
        }
    })()
    .map_err(|error| {
        let error = recovery::job_result(error, &project_path, cli.projects_dir.as_deref());
        if batch_line {
            batch::in_project(error, &project_path)
        } else {
            error
        }
    })?;

    Ok(CommandResult {
        value: result,
        query: plan.post,
        shape,
        page: paged.then_some(plan.page),
    })
}

/// Require the current editing contract before selecting or changing a program.
pub(super) fn connect_program_bridge(port: u16) -> anyhow::Result<BridgeClient> {
    let client = BridgeClient::new(port);
    let info = client.bridge_info()?;
    anyhow::ensure!(info.get("explicit_addresses").and_then(|v| v.as_bool()) == Some(true),
        "Running bridge does not support explicit 0x addresses; save pending changes with `ghidra-cli program save`, then run `ghidra-cli bridge restart` for this project. No program command was sent.");
    anyhow::ensure!(
        info.get("auto_save").and_then(|v| v.as_bool()) == Some(true)
            && info.get("atomic_edits").and_then(|v| v.as_bool()) == Some(true),
        "Running bridge does not support atomic edits and automatic saving; save pending changes with `ghidra-cli program save`, then run `ghidra-cli bridge restart` for this project. No program command was sent."
    );
    Ok(client)
}
