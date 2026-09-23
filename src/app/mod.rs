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
use crate::ipc::client::{BridgeClient, ProgramSelection};
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
use std::collections::HashMap;

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
                    validate_target_scope(sub_cli)?;
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
        execute_bridge_command(&cli, prepared.as_ref(), false, &mut HashMap::new())
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

fn validate_target_scope(cli: &Cli) -> anyhow::Result<()> {
    anyhow::ensure!(
        !matches!(
            cli.command,
            Commands::Type(cli::TypeCommands::Archive(
                cli::TypeArchiveCommands::Inspect(_)
            ))
        ) || cli.program.is_none(),
        "`type archive inspect` reads a file and does not accept --program"
    );
    Ok(())
}

fn execute_bridge_command(
    cli: &Cli,
    prepared_batch: Option<&batch::PreparedBatch>,
    batch_line: bool,
    programs: &mut HashMap<String, String>,
) -> anyhow::Result<CommandResult> {
    let output = Output::new(cli);
    let archive_inspection = matches!(
        &cli.command,
        Commands::Type(cli::TypeCommands::Archive(
            cli::TypeArchiveCommands::Inspect(_)
        ))
    );
    validate_target_scope(cli)?;
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
    let project_key = bridge::project_hash(&project_path)?;

    let selection = ProgramSelection::default();
    let result = (|| -> anyhow::Result<serde_json::Value> {
        if let Commands::Batch(args) = &cli.command {
            // A batch records target intent without selecting it in a separate
            // request. Each line binds its effective target to its own operation.
            if let Some(program) =
                extract_program_from_command(&cli.command).or_else(|| cli.program.clone())
            {
                programs.insert(project_key.clone(), program);
            }
            let on_error = args.on_error.unwrap_or(cli::BatchErrorPolicy::Continue);
            let prepared = prepared_batch.expect("batch input was validated before execution");
            return batch::execute_batch(prepared, on_error, |line| {
                let mut sub_cli = line.cli.clone();
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
                let result =
                    execute_bridge_command(&sub_cli, line.nested.as_ref(), true, programs)?;
                output::process_batch_result(result)
            })
            .map_err(|error| {
                if !batch_line {
                    batch::add_recovery(error, prepared, cli, &project_path)
                } else {
                    error
                }
            });
        }

        // File operands and their --program options are not selection targets.
        // Within a batch these operations still retain its inherited selection.
        let project_operation = matches!(
            &cli.command,
            Commands::Program(cli::ProgramCommands::Delete(_) | cli::ProgramCommands::List(_))
        );
        let inherited_program = programs.get(&project_key).cloned();
        let selected_program = if archive_inspection {
            None
        } else if project_operation {
            inherited_program
        } else {
            extract_program_from_command(&cli.command)
                .or_else(|| cli.program.clone())
                .or(inherited_program)
        };

        if matches!(
            &cli.command,
            Commands::Program(cli::ProgramCommands::Save(_))
        ) {
            let mut save_cli = cli.clone();
            save_cli.program = selected_program;
            return management::program_save_result(&save_cli, &selection).map(|(value, _)| value);
        }

        let ghidra_install_dir = config.get_ghidra_install_dir()?;
        // Import owns its workflow and selects only the actual imported program.
        if let Commands::Program(cli::ProgramCommands::Import(args)) = &cli.command {
            return import::run_import(cli, args, &project_path, &ghidra_install_dir, &selection);
        }

        let startup_program = if project_operation || archive_inspection {
            None
        } else {
            selected_program
                .clone()
                .or_else(|| config.default_program.clone())
        };
        let client = if let Some(port) = bridge::is_bridge_running(&project_path) {
            // Capability checks do not provide authoritative program selection.
            connect_program_bridge(port)?
        } else {
            let mode = if let Some(program) = startup_program {
                BridgeStartMode::Process {
                    program_name: program,
                }
            } else {
                BridgeStartMode::Project
            };

            output.progress("Starting Ghidra bridge...");
            let port = bridge::ensure_bridge_running(&project_path, &ghidra_install_dir, mode)?;
            output.progress("Bridge ready.");
            connect_program_bridge(port)?
        };
        // A file archive query must not replace a batch's intended Program
        // with the unrelated Program currently open in the bridge.
        let client = if archive_inspection {
            client
        } else {
            client.with_selection(selection.clone())
        };
        let client = match selected_program {
            Some(program)
                if !matches!(
                    &cli.command,
                    Commands::Program(cli::ProgramCommands::Open(_))
                ) =>
            {
                client.with_program(program)
            }
            _ => client,
        };
        execute_via_bridge(
            &client,
            &cli.command,
            output.quiet || output.json,
            &plan.fetch,
        )
    })();

    // Executed jobs report the selection from their own program lane, including
    // failures. Missing observations leave intent intact; null clears it.
    if let Some(observed) = selection.observed() {
        // An import can create the .rep directory and establish its persistent
        // identity. Aliased paths must subsequently share this same context.
        let observed_key = bridge::project_hash(&project_path)?;
        programs.remove(&project_key);
        match observed {
            Some(program) => {
                programs.insert(observed_key, program);
            }
            None => {
                programs.remove(&observed_key);
            }
        }
    }
    let result = result.map_err(|error| {
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
    require_program_protocol(&info)?;
    anyhow::ensure!(info.get("explicit_addresses").and_then(|v| v.as_bool()) == Some(true),
        "Running bridge does not support explicit 0x addresses; save pending changes with `ghidra-cli program save`, then run `ghidra-cli bridge restart` for this project. No program command was sent.");
    anyhow::ensure!(
        info.get("auto_save").and_then(|v| v.as_bool()) == Some(true)
            && info.get("atomic_edits").and_then(|v| v.as_bool()) == Some(true),
        "Running bridge does not support atomic edits and automatic saving; save pending changes with `ghidra-cli program save`, then run `ghidra-cli bridge restart` for this project. No program command was sent."
    );
    Ok(client)
}

fn require_program_protocol(info: &serde_json::Value) -> anyhow::Result<()> {
    anyhow::ensure!(
        info.get("protocol_version").and_then(|value| value.as_u64()) == Some(crate::ipc::protocol::PROTOCOL_VERSION),
        "Running bridge uses an incompatible request protocol; save pending changes with `ghidra-cli program save` without a program target, then run `ghidra-cli bridge restart` for this project. No program command was sent."
    );
    Ok(())
}
