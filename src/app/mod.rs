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
mod workflow;

use crate::cli::{self, Cli, Commands};
use crate::ipc::client::BridgeClient;
use crate::query::{Query, QueryPlan};
use installation::handle_doctor;
use local::{handle_config_command, handle_project_command};
pub(super) use management::handle_management_command;
use management::handle_program_save;
use options::{extract_query_options, requires_bridge};
use output::describe_query_error;
pub(crate) use output::Output;
use project::load_config;
use result::{CommandResult, ResultShape};
use workflow::BridgeExecution;

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
            let prepared = batch::prepare(
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
            )?;
            let config = load_config(&cli.projects_dir)?;
            batch::validate_prepared(&prepared, |sub_cli| {
                parse_command_query(&sub_cli.command)?
                    .plan(&sub_cli.command, config.default_limit)
                    .map(|_| ())
            })?;
            Some(prepared)
        } else {
            None
        };
        BridgeExecution::default().execute(&cli, prepared.as_ref(), false)
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
