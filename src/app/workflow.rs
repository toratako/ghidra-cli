//! Bridge execution and project selection state shared by one CLI invocation.

use super::batch;
use super::execute::execute_via_bridge;
use super::options::{extract_program_from_command, extract_project_from_command};
use super::project::{load_config, resolve_project_path};
use super::result::{CommandResult, ResultShape};
use super::{connect_program_bridge, import, management, output, recovery, Output};
use crate::cli::{self, Cli, Commands};
use crate::config::Config;
use crate::ghidra::bridge::{self, BridgeStartMode};
use crate::ipc::client::ProgramSelection;
use crate::query::FetchParams;
use std::collections::HashMap;
use std::path::Path;

/// Nested batches share this invocation's selections, keyed by project identity.
#[derive(Default)]
pub(super) struct BridgeExecution {
    programs: HashMap<String, String>,
}

impl BridgeExecution {
    pub(super) fn execute(
        &mut self,
        cli: &Cli,
        prepared_batch: Option<&batch::PreparedBatch>,
        batch_line: bool,
    ) -> anyhow::Result<CommandResult> {
        let output = Output::new(cli);
        super::validate_target_scope(cli)?;
        let query = super::parse_command_query(&cli.command)?;
        let shape = ResultShape::for_command(&cli.command);
        let paged = shape.supports_paging() && query.has_options;
        let config = load_config(&cli.projects_dir)?;
        // The same plan travels with the result through standalone and batch output,
        // so paging is never applied twice. Preflight has already checked batch input.
        let plan = query.plan(&cli.command, config.default_limit)?;

        // Command-level project, global --project, then the configured default.
        let project_from_cmd =
            extract_project_from_command(&cli.command).or_else(|| cli.project.clone());
        let project_path = resolve_project_path(&project_from_cmd, &config)?;
        let project_key = bridge::project_hash(&project_path)?;

        let selection = ProgramSelection::default();
        let result = match &cli.command {
            Commands::Batch(args) => self.execute_batch(
                cli,
                args,
                prepared_batch.expect("batch input was validated before execution"),
                &project_path,
                &project_key,
                batch_line,
            ),
            _ => execute_single(
                cli,
                output,
                &config,
                &project_path,
                self.programs.get(&project_key).cloned(),
                &selection,
                &plan.fetch,
            ),
        };

        // Reconcile selection before propagating errors: failed jobs can still
        // change it. Missing observations leave intent intact; null clears it.
        if let Some(observed) = selection.observed() {
            // An import can create the .rep directory and establish its persistent
            // identity. Aliased paths must subsequently share this same context.
            let observed_key = bridge::project_hash(&project_path)?;
            self.programs.remove(&project_key);
            match observed {
                Some(program) => {
                    self.programs.insert(observed_key, program);
                }
                None => {
                    self.programs.remove(&observed_key);
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

    fn execute_batch(
        &mut self,
        cli: &Cli,
        args: &cli::BatchArgs,
        prepared: &batch::PreparedBatch,
        project_path: &Path,
        project_key: &str,
        batch_line: bool,
    ) -> anyhow::Result<serde_json::Value> {
        // Apply intent only when the first selected line executes: an empty
        // nested batch must not change the target of later edits.
        let mut program_intent =
            extract_program_from_command(&cli.command).or_else(|| cli.program.clone());
        let on_error = args.on_error.unwrap_or(cli::BatchErrorPolicy::Continue);
        batch::execute_batch(prepared, on_error, |line| {
            if let Some(program) = program_intent.take() {
                self.programs.insert(project_key.to_owned(), program);
            }
            let mut sub_cli = line.cli.clone();
            if sub_cli.project.is_none() {
                sub_cli.project = Some(project_path.to_string_lossy().into_owned());
            }
            if sub_cli.projects_dir.is_none() {
                sub_cli.projects_dir = cli.projects_dir.clone();
            }
            if sub_cli.java_home.is_none() {
                sub_cli.java_home = cli.java_home.clone();
            }
            if let Commands::Batch(nested) = &mut sub_cli.command {
                nested.on_error.get_or_insert(on_error);
            }
            sub_cli.quiet = true;
            let result = self.execute(&sub_cli, line.nested.as_ref(), true)?;
            output::process_batch_result(result)
        })
        .map_err(|error| {
            if !batch_line {
                batch::add_recovery(error, prepared, cli, project_path)
            } else {
                error
            }
        })
    }
}

/// Execute one command; selection observations belong to the invocation above.
fn execute_single(
    cli: &Cli,
    output: Output,
    config: &Config,
    project_path: &Path,
    inherited_program: Option<String>,
    selection: &ProgramSelection,
    fetch: &FetchParams,
) -> anyhow::Result<serde_json::Value> {
    let archive_inspection = matches!(
        &cli.command,
        Commands::Type(cli::TypeCommands::Archive(
            cli::TypeArchiveCommands::Inspect(_)
        ))
    );
    // File operands and their --program options are not selection targets.
    // Within a batch these operations still retain its inherited selection.
    let project_operation = matches!(
        &cli.command,
        Commands::Program(cli::ProgramCommands::Delete(_) | cli::ProgramCommands::List(_))
    );
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
        return management::program_save_result(&save_cli, selection).map(|(value, _)| value);
    }

    // Import owns its workflow and selects only the actual imported program.
    if let Commands::Program(cli::ProgramCommands::Import(args)) = &cli.command {
        let installation = config.get_ghidra_installation()?;
        return import::run_import(cli, args, project_path, &installation, selection);
    }

    let startup_program = if project_operation || archive_inspection {
        None
    } else {
        selected_program
            .clone()
            .or_else(|| config.default_program.clone())
    };
    let client = if let Some(port) = bridge::is_bridge_running(project_path) {
        // Capability checks do not provide authoritative program selection.
        connect_program_bridge(port)?
    } else {
        let installation = config.get_ghidra_installation()?;
        let mode = if let Some(program) = startup_program {
            BridgeStartMode::Process {
                program_name: program,
            }
        } else {
            BridgeStartMode::Project
        };

        output.progress("Starting Ghidra bridge...");
        let port = bridge::start_bridge_with_java(
            project_path,
            &installation,
            mode,
            cli.java_home.as_deref(),
        )?;
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
    execute_via_bridge(&client, &cli.command, output.quiet || output.json, fetch)
}
