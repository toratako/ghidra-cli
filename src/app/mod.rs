mod execute;
mod import;
mod installation;
mod local;
mod management;
mod options;
mod output;
mod project;

use crate::cli::{self, Cli, Commands};
use crate::filter;
use crate::ghidra::bridge::{self, BridgeStartMode};
use crate::ipc::client::BridgeClient;
use execute::execute_via_bridge;
use installation::handle_doctor;
pub(super) use installation::run_setup;
use local::{
    handle_config_command, handle_init, handle_project_command, handle_set_default, handle_version,
};
pub(super) use management::handle_bridge_command;
use management::handle_program_save;
use options::{
    extract_program_from_command, extract_project_from_command, extract_query_options,
    requires_bridge,
};
use output::describe_query_error;
use project::{load_config, resolve_project_path};

/// Run a command, starting the bridge if needed.
pub(super) fn run_command(cli: Cli) -> anyhow::Result<()> {
    match &cli.command {
        // Non-bridge commands
        Commands::Init => handle_init(),
        Commands::Doctor => handle_doctor(&cli.projects_dir),
        Commands::Version => handle_version(),
        Commands::Config(cmd) => handle_config_command(cmd.clone()),
        Commands::SetDefault(args) => handle_set_default(args.clone()),
        Commands::Project(args) => handle_project_command(args.command.clone()),
        // Saving means stopping and restarting the bridge, not a single
        // request/response against an already-running one, so it's handled
        // before the generic bridge dispatch below.
        Commands::Program(cli::ProgramCommands::Save(_)) => handle_program_save(cli),
        // Commands requiring bridge
        _ if requires_bridge(&cli.command) => run_with_bridge(cli),
        _ => {
            println!("Command not yet implemented");
            Ok(())
        }
    }
}

/// Run a command that requires the bridge.
fn run_with_bridge(cli: Cli) -> anyhow::Result<()> {
    // Reject a malformed --filter up front, before any bridge work: the bridge
    // fetch for a filtered query pulls the *full* dataset, so failing late
    // wastes that transfer (and used to silently dump it — TODO.md Bug 2).
    if let Some(opts) = extract_query_options(&cli.command) {
        if let Some(expr) = &opts.filter {
            filter::Filter::parse(expr).map_err(describe_query_error)?;
        }
    }

    let config = load_config(&cli.projects_dir)?;

    // Extract project from command args, fall back to global --project, then config default
    let project_from_cmd =
        extract_project_from_command(&cli.command).or_else(|| cli.project.clone());
    let project_path = resolve_project_path(&project_from_cmd, &config)?;

    let ghidra_install_dir = config
        .ghidra_install_dir
        .clone()
        .or_else(|| config.get_ghidra_install_dir().ok())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Ghidra installation directory not configured. Run 'ghidra setup' first."
            )
        })?;

    // Import and Quick produce their own result and don't need execute_via_bridge.
    // Other commands (including Analyze) produce a result via execute_via_bridge.
    let result = match &cli.command {
        Commands::Import(args) => {
            import::run_import(&cli, args, &project_path, &ghidra_install_dir)?
        }

        _ => {
            // For all bridge commands (including Analyze), ensure bridge is running
            let client = if let Some(port) = bridge::is_bridge_running(&project_path) {
                // Liveness already proven by is_bridge_running() (PID alive + socket
                // accepting). A busy bridge queues the request rather than failing a
                // pre-flight ping, so connect directly and let it wait its turn.
                BridgeClient::new(port)
            } else {
                // Auto-start bridge - use specific program if available, otherwise project mode
                let mode = if let Some(program) = extract_program_from_command(&cli.command)
                    .or_else(|| cli.program.clone())
                    .or_else(|| config.get_default_program())
                {
                    BridgeStartMode::Process {
                        program_name: program,
                    }
                } else {
                    BridgeStartMode::Project
                };

                if !cli.quiet {
                    eprintln!("Starting Ghidra bridge...");
                }
                let port = bridge::ensure_bridge_running(&project_path, &ghidra_install_dir, mode)?;
                if !cli.quiet {
                    eprintln!("Bridge ready.");
                }
                BridgeClient::new(port)
            };

            // Let the bridge compare project files. Internal Program names can
            // be identical across different files, so program_info is not an
            // identity check. Opening the selected file again is a no-op.
            if let Some(requested_program) =
                extract_program_from_command(&cli.command).or_else(|| cli.program.clone())
            {
                client.open_program(&requested_program)?;
            }

            let first_attempt =
                execute_via_bridge(&client, &cli.command, cli.quiet, config.default_limit);
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
                    if !cli.quiet {
                        eprintln!(
                            "Bridge command not supported by running instance. Restarting bridge and retrying..."
                        );
                    }

                    // Running bridge may be from an older script; force restart to load
                    // the embedded bridge matching this CLI version.
                    let _ = bridge::stop_bridge(&project_path);
                    let mode = if let Some(program) = extract_program_from_command(&cli.command)
                        .or_else(|| cli.program.clone())
                        .or_else(|| config.get_default_program())
                    {
                        BridgeStartMode::Process {
                            program_name: program,
                        }
                    } else {
                        BridgeStartMode::Project
                    };
                    let port =
                        bridge::ensure_bridge_running(&project_path, &ghidra_install_dir, mode)?;
                    let retry_client = BridgeClient::new(port);

                    if let Some(requested_program) =
                        extract_program_from_command(&cli.command).or_else(|| cli.program.clone())
                    {
                        retry_client.open_program(&requested_program)?;
                    }

                    // One restart per invocation: the retry result is accepted
                    // (or its error propagated) without re-probing.
                    execute_via_bridge(
                        &retry_client,
                        &cli.command,
                        cli.quiet,
                        config.default_limit,
                    )?
                }
            }
        }
    };

    output::print_result(&cli, result)
}

fn is_unknown_command_error(err: &anyhow::Error) -> bool {
    err.to_string().contains("Unknown command:")
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
