use super::output::Output;
use super::project::project_exists;
use crate::cli;
use crate::config::Config;
use crate::error::GhidraError;
use crate::ghidra::bridge;
use crate::ghidra::GhidraClient;
use serde_json::json;
use std::path::PathBuf;

pub(super) fn handle_init(output: Output) -> anyhow::Result<()> {
    let config = Config::update(|config| {
        if config.ghidra_project_dir.is_none() {
            config.ghidra_project_dir = Some(Config::default_project_dir()?);
        }
        Ok(())
    })?;

    if config.ghidra_install_dir.is_none() {
        output.progress("Ghidra installation not found automatically.");
        output.progress(
            "Please set GHIDRA_INSTALL_DIR environment variable or run 'ghidra-cli setup'.",
        );
    }

    // Set default project directory. Must avoid dot-prefixed path components,
    // which Ghidra 12.1+ rejects (see Config::default_project_dir).
    let project_dir = config.get_project_dir()?;

    let path = Config::config_path()?;
    output.progress("Run 'ghidra-cli doctor' to verify your installation.");
    output.result(
        &json!({"config_path": path, "project_dir": project_dir}),
        &format!(
            "Configuration saved to: {}\nProject directory: {}",
            path.display(),
            project_dir.display()
        ),
    )
}

pub(super) fn handle_version(output: Output) -> anyhow::Result<()> {
    output.result(
        &json!({"name": "ghidra-cli", "version": env!("CARGO_PKG_VERSION")}),
        &format!(
            "ghidra-cli {}\nRust CLI for Ghidra reverse engineering",
            env!("CARGO_PKG_VERSION")
        ),
    )
}

pub(super) fn handle_config_command(
    cmd: cli::ConfigCommands,
    output: Output,
) -> anyhow::Result<()> {
    use cli::ConfigCommands;

    match cmd {
        ConfigCommands::List => {
            let config = Config::load()?;
            output.result(&config, serde_yaml::to_string(&config)?.trim_end())?;
        }
        ConfigCommands::Get { key } => {
            let config = Config::load()?;
            let yaml = serde_yaml::to_value(&config)?;
            if let Some(value) = yaml.get(&key) {
                output.result(value, serde_yaml::to_string(value)?.trim_end())?;
            } else {
                anyhow::bail!(
                    "Key not found: {}. Use 'ghidra-cli config list' to see available keys.",
                    key
                );
            }
        }
        ConfigCommands::Set { key, value } => {
            Config::update(|config| {
                match key.as_str() {
                    "default_output_format" => {
                        if !value.eq_ignore_ascii_case("auto") {
                            crate::format::OutputFormat::from_str(&value)?;
                        }
                        config.default_output_format = Some(value);
                    }
                    "timeout" => return Err(GhidraError::ConfigError(
                        "'timeout' has been removed because it no longer controlled bridge waits. \
                     Use GHIDRA_CLI_READ_TIMEOUT for normal commands, GHIDRA_CLI_OP_TIMEOUT \
                     for analyze/import, or config 'launch_timeout_secs' for bridge startup."
                            .to_string(),
                    )),
                    "ghidra_install_dir" => config.ghidra_install_dir = Some(PathBuf::from(value)),
                    "ghidra_project_dir" => config.ghidra_project_dir = Some(PathBuf::from(value)),
                    "default_program" => config.default_program = Some(value),
                    "default_project" => config.default_project = Some(value),
                    "launch_timeout_secs" => {
                        let timeout: u64 = value.parse().map_err(|_| {
                            GhidraError::ConfigError("Invalid launch timeout value".to_string())
                        })?;
                        config.launch_timeout_secs = Some(timeout);
                    }
                    "default_limit" => {
                        let limit: usize = value.parse().map_err(|_| {
                            GhidraError::ConfigError("Invalid limit value".to_string())
                        })?;
                        config.default_limit = Some(limit);
                    }
                    _ => {
                        return Err(GhidraError::ConfigError(format!(
                            "Unknown config key: {}",
                            key
                        )));
                    }
                }
                Ok(())
            })?;
            output.result(
                &json!({"message": "Configuration updated", "key": key}),
                "Configuration updated",
            )?;
        }
        ConfigCommands::Reset => {
            let config = Config::default();
            config.save()?;
            output.result(
                &json!({"message": "Configuration reset to defaults"}),
                "Configuration reset to defaults",
            )?;
        }
    }

    Ok(())
}

pub(super) fn handle_set_default(args: cli::SetDefaultArgs, output: Output) -> anyhow::Result<()> {
    match args.kind {
        cli::DefaultKind::Program => {
            Config::update(|config| {
                config.default_program = Some(args.value.clone());
                Ok(())
            })?;
            output.result(
                &json!({"message": "Default program set", "program": args.value}),
                &format!("Default program set to: {}", args.value),
            )?;
        }
        cli::DefaultKind::Project => {
            Config::update(|config| {
                config.default_project = Some(args.value.clone());
                Ok(())
            })?;
            output.result(
                &json!({"message": "Default project set", "project": args.value}),
                &format!("Default project set to: {}", args.value),
            )?;
        }
    }

    Ok(())
}

pub(super) fn handle_project_command(
    cmd: cli::ProjectCommands,
    projects_dir: &Option<PathBuf>,
    output: Output,
) -> anyhow::Result<()> {
    use cli::ProjectCommands;

    let config = super::project::load_config(projects_dir)?;
    let client = GhidraClient::new(config)?;

    match cmd {
        ProjectCommands::Create { name } => {
            client.create_project(&name)?;
            output.result(
                &json!({"project": name, "created": true}),
                &format!("Project '{}' created", name),
            )?;
        }
        ProjectCommands::List => {
            let projects = crate::ghidra::project::list_projects(client.get_project_dir())?;
            let human = if projects.is_empty() {
                "No projects found".to_string()
            } else {
                format!("Projects:\n  {}", projects.join("\n  "))
            };
            output.result(&projects, &human)?;
        }

        ProjectCommands::Delete { name } => {
            // analyzeHeadless materializes a project as sibling files
            // `<parent>/<basename>.gpr` (descriptor) + `<basename>.rep` (data dir),
            // NOT a `<parent>/<basename>` directory. Derive the real paths from the
            // basename so absolute project names work too. `create_project` may
            // also have left an empty `<parent>/<basename>` directory.
            let project_path = client.get_project_path(&name);
            let Some(paths) = crate::ghidra::project::ProjectPaths::new(&project_path) else {
                output.result(
                    &json!({"project": name, "deleted": false}),
                    &format!("Project '{}' not found", name),
                )?;
                return Ok(());
            };
            if !paths.exists() && !paths.is_empty_reservation() {
                output.result(
                    &json!({"project": name, "deleted": false}),
                    &format!("Project '{}' not found", name),
                )?;
                return Ok(());
            }
            let gpr = paths.descriptor;
            let rep = paths.data;
            let legacy_dir = paths.legacy;

            // Stop any running bridge first so the JVM releases the project lock
            // before we delete its files. stop_bridge also clears the stale
            // port/pid/`.lock`/`.lock~` files via cleanup_stale_files.
            bridge::stop_bridge(&project_path)?;

            if gpr.exists() {
                std::fs::remove_file(&gpr)?;
            }
            if rep.exists() {
                std::fs::remove_dir_all(&rep)?;
            }
            if legacy_dir.is_dir() {
                // create_project only reserves an empty directory. Contents
                // added later are not Ghidra's sibling .gpr/.rep artifacts.
                if let Err(error) = std::fs::remove_dir(&legacy_dir) {
                    if error.kind() != std::io::ErrorKind::DirectoryNotEmpty {
                        return Err(error.into());
                    }
                }
            }
            output.result(
                &json!({"project": name, "deleted": true}),
                &format!("Project '{}' deleted", name),
            )?;
        }
        ProjectCommands::Info { name } => {
            let project_name = name.unwrap_or_else(|| "default".to_string());
            let project_path = client.get_project_path(&project_name);
            // The project lives on disk as sibling `<name>.gpr`/`<name>.rep`
            // artifacts, not a `<name>` directory, so check those (see
            // `project_exists`) rather than the bare path.
            let exists = project_exists(&project_path);
            output.result(
                &json!({"project": project_name, "path": project_path, "exists": exists}),
                &format!(
                    "Project: {}\nPath: {}\nExists: {}",
                    project_name,
                    project_path.display(),
                    exists
                ),
            )?;
        }
    }

    Ok(())
}
