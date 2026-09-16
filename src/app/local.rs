use super::output::Output;
use super::project::resolve_project_name;
use crate::cli;
use crate::config::Config;
use crate::error::GhidraError;
use crate::ghidra::GhidraClient;
use serde_json::json;
use std::path::PathBuf;

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
                    "java_home" => config.java_home = Some(PathBuf::from(value)),
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

pub(super) fn handle_project_command(
    cmd: cli::ProjectCommands,
    project: &Option<String>,
    projects_dir: &Option<PathBuf>,
    output: Output,
) -> anyhow::Result<()> {
    use cli::ProjectCommands;

    let config = super::project::load_config(projects_dir)?;
    let client = GhidraClient::new(config.clone())?;

    match cmd {
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
            let deleted = client.delete_project(&name)?;
            output.result(
                &json!({"project": name, "deleted": deleted}),
                &format!(
                    "Project '{}' {}",
                    name,
                    if deleted { "deleted" } else { "not found" }
                ),
            )?;
        }
        ProjectCommands::Info { name } => {
            let project_name = resolve_project_name(&name.or_else(|| project.clone()), &config)?;
            let project_path = client.get_project_path(&project_name);
            let exists = crate::ghidra::project::ProjectPaths::new(&project_path)
                .is_some_and(|paths| paths.exists());
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
