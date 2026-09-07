use super::project::project_exists;
use crate::cli;
use crate::config::Config;
use crate::error::GhidraError;
use crate::ghidra::bridge;
use crate::ghidra::GhidraClient;
use std::path::PathBuf;

pub(super) fn handle_init() -> anyhow::Result<()> {
    println!("Ghidra CLI Initialization");
    println!("========================\n");

    let mut config = Config::default();

    if config.ghidra_install_dir.is_none() {
        println!("Ghidra installation not found automatically.");
        println!("Please set GHIDRA_INSTALL_DIR environment variable or run 'ghidra setup'.");
    }

    // Set default project directory. Must avoid dot-prefixed path components,
    // which Ghidra 12.1+ rejects (see Config::default_project_dir).
    let project_dir = Config::default_project_dir()?;
    config.ghidra_project_dir = Some(project_dir.clone());

    println!("\nProject directory: {}", project_dir.display());

    // Save config
    config.save()?;

    println!(
        "\nConfiguration saved to: {}",
        Config::config_path()?.display()
    );
    println!("\nRun 'ghidra doctor' to verify your installation.");

    Ok(())
}

pub(super) fn handle_version() -> anyhow::Result<()> {
    println!("ghidra-cli {}", env!("CARGO_PKG_VERSION"));
    println!("Rust CLI for Ghidra reverse engineering");
    Ok(())
}

pub(super) fn handle_config_command(cmd: cli::ConfigCommands) -> anyhow::Result<()> {
    use cli::ConfigCommands;

    match cmd {
        ConfigCommands::List => {
            let config = Config::load()?;
            println!("{}", serde_yaml::to_string(&config)?);
        }
        ConfigCommands::Get { key } => {
            let config = Config::load()?;
            let yaml = serde_yaml::to_value(&config)?;
            if let Some(value) = yaml.get(&key) {
                println!("{}", serde_yaml::to_string(value)?);
            } else {
                println!("Key not found: {}", key);
            }
        }
        ConfigCommands::Set { key, value } => {
            let mut config = Config::load()?;
            match key.as_str() {
                "default_output_format" => config.default_output_format = Some(value),
                "timeout" => anyhow::bail!(
                    "'timeout' has been removed because it no longer controlled bridge waits. \
                     Use GHIDRA_CLI_READ_TIMEOUT for normal commands, GHIDRA_CLI_OP_TIMEOUT \
                     for analyze/import, or config 'launch_timeout_secs' for bridge startup."
                ),
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
                    let limit: usize = value
                        .parse()
                        .map_err(|_| GhidraError::ConfigError("Invalid limit value".to_string()))?;
                    config.default_limit = Some(limit);
                }
                _ => {
                    anyhow::bail!("Unknown config key: {}", key);
                }
            }
            config.save()?;
            println!("Configuration updated");
        }
        ConfigCommands::Reset => {
            let config = Config::default();
            config.save()?;
            println!("Configuration reset to defaults");
        }
    }

    Ok(())
}

pub(super) fn handle_set_default(args: cli::SetDefaultArgs) -> anyhow::Result<()> {
    let mut config = Config::load()?;

    match args.kind.as_str() {
        "program" => {
            config.default_program = Some(args.value.clone());
            config.save()?;
            println!("Default program set to: {}", args.value);
        }
        "project" => {
            config.default_project = Some(args.value.clone());
            config.save()?;
            println!("Default project set to: {}", args.value);
        }
        _ => {
            anyhow::bail!(format!("Unknown default kind: {}", args.kind));
        }
    }

    Ok(())
}

pub(super) fn handle_project_command(cmd: cli::ProjectCommands) -> anyhow::Result<()> {
    use cli::ProjectCommands;

    let config = Config::load()?;
    let client = GhidraClient::new(config)?;

    match cmd {
        ProjectCommands::Create { name } => {
            client.create_project(&name)?;
            println!("Project '{}' created", name);
        }
        ProjectCommands::List => {
            let project_dir = client.get_project_dir();
            if !project_dir.exists() {
                println!("No projects found");
                return Ok(());
            }

            println!("Projects:");
            for entry in std::fs::read_dir(project_dir)? {
                let entry = entry?;
                if entry.path().is_dir() {
                    if let Some(name) = entry.file_name().to_str() {
                        println!("  {}", name);
                    }
                }
            }
        }
        ProjectCommands::Delete { name } => {
            // analyzeHeadless materializes a project as sibling files
            // `<parent>/<basename>.gpr` (descriptor) + `<basename>.rep` (data dir),
            // NOT a `<parent>/<basename>` directory. Derive the real paths from the
            // basename so absolute project names work too. `create_project` may
            // also have left an empty `<parent>/<basename>` directory.
            let project_path = client.get_project_path(&name);
            let (basename, parent) = match (project_path.file_name(), project_path.parent()) {
                (Some(f), Some(p)) => (f.to_string_lossy().to_string(), p.to_path_buf()),
                _ => {
                    println!("Project '{}' not found", name);
                    return Ok(());
                }
            };
            let gpr = parent.join(format!("{}.gpr", basename));
            let rep = parent.join(format!("{}.rep", basename));
            let legacy_dir = project_path.clone();

            if !gpr.exists() && !rep.exists() && !legacy_dir.is_dir() {
                println!("Project '{}' not found", name);
                return Ok(());
            }

            // Stop any running bridge first so the JVM releases the project lock
            // before we delete its files. stop_bridge also clears the stale
            // port/pid/`.lock`/`.lock~` files via cleanup_stale_files.
            let _ = bridge::stop_bridge(&project_path);

            if gpr.exists() {
                std::fs::remove_file(&gpr)?;
            }
            if rep.exists() {
                std::fs::remove_dir_all(&rep)?;
            }
            if legacy_dir.is_dir() {
                std::fs::remove_dir_all(&legacy_dir)?;
            }
            println!("Project '{}' deleted", name);
        }
        ProjectCommands::Info { name } => {
            let project_name = name.unwrap_or_else(|| "default".to_string());
            let project_path = client.get_project_path(&project_name);
            println!("Project: {}", project_name);
            println!("Path: {}", project_path.display());
            // The project lives on disk as sibling `<name>.gpr`/`<name>.rep`
            // artifacts, not a `<name>` directory, so check those (see
            // `project_exists`) rather than the bare path.
            println!("Exists: {}", project_exists(&project_path));
        }
    }

    Ok(())
}
