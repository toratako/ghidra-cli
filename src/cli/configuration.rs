use clap::{Args, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum ConfigCommands {
    /// List all configuration
    List,
    /// Get configuration value
    Get { key: String },
    /// Set configuration value
    #[command(
        after_help = "Examples:\n  ghidra-cli config set default_limit 100\n  ghidra-cli config set ghidra_install_dir /opt/ghidra\n  ghidra-cli config set launch_timeout_secs 240"
    )]
    Set {
        /// Key to set: ghidra_install_dir, ghidra_project_dir, default_program,
        /// default_project, default_output_format, default_limit, launch_timeout_secs
        key: String,
        /// Value for the key (e.g. 100 for default_limit, /opt/ghidra for ghidra_install_dir)
        value: String,
    },
    /// Reset configuration
    Reset,
}

#[derive(Clone, Copy, Serialize, Deserialize, Debug, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum DefaultKind {
    Program,
    Project,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
#[command(
    after_help = "Examples:\n  ghidra-cli set-default program sample_binary\n  ghidra-cli set-default project target"
)]
pub struct SetDefaultArgs {
    /// Default to update
    #[arg(value_enum)]
    pub kind: DefaultKind,
    /// Program name (e.g. sample_binary) or project name/path (e.g. target)
    pub value: String,
}

/// Arguments for the setup command
#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct SetupArgs {
    /// Specific Ghidra version to install (e.g., "11.0"). Defaults to latest.
    #[arg(long)]
    pub version: Option<String>,

    /// Installation directory. Defaults to standard data directory.
    #[arg(long, short = 'd')]
    pub dir: Option<String>,

    /// Skip Java check
    #[arg(long)]
    pub force: bool,
}
