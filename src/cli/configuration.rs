use clap::Subcommand;
use serde::{Deserialize, Serialize};

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum ConfigCommands {
    /// List all configuration
    List,
    /// Get configuration value
    Get { key: String },
    /// Set configuration value
    #[command(
        after_help = "Examples:\n  ghidra-cli config set default_program sample_binary\n  ghidra-cli config set default_project target\n  ghidra-cli config set default_limit 100\n  ghidra-cli config set ghidra_install_dir /opt/ghidra\n  ghidra-cli config set ghidra_jar /opt/ghidra.jar\n  ghidra-cli config set java_home /opt/jdk-21\n  ghidra-cli config set launch_timeout_secs 240"
    )]
    Set {
        /// Key to set: ghidra_install_dir, ghidra_jar, ghidra_project_dir, java_home, default_program,
        /// default_project, default_output_format, default_limit, launch_timeout_secs
        key: String,
        /// Value for the key (e.g. 100 for default_limit, /opt/ghidra for ghidra_install_dir)
        value: String,
    },
    /// Reset configuration
    Reset,
}
