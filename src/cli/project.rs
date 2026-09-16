use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct ProjectArgs {
    #[command(subcommand)]
    pub command: ProjectCommands,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum ProjectCommands {
    /// Create a new project
    Create { name: String },
    /// List all projects
    List,
    /// Delete a project
    Delete { name: String },
    /// Show project information (NAME overrides --project and the configured default)
    Info { name: Option<String> },
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum ProgramCommands {
    /// List all programs in the project
    #[command(alias = "ls")]
    List(ProgramTargetArgs),
    /// Open/switch to a program
    Open(ProgramTargetArgs),
    /// Close a program
    Close(ProgramTargetArgs),
    /// Delete a program
    Delete(ProgramTargetArgs),
    /// Show program information
    Info(super::options::QueryOptions),
    /// Export program
    Export(ExportArgs),
    /// Retry saving pending changes without restarting the bridge.
    /// Edits are saved automatically before a command reports success;
    /// use this after a save failure to retry without repeating the edit.
    Save(ProgramTargetArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct ProgramTargetArgs {
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct ExportArgs {
    /// Export format (json, xml, c, binary/bin, gzf, ascii/asm, hex, html)
    pub format: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
    /// Output file
    #[arg(short, long)]
    pub output: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct ImportArgs {
    pub binary: String,
    /// Save the imported program under this name (default: input file name).
    /// An explicitly named existing program is never overwritten.
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
    /// Force a specific Ghidra loader (for raw blobs, use BinaryLoader)
    #[arg(long)]
    pub loader: Option<String>,
    /// Ghidra language ID, e.g. x86:LE:32:default
    #[arg(long, visible_alias = "processor")]
    pub language: Option<String>,
    /// Ghidra compiler spec ID for the selected language
    #[arg(long, visible_alias = "cspec")]
    pub compiler_spec: Option<String>,
    /// BinaryLoader base address (implies --loader BinaryLoader if omitted)
    #[arg(long)]
    pub base_address: Option<String>,
    /// BinaryLoader memory block name (implies --loader BinaryLoader if omitted)
    #[arg(long)]
    pub block_name: Option<String>,
    /// BinaryLoader file offset (implies --loader BinaryLoader if omitted)
    #[arg(long)]
    pub file_offset: Option<String>,
    /// BinaryLoader length in bytes (implies --loader BinaryLoader if omitted)
    #[arg(long)]
    pub length: Option<String>,
    /// Additional loader argument as NAME=VALUE; repeat for multiple arguments
    #[arg(long = "loader-option", value_name = "NAME=VALUE")]
    pub loader_options: Vec<String>,
    /// Import only — skip auto-analysis (the program is still persisted)
    #[arg(long, default_value = "false")]
    pub no_analyze: bool,
}
