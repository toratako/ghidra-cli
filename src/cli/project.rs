use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct ProjectArgs {
    #[command(subcommand)]
    pub command: ProjectCommands,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum ProjectCommands {
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
    List(ProgramTargetArgs),
    /// Open/switch to a program
    Open(ProgramTargetArgs),
    /// Close a program
    Close(ProgramTargetArgs),
    /// Delete a program
    Delete(ProgramTargetArgs),
    /// Show program information
    Info(super::options::ObjectOptions),
    /// Show program statistics
    Stats(super::options::ObjectOptions),
    /// List program relocations
    ListRelocations(super::options::QueryOptions),
    /// Inspect and edit processor decoding context without redefining instructions
    #[command(subcommand)]
    Context(ProgramContextCommands),
    /// Set an absolute image base, moving default-space addresses without fixing pointer bytes
    Rebase(ProgramRebaseArgs),
    /// Import a binary into a project
    Import(ImportArgs),
    /// Export program
    Export(ExportArgs),
    /// Retry saving pending changes without restarting the bridge.
    /// Edits are saved automatically before a command reports success;
    /// use this after a save failure to retry without repeating the edit.
    Save(ProgramTargetArgs),
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum ProgramContextCommands {
    /// List processor context registers and their bit widths
    List(super::QueryOptions),
    /// Read stored, default, and effective context across inclusive address ranges
    Get(ProgramContextGetArgs),
    /// Set decoding context without deleting instructions or running analysis
    Set(ProgramContextSetArgs),
    /// Unset stored context so defaults can apply; this does not undo a previous set
    Clear(ProgramContextClearArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct ProgramContextGetArgs {
    /// Processor context register name from program context list
    pub register: String,
    /// Explicit 0x-prefixed address, optionally qualified with its address space
    pub start: String,
    /// Inclusive end in the same address space (default: START)
    #[arg(long)]
    pub end: Option<String>,
    #[command(flatten)]
    pub options: super::QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct ProgramContextSetArgs {
    /// Processor context register name from program context list
    pub register: String,
    /// Nonnegative decimal or 0x-prefixed integer fitting the register's bit width
    pub value: String,
    /// Explicit 0x-prefixed start address
    pub start: String,
    /// Inclusive end in the same address space; qualify independently of START
    #[arg(long)]
    pub end: String,
    #[command(flatten)]
    pub options: super::ObjectOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct ProgramContextClearArgs {
    /// Processor context register name from program context list
    pub register: String,
    /// Explicit 0x-prefixed start address
    pub start: String,
    /// Inclusive end in the same address space; qualify independently of START
    #[arg(long)]
    pub end: String,
    #[command(flatten)]
    pub options: super::ObjectOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct ProgramRebaseArgs {
    /// New absolute image base in the default address space, with an explicit 0x prefix
    pub base: String,
    #[command(flatten)]
    pub options: super::ObjectOptions,
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
    /// Export format
    #[arg(value_parser = ["xml", "c", "binary", "gzf", "asm", "hex", "html"], ignore_case = true)]
    pub format: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
    /// Output file
    #[arg(short, long)]
    pub output: String,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct ImportArgs {
    pub binary: String,
    /// Save the imported program under this name (default: input file name).
    /// An explicitly named existing program is never overwritten.
    #[arg(long)]
    pub name: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
    /// Force a specific Ghidra loader (for raw blobs, use BinaryLoader)
    #[arg(long)]
    pub loader: Option<String>,
    /// Ghidra language ID, e.g. x86:LE:32:default
    #[arg(long)]
    pub language: Option<String>,
    /// Ghidra compiler spec ID for the selected language
    #[arg(long)]
    pub compiler_spec: Option<String>,
    /// Explicit 0x-prefixed BinaryLoader base address (implies --loader BinaryLoader if omitted)
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
    /// Additional loader argument as NAME=VALUE; repeat for multiple arguments.
    /// baseAddr requires an explicit 0x-prefixed address.
    #[arg(long = "loader-option", value_name = "NAME=VALUE")]
    pub loader_options: Vec<String>,
    /// Import only — skip auto-analysis (the program is still persisted)
    #[arg(long, default_value = "false")]
    pub no_analyze: bool,
}
