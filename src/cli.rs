use clap::{ArgAction, Parser, Subcommand};
use serde::{Deserialize, Serialize};

mod annotations;
mod automation;
mod configuration;
mod function;
mod inspection;
mod memory;
mod options;
mod project;
mod types;

// Keep command types available through crate::cli while their definitions
// live with the command family that owns them.
pub use annotations::*;
pub use automation::*;
pub use configuration::*;
pub use function::*;
pub use inspection::*;
pub use memory::*;
pub use options::QueryOptions;
pub use project::*;
pub use types::*;

#[derive(Parser)]
#[command(name = "ghidra-cli")]
#[command(version, about = "Rust CLI for Ghidra reverse engineering", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Increase log verbosity printed to stderr (-v=warn, -vv=info, -vvv=debug)
    #[arg(short, long, action = ArgAction::Count, global = true)]
    pub verbose: u8,

    /// Suppress non-essential output
    #[arg(short, long, global = true)]
    pub quiet: bool,

    /// Output as JSON
    #[arg(long, global = true)]
    pub json: bool,

    /// Output JSON with pretty formatting
    #[arg(long, global = true)]
    pub pretty: bool,

    /// Project name or path (can also be specified per-subcommand)
    #[arg(long, global = true)]
    pub project: Option<String>,

    /// Program name within the project (can also be specified per-subcommand)
    #[arg(long, global = true)]
    pub program: Option<String>,

    /// Directory under which Ghidra projects are stored.
    /// Overrides `GHIDRA_PROJECT_DIR`, config `ghidra_project_dir`, and the default location.
    /// Note: Ghidra 12.1+ rejects paths containing a dot-prefixed component.
    #[arg(long, global = true)]
    pub projects_dir: Option<std::path::PathBuf>,

    /// Full JDK home for Ghidra to use (must be a JDK, not a JRE).
    /// Overrides config `java_home` and auto-detection.
    #[arg(long, global = true)]
    pub java_home: Option<std::path::PathBuf>,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum Commands {
    /// Query functions, strings, imports, exports, or memory
    Query(QueryArgs),

    /// Project management commands
    Project(ProjectArgs),

    /// Program/binary management commands
    #[command(subcommand, alias = "prog", alias = "programs")]
    Program(ProgramCommands),

    /// Function operations
    #[command(subcommand, alias = "fn", alias = "func", alias = "functions")]
    Function(FunctionCommands),

    /// String operations
    #[command(subcommand, alias = "string", alias = "str")]
    Strings(StringsCommands),

    /// Symbol operations
    #[command(subcommand, alias = "sym", alias = "symbols")]
    Symbol(SymbolCommands),

    /// Memory operations
    #[command(subcommand, alias = "mem")]
    Memory(MemoryCommands),

    /// Cross-reference operations
    #[command(
        subcommand,
        alias = "xrefs",
        alias = "xref",
        alias = "crossref",
        alias = "crossrefs"
    )]
    XRef(XRefCommands),

    /// Type operations
    #[command(subcommand, alias = "types")]
    Type(TypeCommands),

    /// Function tag operations
    #[command(subcommand, alias = "tags")]
    Tag(TagCommands),

    /// PCode operations (intermediate representation)
    #[command(subcommand)]
    Pcode(PcodeCommands),

    /// Analysis control (list/enable/disable analyzers, re-analyze)
    #[command(subcommand, alias = "analysis-control")]
    Analyzer(AnalyzerCommands),

    /// Comment operations
    #[command(subcommand, alias = "comments")]
    Comment(CommentCommands),

    /// Search operations
    #[command(subcommand, alias = "search")]
    Find(FindCommands),

    /// Graph operations
    #[command(subcommand, alias = "callgraph", alias = "cg")]
    Graph(GraphCommands),

    /// Decompile function
    #[command(alias = "decomp", alias = "dec")]
    Decompile(DecompileArgs),

    /// Disassemble code
    #[command(alias = "disassemble", alias = "dis")]
    Disasm(DisasmArgs),

    /// Disassemble at an address, disassembling first if nothing is there yet
    /// (the common case for computed-jump targets auto-analysis never reached)
    #[command(alias = "disassemble-at")]
    DisasmAt(DisasmAtArgs),

    /// Clear code units in a range (undoes auto-analysis that mis-disassembled
    /// through inline data), optionally re-disassembling at a precise address
    Clear(ClearArgs),

    /// Script execution
    #[command(subcommand, alias = "scripts")]
    Script(ScriptCommands),

    /// Batch operations
    Batch(BatchArgs),

    /// Configuration management
    #[command(subcommand)]
    Config(ConfigCommands),

    /// Program statistics
    Stats(StatsArgs),

    /// Check installation, storage writes, and local communication
    Doctor {
        /// Also start, ping, and stop Ghidra using a disposable project and the current environment
        #[arg(long)]
        runtime: bool,
    },

    /// Import a binary into a project
    Import(ImportArgs),

    /// Analyze a program
    #[command(alias = "analysis")]
    Analyze(AnalyzeArgs),

    /// Start the bridge
    Start {
        /// Project path
        #[arg(long)]
        project: Option<String>,
        /// Program name to load
        #[arg(long)]
        program: Option<String>,
    },

    /// Stop the bridge
    Stop {
        /// Project path
        #[arg(long)]
        project: Option<String>,
    },

    /// Restart the bridge
    Restart {
        /// Project path
        #[arg(long)]
        project: Option<String>,
        /// Program name to load
        #[arg(long)]
        program: Option<String>,
    },

    /// Show bridge status
    Status {
        /// Project path
        #[arg(long)]
        project: Option<String>,
    },

    /// Ping the bridge
    Ping {
        /// Project path
        #[arg(long)]
        project: Option<String>,
    },

    /// List active, queued, and recently completed bridge jobs
    Jobs {
        /// Show one job by ID; omit for the bridge queue and recent jobs
        job_id: Option<u64>,
        /// Project path
        #[arg(long)]
        project: Option<String>,
    },

    /// Request cooperative cancellation of a bridge job (defaults to active job)
    Cancel {
        /// Job ID; omit to cancel the currently active job
        job_id: Option<u64>,
        /// Project path
        #[arg(long)]
        project: Option<String>,
    },

    /// Download and setup Ghidra automatically
    Setup(SetupArgs),
}

#[cfg(test)]
mod tests;
