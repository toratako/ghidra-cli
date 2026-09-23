use clap::{ArgAction, Parser, Subcommand};
use serde::{Deserialize, Serialize};

mod analysis;
mod annotations;
mod automation;
mod configuration;
mod data;
mod function;
mod inspection;
mod listing;
mod management;
mod memory;
pub(crate) mod numeric;
mod options;
mod output;
mod project;
mod references;
mod types;
mod vtable;

// Keep command types available through crate::cli while their definitions
// live with the command family that owns them.
pub use analysis::*;
pub use annotations::*;
pub use automation::*;
pub use configuration::*;
pub use data::*;
pub use function::*;
pub use inspection::*;
pub use listing::*;
pub use management::*;
pub use memory::*;
pub use options::{ObjectOptions, QueryOptions};
pub use output::OutputFormat;
pub use project::*;
pub use references::*;
pub use types::*;
pub use vtable::*;

#[derive(Parser, Clone)]
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
    /// Project management commands
    Project(ProjectArgs),

    /// Program/binary management commands
    #[command(subcommand)]
    Program(ProgramCommands),

    /// Function operations
    #[command(subcommand)]
    Function(FunctionCommands),

    /// String operations
    #[command(subcommand, name = "string")]
    Strings(StringsCommands),

    /// Symbol operations
    #[command(subcommand)]
    Symbol(SymbolCommands),

    /// Named integer constants and their instruction applications
    #[command(subcommand)]
    Equate(EquateCommands),

    /// Namespace and class organization
    #[command(subcommand)]
    Namespace(NamespaceCommands),

    /// Memory operations
    #[command(subcommand)]
    Memory(MemoryCommands),

    /// Inspect virtual-function tables using an explicit ABI
    #[command(subcommand)]
    Vtable(VtableCommands),

    /// Inspect defined data and read typed values
    #[command(subcommand)]
    Data(DataCommands),

    /// Instruction and data definitions in the listing
    #[command(subcommand)]
    Listing(ListingCommands),

    /// Cross-reference operations
    #[command(subcommand, name = "xref")]
    XRef(XRefCommands),

    /// Type operations
    #[command(subcommand)]
    Type(TypeCommands),

    /// Function tag operations
    #[command(subcommand)]
    Tag(TagCommands),

    /// PCode operations (intermediate representation)
    #[command(subcommand)]
    Pcode(PcodeCommands),

    /// Run analysis and configure program analysis settings
    #[command(subcommand)]
    Analysis(AnalysisCommands),

    /// Comment operations
    #[command(subcommand)]
    Comment(CommentCommands),

    /// Bookmark operations
    #[command(subcommand)]
    Bookmark(BookmarkCommands),

    /// Search operations
    #[command(subcommand)]
    Find(FindCommands),

    /// Graph operations
    #[command(subcommand)]
    Graph(GraphCommands),

    /// Decompile function
    Decompile(DecompileArgs),

    /// Show existing instructions from a name or address, optionally through --end
    #[command(name = "disassemble")]
    Disasm(DisasmArgs),

    /// Script execution
    #[command(subcommand)]
    Script(ScriptCommands),

    /// Batch operations
    Batch(BatchArgs),

    /// Configuration management
    #[command(subcommand)]
    Config(ConfigCommands),

    /// Check installation, storage writes, and local communication
    Doctor {
        /// Also start, ping, and stop Ghidra using a disposable project and the current environment
        #[arg(long)]
        runtime: bool,
    },

    /// Bridge lifecycle and health
    #[command(subcommand)]
    Bridge(BridgeCommands),

    /// Inspect and cancel bridge jobs
    #[command(subcommand)]
    Job(JobCommands),
}

#[cfg(test)]
mod tests;
