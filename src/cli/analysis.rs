use super::{ObjectOptions, QueryOptions};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum AnalysisCommands {
    /// Run saved analysis settings (default: the entire program)
    Run(AnalysisRunArgs),
    /// Inspect and change program analysis settings, including analyzer enablement
    #[command(subcommand)]
    Option(AnalysisOptionCommands),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct AnalysisRunArgs {
    /// Inclusive start address to seed reanalysis; effects can extend outside the range
    #[arg(long, requires = "end", conflicts_with = "pending")]
    pub start: Option<String>,
    /// Inclusive end in the same address space; requires --start
    #[arg(long, requires = "start", conflicts_with = "pending")]
    pub end: Option<String>,
    /// Process the open program's queued analysis; does not resume cancelled or closed work
    #[arg(long)]
    pub pending: bool,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum AnalysisOptionCommands {
    /// List analysis settings with their types, values, defaults, and descriptions
    List(QueryOptions),
    /// Get one analysis setting by its exact name
    Get(AnalysisOptionGetArgs),
    /// Save an analysis setting without running analysis
    Set(AnalysisOptionSetArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct AnalysisOptionGetArgs {
    /// Exact option name from analysis option list (including any dotted path)
    pub name: String,
    #[command(flatten)]
    pub options: ObjectOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct AnalysisOptionSetArgs {
    /// Exact option name from analysis option list (including any dotted path)
    pub name: String,
    /// Value in the option's type: decimal or 0x integers, true/false, enum names from choices,
    /// or literal text. File options require an absolute path.
    #[arg(allow_hyphen_values = true)]
    pub value: String,
    #[command(flatten)]
    pub options: ObjectOptions,
}
