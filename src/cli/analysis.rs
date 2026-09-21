use super::{ObjectOptions, QueryOptions};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum AnalysisCommands {
    /// Analyze or reanalyze the entire program using its saved analysis settings
    Run(AnalysisRunArgs),
    /// Inspect and change program analysis settings, including analyzer enablement
    #[command(subcommand)]
    Option(AnalysisOptionCommands),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct AnalysisRunArgs {
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
    /// Value in the option's type: decimal integers, true/false, enum names from choices,
    /// or literal text. File options require an absolute path.
    #[arg(allow_hyphen_values = true)]
    pub value: String,
    #[command(flatten)]
    pub options: ObjectOptions,
}
