use clap::{Args, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum AnalyzerCommands {
    /// List all analyzers and their enabled status
    #[command(alias = "ls")]
    List(AnalyzerListArgs),
    /// Enable or disable an analyzer; run `analyze` to apply the setting
    Set(AnalyzerSetArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct AnalyzerListArgs {
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct AnalyzerSetArgs {
    /// Analyzer name
    pub name: String,
    /// Enable (true) or disable (false)
    #[arg(action = clap::ArgAction::Set)]
    pub enabled: bool,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum ScriptCommands {
    /// Run a script file (pass "-" to read Java source from stdin instead of a path)
    Run(ScriptRunArgs),
    /// List available scripts
    List,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct ScriptRunArgs {
    /// Path to a script file, or "-" to read Java source from stdin
    pub script_path: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
    /// Expected output artifact: PATH or PATH:MIN_ROWS (repeatable). The job
    /// fails if the artifact is missing, empty, or below MIN_ROWS.
    /// MIN_ROWS is supported for .jsonl/.ndjson only; CSV row counting is WIP.
    #[arg(long = "expect", value_name = "PATH[:MIN_ROWS]")]
    pub expect: Vec<String>,
    /// Allow an expected artifact to exist but be empty.
    #[arg(long)]
    pub allow_empty: bool,
    /// Script arguments (after --)
    #[arg(last = true)]
    pub args: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum BatchErrorPolicy {
    Continue,
    Stop,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct BatchArgs {
    pub script_file: String,

    /// Action after a command error (default: continue; nested batches inherit).
    /// Save failures and timeouts always stop. Completed edits are not rolled back.
    #[arg(long, value_enum, value_name = "MODE")]
    pub on_error: Option<BatchErrorPolicy>,

    #[arg(long)]
    pub project: Option<String>,

    #[arg(long)]
    pub program: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct AnalyzeArgs {
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}
