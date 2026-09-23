use clap::{Args, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum ScriptCommands {
    /// Run a script file (pass "-" to read Java source from stdin instead of a path)
    Run(ScriptRunArgs),
    /// List .java and .py files in Ghidra's script directories
    ///
    /// Listing does not check whether a file can be executed.
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
    /// Expected output artifact (repeatable). Missing or empty artifacts fail the job.
    #[arg(long = "expect", value_name = "PATH")]
    pub expect: Vec<String>,
    /// Expected JSONL/NDJSON artifact and minimum row count (repeatable).
    #[arg(long, num_args = 2, value_names = ["PATH", "MIN_ROWS"], action = clap::ArgAction::Append)]
    pub expect_rows: Vec<String>,
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
    /// Command file; selected lines and nested batches are checked before execution
    pub script_file: String,

    /// Start at this one-based source line, including blank lines and comments in the count
    #[arg(long, value_name = "N")]
    pub from_line: Option<std::num::NonZeroUsize>,

    /// Action after a runtime command error (default: continue; nested batches inherit).
    /// Transaction/save failures, timeouts, and lost responses always stop. Commands run sequentially;
    /// a failed ordinary request rolls back its own edits, while earlier commands remain saved.
    #[arg(long, value_enum, value_name = "MODE")]
    pub on_error: Option<BatchErrorPolicy>,

    #[arg(long)]
    pub project: Option<String>,

    #[arg(long)]
    pub program: Option<String>,
}
