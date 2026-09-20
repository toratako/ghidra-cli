use super::OutputFormat;
use clap::Args;
use serde::{Deserialize, Serialize};

/// Target selection and output controls for a single result object.
#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct ObjectOptions {
    /// Target program
    #[arg(long)]
    pub program: Option<String>,

    /// Project name
    #[arg(long)]
    pub project: Option<String>,

    /// Field selection (comma-separated)
    #[arg(long)]
    pub fields: Option<String>,

    /// Output format (omitted: compact on TTY, json-compact otherwise)
    #[arg(long, short = 'o', value_enum, ignore_case = true)]
    pub format: Option<OutputFormat>,

    /// Output compact JSON (shorthand for --format=json-compact)
    #[arg(long)]
    pub json: bool,
}

impl From<&ObjectOptions> for QueryOptions {
    fn from(options: &ObjectOptions) -> Self {
        Self {
            program: options.program.clone(),
            project: options.project.clone(),
            fields: options.fields.clone(),
            format: options.format,
            json: options.json,
            filter: None,
            limit: None,
            offset: None,
            sort: None,
            count: false,
        }
    }
}

/// Common query options used across commands
#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct QueryOptions {
    /// Target program
    #[arg(long)]
    pub program: Option<String>,

    /// Project name
    #[arg(long)]
    pub project: Option<String>,

    /// Filter expression: <field><op><value>, e.g. 'name~PK' (contains),
    /// 'name=~"^PK_"' (regex), 'size>100'. Ops: = != > >= < <= ~ ^ $ =~.
    /// Combine with AND/OR/NOT. Bare words are rejected.
    #[arg(short, long)]
    pub filter: Option<String>,

    /// Field selection (comma-separated)
    #[arg(long)]
    pub fields: Option<String>,

    /// Output format (omitted: compact on TTY, json-compact otherwise)
    #[arg(long, short = 'o', value_enum, ignore_case = true)]
    pub format: Option<OutputFormat>,

    /// Maximum number of results (0 = unlimited; default 1000)
    #[arg(long)]
    pub limit: Option<usize>,

    /// Skip first N results
    #[arg(long)]
    pub offset: Option<usize>,

    /// Sort by field(s) (comma-separated, prefix with - for descending)
    #[arg(long, allow_hyphen_values = true)]
    pub sort: Option<String>,

    /// Only return count
    #[arg(long)]
    pub count: bool,

    /// Output compact JSON (shorthand for --format=json-compact)
    #[arg(long)]
    pub json: bool,
}
