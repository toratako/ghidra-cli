use super::options::QueryOptions;
use crate::format::OutputFormat;
use clap::{Args, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};

// Only types routed by execute_via_bridge belong here; query::DataType also
// contains types that the query command does not implement.
#[derive(Clone, Copy, Serialize, Deserialize, Debug, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum QueryDataType {
    Functions,
    Strings,
    Imports,
    Exports,
    Memory,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct QueryArgs {
    /// Data type to query
    #[arg(value_enum)]
    pub data_type: QueryDataType,

    /// Target program
    #[arg(long, env = "GHIDRA_DEFAULT_PROGRAM")]
    pub program: Option<String>,

    /// Project name
    #[arg(long, env = "GHIDRA_DEFAULT_PROJECT")]
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

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum StringsCommands {
    /// List all strings
    #[command(alias = "ls")]
    List(QueryOptions),
    /// Get references to a string
    #[command(alias = "references", alias = "xrefs")]
    Refs(StringRefsArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct StringRefsArgs {
    pub string: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum XRefCommands {
    /// Get cross-references to address
    To(XRefArgs),
    /// Get cross-references from address
    From(XRefArgs),
    /// List all cross-references
    List(XRefArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct XRefArgs {
    /// XRef target (name | 0xaddr | FUN_<hex>)
    #[arg(value_name = "TARGET", required_unless_present = "target")]
    pub positional_target: Option<String>,
    /// XRef target (name | 0xaddr | FUN_<hex>)
    #[arg(long = "target", value_name = "TARGET")]
    pub target: Option<String>,
    #[command(flatten)]
    pub options: QueryOptions,
}

impl XRefArgs {
    pub fn resolved_target(&self) -> &str {
        self.target
            .as_deref()
            .or(self.positional_target.as_deref())
            .expect("clap should ensure target is provided")
    }
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum FindCommands {
    /// Find strings
    #[command(alias = "str", alias = "strings")]
    String(FindStringArgs),
    /// Find byte patterns
    Bytes(FindBytesArgs),
    /// Find functions
    #[command(alias = "func", alias = "fn", alias = "functions")]
    Function(FindFunctionArgs),
    /// Find calls to function
    Calls(FindCallsArgs),
    /// Find crypto constants
    #[command(alias = "encryption")]
    Crypto(QueryOptions),
    /// Find interesting functions
    #[command(alias = "suspicious", alias = "notable")]
    Interesting(QueryOptions),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct FindStringArgs {
    pub pattern: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct FindBytesArgs {
    /// Hex bytes, contiguous or quoted with spaces (e.g. 488b05 or "48 8b 05")
    pub hex: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct FindFunctionArgs {
    pub pattern: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct FindCallsArgs {
    /// Function target (name | 0xaddr | FUN_<hex>)
    #[arg(value_name = "TARGET", required_unless_present = "target")]
    pub positional_target: Option<String>,
    /// Function target (name | 0xaddr | FUN_<hex>)
    #[arg(long = "target", value_name = "TARGET")]
    pub target: Option<String>,
    #[command(flatten)]
    pub options: QueryOptions,
}

impl FindCallsArgs {
    pub fn resolved_target(&self) -> &str {
        self.target
            .as_deref()
            .or(self.positional_target.as_deref())
            .expect("clap should ensure target is provided")
    }
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum GraphCommands {
    /// Call graph
    Calls(QueryOptions),
    /// Get callers of function
    #[command(alias = "called-by", alias = "incoming")]
    Callers(GraphFunctionArgs),
    /// Get callees of function
    #[command(alias = "calls-to", alias = "outgoing")]
    Callees(GraphFunctionArgs),
    /// Export graph
    Export(GraphExportArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct GraphFunctionArgs {
    /// Function target (name | 0xaddr | FUN_<hex>)
    #[arg(value_name = "TARGET", required_unless_present = "target")]
    pub positional_target: Option<String>,
    /// Function target (name | 0xaddr | FUN_<hex>)
    #[arg(long = "target", value_name = "TARGET")]
    pub target: Option<String>,
    #[arg(long)]
    pub depth: Option<usize>,
    #[command(flatten)]
    pub options: QueryOptions,
}

impl GraphFunctionArgs {
    pub fn resolved_target(&self) -> &str {
        self.target
            .as_deref()
            .or(self.positional_target.as_deref())
            .expect("clap should ensure target is provided")
    }
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct GraphExportArgs {
    /// Export format (e.g., dot, json)
    #[arg(id = "export_format")]
    pub format: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum DiffCommands {
    /// Compare two programs
    Programs(DiffProgramsArgs),
    /// Compare functions
    Functions(DiffFunctionsArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct DiffProgramsArgs {
    pub program1: String,
    pub program2: String,
    #[arg(long)]
    pub format: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct DiffFunctionsArgs {
    /// First function (name or address)
    pub func1: String,
    /// Second function (name or address)
    pub func2: String,
    #[arg(long)]
    pub format: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum DumpCommands {
    /// Dump imports
    Imports(QueryOptions),
    /// Dump exports
    Exports(QueryOptions),
    /// Dump functions
    Functions(QueryOptions),
    /// Dump strings
    Strings(QueryOptions),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct SummaryArgs {
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct StatsArgs {
    #[command(flatten)]
    pub options: QueryOptions,
}
