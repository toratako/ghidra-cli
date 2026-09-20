use super::options::QueryOptions;
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum StringsCommands {
    /// List all strings
    List(QueryOptions),
    /// Find defined strings containing PATTERN (case-insensitive) and list their references
    Refs(StringRefsArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct StringRefsArgs {
    /// Case-insensitive substring of the decoded string value
    #[arg(value_name = "PATTERN")]
    pub pattern: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum XRefCommands {
    /// Get cross-references to address
    To(XRefArgs),
    /// Get cross-references from one address, or an entire function with --function
    From(XRefFromArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct XRefArgs {
    /// Exact symbol name or explicit 0x-prefixed address
    #[arg(value_name = "TARGET")]
    pub target: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct XRefFromArgs {
    /// Exact symbol name or explicit 0x-prefixed address
    #[arg(value_name = "TARGET")]
    pub target: String,
    /// Read references from the whole containing function, including disjoint body ranges
    #[arg(long)]
    pub function: bool,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum FindCommands {
    /// Find a case-insensitive substring in defined strings
    String(FindStringArgs),
    /// Find literal encoded text in program memory, including undefined data
    Text(FindTextArgs),
    /// Find exact hex bytes or a byte regular expression in program memory
    Bytes(FindBytesArgs),
    /// Find a substring in already-disassembled instructions (does not require xrefs)
    Instruction(FindInstructionArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct FindStringArgs {
    pub pattern: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct FindTextArgs {
    /// Non-empty literal text (case-sensitive; no regular expressions)
    #[arg(value_parser = clap::builder::NonEmptyStringValueParser::new())]
    pub text: String,
    /// Java charset name, e.g. utf-8, utf-16le, utf-16be, ascii, shift_jis
    #[arg(long, default_value = "utf-8", value_parser = clap::builder::NonEmptyStringValueParser::new())]
    pub encoding: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct FindBytesArgs {
    /// Hex bytes (e.g. "48 8b 05"), or a Java byte pattern with --regex
    #[arg(value_name = "PATTERN")]
    pub hex: String,
    /// Use Ghidra's native byte regex search (case-sensitive; . matches any byte)
    #[arg(long)]
    #[serde(default)]
    pub regex: bool,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct FindInstructionArgs {
    /// Literal substring of Ghidra's instruction text (case-insensitive by default)
    #[arg(value_parser = clap::builder::NonEmptyStringValueParser::new())]
    pub pattern: String,
    /// Inclusive start bound: explicit 0x-prefixed address or exact symbol name
    #[arg(long)]
    pub start: Option<String>,
    /// Inclusive end bound: explicit 0x-prefixed address or exact symbol name (same space)
    #[arg(long)]
    pub end: Option<String>,
    /// Match instruction text case-sensitively
    #[arg(long)]
    pub case_sensitive: bool,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum GraphCommands {
    /// Call graph
    Calls(QueryOptions),
    /// List incoming call sites, resolving thunks and import pointers
    Callers(GraphFunctionArgs),
    /// List outgoing call sites, retaining destinations without a defined function
    Callees(GraphFunctionArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct GraphFunctionArgs {
    /// Exact name or explicit 0x-prefixed address (callees requires a function body)
    #[arg(value_name = "TARGET")]
    pub target: String,
    /// Number of call levels to traverse (default: 1; 0: unlimited)
    #[arg(long)]
    pub depth: Option<usize>,
    #[command(flatten)]
    pub options: QueryOptions,
}
