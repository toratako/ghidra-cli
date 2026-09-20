use super::options::QueryOptions;
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum StringsCommands {
    /// List all strings
    List(QueryOptions),
    /// Get references to a string
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
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct XRefArgs {
    /// Exact symbol name or explicit 0x-prefixed address
    #[arg(value_name = "TARGET")]
    pub target: String,
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
    /// Find calls to the target across the selected program (including resolved thunks/import pointers)
    Calls(FindCallsArgs),
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

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct FindCallsArgs {
    /// Exact function name or explicit 0x-prefixed address
    #[arg(value_name = "TARGET")]
    pub target: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum GraphCommands {
    /// Call graph
    Calls(QueryOptions),
    /// Get callers of function
    Callers(GraphFunctionArgs),
    /// Get callees of function
    Callees(GraphFunctionArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct GraphFunctionArgs {
    /// Exact function name or explicit 0x-prefixed address
    #[arg(value_name = "TARGET")]
    pub target: String,
    #[arg(long)]
    pub depth: Option<usize>,
    #[command(flatten)]
    pub options: QueryOptions,
}
