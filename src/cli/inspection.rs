use super::options::QueryOptions;
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};

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
pub struct FindBytesArgs {
    /// Hex bytes, contiguous or quoted with spaces (e.g. 488b05 or "48 8b 05")
    pub hex: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct FindInstructionArgs {
    /// Literal substring of Ghidra's instruction text (case-insensitive by default)
    #[arg(value_parser = clap::builder::NonEmptyStringValueParser::new())]
    pub pattern: String,
    /// Include instructions starting at or after this address
    #[arg(long)]
    pub start: Option<String>,
    /// Include instructions starting at or before this address (same address space)
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
