use super::options::{ObjectOptions, QueryOptions};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum StringsCommands {
    /// List defined strings
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
    /// Get cross-references from one address, or an entire function with --whole-function
    From(XRefFromArgs),
    /// Create a reference of an explicit kind
    #[command(subcommand)]
    Create(XRefCreateCommands),
    /// Delete the exact reference only if its source matches
    Delete(XRefEditArgs),
    /// Select the primary reference for one source operand
    SetPrimary(XRefEditArgs),
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum XRefCreateCommands {
    /// Create an ordinary memory reference with USER_DEFINED source
    Memory(XRefCreateMemoryArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct XRefCreateMemoryArgs {
    /// Explicit address of the instruction or data start
    pub from: String,
    /// Explicit destination address; unmapped memory is allowed
    pub to: String,
    /// Zero-based operand index; -1 selects the whole instruction or data unit
    #[arg(long = "operand", value_name = "N", allow_hyphen_values = true, value_parser = |value: &str| super::numeric::ranged::<i32>(value, -1, i32::MAX as i128))]
    pub operand_index: i32,
    /// Meaning of the reference
    #[arg(long = "type", ignore_case = true, value_parser = ["DATA", "READ", "WRITE", "READ_WRITE", "INDIRECTION", "UNCONDITIONAL_CALL", "CONDITIONAL_CALL", "COMPUTED_CALL", "UNCONDITIONAL_JUMP", "CONDITIONAL_JUMP", "COMPUTED_JUMP"])]
    pub ref_type: String,
    #[command(flatten)]
    pub options: ObjectOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct XRefEditArgs {
    /// Explicit address of the instruction or data start
    pub from: String,
    /// Explicit destination address
    pub to: String,
    /// Zero-based operand index; -1 selects the whole instruction or data unit
    #[arg(long = "operand", value_name = "N", allow_hyphen_values = true, value_parser = |value: &str| super::numeric::ranged::<i32>(value, -1, i32::MAX as i128))]
    pub operand_index: i32,
    /// Required source of the existing reference
    #[arg(long, default_value = "USER_DEFINED", ignore_case = true, value_parser = ["USER_DEFINED", "ANALYSIS", "IMPORTED", "DEFAULT"])]
    pub source: String,
    #[command(flatten)]
    pub options: ObjectOptions,
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
    pub whole_function: bool,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum FindCommands {
    /// Find indirect-call candidates by a function's slots in an explicit vtable
    VirtualCallers(FindVirtualCallersArgs),
    /// Find candidate address tables using Ghidra's native search
    AddressTables(FindAddressTablesArgs),
    /// Find unowned instruction starts with call evidence as function candidates
    FunctionCandidates(FindFunctionCandidatesArgs),
    /// Find a case-insensitive substring in defined strings
    String(FindStringArgs),
    /// Find literal encoded text in program memory, including undefined data
    Text(FindTextArgs),
    /// Find exact hex bytes or a byte regular expression in program memory
    Bytes(FindBytesArgs),
    /// Find a substring in already-disassembled instructions (does not require xrefs)
    Instruction(FindInstructionArgs),
    /// Find immediate values and displacements in already-disassembled instructions
    Constant(FindConstantArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct FindVirtualCallersArgs {
    /// Callee: exact function name or explicit 0x-prefixed address
    #[arg(value_name = "FUNCTION", value_parser = clap::builder::NonEmptyStringValueParser::new())]
    pub function: String,
    /// Vtable address point (slot 0): exact symbol name or explicit address
    #[arg(long, value_name = "ADDRESS_POINT", value_parser = clap::builder::NonEmptyStringValueParser::new())]
    pub vtable: String,
    /// Number of absolute-pointer slots to inspect; table length is not inferred
    #[arg(long, value_name = "N", value_parser = |value: &str| super::numeric::ranged::<u32>(value, 1, 65_536))]
    pub entries: u32,
    /// Explicit C++ ABI used to interpret the vtable
    #[arg(long, value_enum)]
    pub abi: super::memory::VtableAbi,
    /// Search within one function (default: all internal functions)
    #[arg(long, value_name = "FUNCTION", value_parser = clap::builder::NonEmptyStringValueParser::new())]
    pub within: Option<String>,
    #[command(flatten)]
    pub options: QueryOptions,
}

impl FindVirtualCallersArgs {
    pub fn validate(&self) -> Result<(), String> {
        if !(1..=65_536).contains(&self.entries) {
            return Err("--entries must be an integer from 1 to 65536".into());
        }
        for (name, value) in [
            ("FUNCTION", Some(&self.function)),
            ("--vtable", Some(&self.vtable)),
            ("--within", self.within.as_ref()),
        ] {
            if value.is_some_and(|value| value.trim().is_empty()) {
                return Err(format!("{name} must not be empty"));
            }
        }
        Ok(())
    }
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct FindAddressTablesArgs {
    /// Inclusive bound on candidate starts: exact symbol name or explicit address
    #[arg(long)]
    pub start: Option<String>,
    /// Inclusive bound on candidate starts; detected tables may extend beyond it
    #[arg(long)]
    pub end: Option<String>,
    /// Minimum number of address entries in a candidate
    #[arg(long, value_name = "N", default_value_t = 3, value_parser = |value: &str| super::numeric::ranged::<u32>(value, 2, i32::MAX as i128))]
    pub min_entries: u32,
    /// Alignment of candidate starts and pointer targets (default: Ghidra's language alignment)
    #[arg(long, value_name = "N", value_parser = |value: &str| super::numeric::ranged::<u32>(value, 1, 8))]
    pub alignment: Option<u32>,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct FindFunctionCandidatesArgs {
    /// Inclusive bound on candidate starts: exact symbol name or explicit address
    #[arg(long)]
    pub start: Option<String>,
    /// Inclusive bound on candidate starts; callers may lie outside the range
    #[arg(long)]
    pub end: Option<String>,
    #[command(flatten)]
    pub options: QueryOptions,
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
pub struct FindConstantArgs {
    /// Exact integer in decimal or 0x-prefixed hex; negative values compare signed
    #[arg(value_name = "VALUE", allow_hyphen_values = true, required_unless_present = "min", conflicts_with_all = ["min", "max"], value_parser = parse_constant_value)]
    pub value: Option<String>,
    /// Inclusive minimum; a negative minimum selects signed comparison for the range
    #[arg(long, value_name = "MIN", allow_hyphen_values = true, requires = "max", value_parser = parse_constant_value)]
    pub min: Option<String>,
    /// Inclusive maximum (decimal or 0x-prefixed hex)
    #[arg(long, value_name = "MAX", allow_hyphen_values = true, requires = "min", value_parser = parse_constant_value)]
    pub max: Option<String>,
    /// Match only operand scalars with this bit width (default: any width)
    #[arg(long, value_parser = |value: &str| super::numeric::ranged::<u32>(value, 1, 64))]
    pub bits: Option<u32>,
    /// Inclusive start bound: explicit 0x-prefixed address or exact symbol name
    #[arg(long)]
    pub start: Option<String>,
    /// Inclusive end bound: explicit 0x-prefixed address or exact symbol name (same space)
    #[arg(long)]
    pub end: Option<String>,
    #[command(flatten)]
    pub options: QueryOptions,
}

impl FindConstantArgs {
    /// Validate the complete selection before connecting, including batch requests.
    pub fn validate(&self) -> Result<(), String> {
        match (&self.value, &self.min, &self.max) {
            (Some(value), None, None) => {
                constant_number(value)?;
            }
            (None, Some(min), Some(max)) => {
                let min = constant_number(min)?;
                let max = constant_number(max)?;
                if min > max {
                    return Err("--min must not be greater than --max".into());
                }
                if min < 0 && max > i64::MAX as i128 {
                    return Err(
                        "A signed range requires --max to fit a signed 64-bit integer".into(),
                    );
                }
            }
            _ => return Err("Provide VALUE or both --min and --max".into()),
        }
        if self.bits.is_some_and(|bits| !(1..=64).contains(&bits)) {
            return Err("--bits must be an integer from 1 to 64".into());
        }
        Ok(())
    }
}

fn parse_constant_value(value: &str) -> Result<String, String> {
    constant_number(value).map(|_| value.to_owned())
}

fn constant_number(value: &str) -> Result<i128, String> {
    super::numeric::ranged::<i128>(value, i64::MIN as i128, u64::MAX as i128)
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum GraphCommands {
    /// Inspect instruction control flow within one function
    Cfg(GraphCfgArgs),
    /// Call graph
    Calls(QueryOptions),
    /// List incoming call sites, resolving thunks and import pointers
    Callers(GraphFunctionArgs),
    /// List outgoing call sites, retaining destinations without a defined function
    Callees(GraphFunctionArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct GraphCfgArgs {
    /// Exact function name or explicit 0x-prefixed address
    pub function: String,
    /// Maximum returned blocks
    #[arg(long, value_name = "N", default_value_t = 1000, value_parser = |value: &str| super::numeric::ranged::<u32>(value, 1, i32::MAX as i128))]
    pub max_nodes: u32,
    /// Maximum returned flow records, including calls and boundaries
    #[arg(long, value_name = "N", default_value_t = 4000, value_parser = |value: &str| super::numeric::ranged::<u32>(value, 1, i32::MAX as i128))]
    pub max_edges: u32,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct GraphFunctionArgs {
    /// Exact name or explicit 0x-prefixed address (callees requires a function body)
    #[arg(value_name = "TARGET")]
    pub target: String,
    /// Number of call levels to traverse (default: 1; 0: unlimited)
    #[arg(long, value_parser = super::numeric::parse::<usize>)]
    pub depth: Option<usize>,
    #[command(flatten)]
    pub options: QueryOptions,
}
