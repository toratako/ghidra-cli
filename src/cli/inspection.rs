use super::options::{ObjectOptions, QueryOptions};
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
    #[arg(long = "operand", value_name = "N", allow_hyphen_values = true, value_parser = clap::value_parser!(i32).range(-1..))]
    pub operand_index: i32,
    /// Meaning of the reference
    #[arg(long, ignore_case = true, value_parser = ["DATA", "READ", "WRITE", "READ_WRITE", "INDIRECTION", "UNCONDITIONAL_CALL", "CONDITIONAL_CALL", "COMPUTED_CALL", "UNCONDITIONAL_JUMP", "CONDITIONAL_JUMP", "COMPUTED_JUMP"])]
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
    #[arg(long = "operand", value_name = "N", allow_hyphen_values = true, value_parser = clap::value_parser!(i32).range(-1..))]
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
    /// Find immediate values and displacements in already-disassembled instructions
    Constant(FindConstantArgs),
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
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..=64))]
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
    let invalid = || {
        "Expected a decimal or 0x-prefixed integer from -9223372036854775808 to 18446744073709551615"
            .to_owned()
    };
    let (negative, magnitude) = match value.strip_prefix('-') {
        Some(magnitude) => (true, magnitude),
        None => (false, value),
    };
    let (digits, radix) = match magnitude
        .strip_prefix("0x")
        .or_else(|| magnitude.strip_prefix("0X"))
    {
        Some(digits) => (digits, 16),
        None => (magnitude, 10),
    };
    if digits.is_empty()
        || !digits.bytes().all(|digit| match radix {
            16 => digit.is_ascii_hexdigit(),
            _ => digit.is_ascii_digit(),
        })
    {
        return Err(invalid());
    }
    let magnitude = u64::from_str_radix(digits, radix).map_err(|_| invalid())?;
    if negative {
        if magnitude > 1u64 << 63 {
            return Err(invalid());
        }
        Ok(-(magnitude as i128))
    } else {
        Ok(magnitude as i128)
    }
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
