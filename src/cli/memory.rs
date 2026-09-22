use super::{ObjectOptions, QueryOptions};
use clap::{Args, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum MemoryCommands {
    /// Show memory map
    Map(QueryOptions),
    /// List direct file mapping intervals, optionally matching an original-file offset
    FileMappings(MemoryFileMappingsArgs),
    /// Show the instruction, data, function, and memory block at a target
    Info(MemoryInfoArgs),
    /// Read memory
    Read(MemReadArgs),
    /// Write hex bytes to memory
    Write(MemWriteArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct MemoryFileMappingsArgs {
    /// Original-file byte offset in decimal or 0x notation; omit to list intervals
    #[arg(long, value_name = "OFFSET", value_parser = parse_file_offset)]
    pub file_offset: Option<String>,
    /// Explicit address directly mapped to the saved source to select
    #[arg(long, value_name = "ADDRESS")]
    pub source_at: Option<String>,
    #[command(flatten)]
    pub options: QueryOptions,
}

fn parse_nonnegative_long(value: &str) -> Result<i64, String> {
    let (digits, radix) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .map_or((value, 10), |digits| (digits, 16));
    if digits.is_empty()
        || !digits.bytes().all(|c| match radix {
            16 => c.is_ascii_hexdigit(),
            _ => c.is_ascii_digit(),
        })
    {
        return Err("use a nonnegative decimal or 0x integer".into());
    }
    i64::from_str_radix(digits, radix)
        .map_err(|_| format!("value must be between 0 and {}", i64::MAX))
}

fn parse_file_offset(value: &str) -> Result<String, String> {
    parse_nonnegative_long(value)?;
    Ok(value.to_owned())
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct MemoryInfoArgs {
    /// Exact symbol name or explicit 0x-prefixed address
    #[arg(value_name = "TARGET")]
    pub target: String,
    #[command(flatten)]
    pub options: ObjectOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct MemReadArgs {
    /// Explicit 0x-prefixed start address or exact symbol name (e.g. main)
    pub address: String,
    /// Number of bytes to read in decimal (e.g. 64)
    pub size: usize,
    /// Read current memory or preserved imported bytes; original requires a file mapping for the whole range
    #[arg(long, value_enum, default_value = "memory")]
    pub source: MemorySource,
    #[command(flatten)]
    pub options: ObjectOptions,
}

#[derive(ValueEnum, Clone, Copy, Serialize, Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum MemorySource {
    Memory,
    Original,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct MemWriteArgs {
    /// Explicit 0x-prefixed start address or exact symbol name
    pub address: String,
    /// Hex bytes, contiguous or quoted with spaces
    pub hex: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum PcodeCommands {
    /// Get raw PCode at an address
    At(PcodeAtArgs),
    /// Get PCode for an entire function
    Function(PcodeFunctionArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct PcodeAtArgs {
    /// Explicit 0x-prefixed address or exact symbol name
    pub address: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct PcodeFunctionArgs {
    /// Exact function name or explicit 0x-prefixed address
    pub function: String,
    /// Use high PCode from decompiler (vs raw from listing)
    #[arg(long)]
    pub high: bool,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct DisasmArgs {
    /// Exact symbol name or explicit 0x-prefixed address
    #[arg(value_name = "TARGET")]
    pub target: String,
    /// Inclusive end bound: explicit 0x-prefixed address or exact symbol name
    #[arg(long)]
    pub end: Option<String>,
    #[command(flatten)]
    pub options: QueryOptions,
}
