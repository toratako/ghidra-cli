use super::{ObjectOptions, QueryOptions};
use clap::{Args, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum MemoryCommands {
    /// Show memory map
    Map(QueryOptions),
    /// List direct file mapping intervals, optionally matching an original-file offset
    FileMappings(MemoryFileMappingsArgs),
    /// Create, edit, move, or delete memory blocks
    #[command(subcommand)]
    Block(MemoryBlockCommands),
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

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum MemoryBlockCommands {
    /// Create a block with explicit initialization and permissions
    Create(MemoryBlockCreateArgs),
    /// Change a block's display name, preserving its address space
    Rename(MemoryBlockRenameArgs),
    /// Replace all read, write, and execute permissions
    SetPermissions(MemoryBlockPermissionsArgs),
    /// Set or clear a block's volatile attribute
    SetVolatile(MemoryBlockVolatileArgs),
    /// Move a whole block and its analysis within the same address space
    Move(MemoryBlockMoveArgs),
    /// Delete a block and its associated analysis
    Delete(MemoryBlockDeleteArgs),
}

impl MemoryBlockCommands {
    pub fn options(&self) -> &ObjectOptions {
        match self {
            Self::Create(args) => &args.options,
            Self::Rename(args) => &args.options,
            Self::SetPermissions(args) => &args.options,
            Self::SetVolatile(args) => &args.options,
            Self::Move(args) => &args.options,
            Self::Delete(args) => &args.options,
        }
    }
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
#[command(group(clap::ArgGroup::new("initialization").required(true).args(["uninitialized", "fill"])))]
pub struct MemoryBlockCreateArgs {
    /// Block display name
    pub name: String,
    /// Explicit start address, qualified with the space name for an existing overlay
    #[arg(long)]
    pub start: String,
    /// Positive size in decimal bytes
    #[arg(long, value_parser = parse_block_size)]
    pub size: i64,
    /// Create memory without known byte values
    #[arg(long)]
    pub uninitialized: bool,
    /// Initialize every byte to this decimal or 0x byte value
    #[arg(long, value_name = "BYTE", value_parser = parse_fill_byte)]
    pub fill: Option<u8>,
    /// Combination of r, w, x, or none
    #[arg(long, value_parser = parse_permissions)]
    pub permissions: String,
    /// Mark the block volatile, as for MMIO
    #[arg(long)]
    pub volatile: bool,
    /// Create a new overlay space with this name over START's physical space
    #[arg(long, value_name = "NAME")]
    pub overlay: Option<String>,
    #[command(flatten)]
    pub options: ObjectOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct MemoryBlockRenameArgs {
    /// Exact block start as an explicit address, including its space when needed
    pub block_start: String,
    /// New block display name
    pub name: String,
    #[command(flatten)]
    pub options: ObjectOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct MemoryBlockPermissionsArgs {
    /// Exact block start as an explicit address, including its space when needed
    pub block_start: String,
    /// Replacement combination of r, w, x, or none
    #[arg(long, value_parser = parse_permissions)]
    pub permissions: String,
    #[command(flatten)]
    pub options: ObjectOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct MemoryBlockVolatileArgs {
    /// Exact block start as an explicit address, including its space when needed
    pub block_start: String,
    /// Whether the block is volatile
    #[arg(long, required = true, action = clap::ArgAction::Set)]
    pub value: bool,
    #[command(flatten)]
    pub options: ObjectOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct MemoryBlockMoveArgs {
    /// Exact block start as an explicit address, including its space when needed
    pub block_start: String,
    /// New explicit start address in the same address space
    pub start: String,
    #[command(flatten)]
    pub options: ObjectOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct MemoryBlockDeleteArgs {
    /// Exact block start as an explicit address, including its space when needed
    pub block_start: String,
    #[command(flatten)]
    pub options: ObjectOptions,
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

fn parse_block_size(value: &str) -> Result<i64, String> {
    if value.is_empty() || !value.bytes().all(|c| c.is_ascii_digit()) {
        return Err("use a positive decimal byte count".into());
    }
    value
        .parse::<i64>()
        .ok()
        .filter(|size| *size > 0)
        .ok_or_else(|| format!("size must be between 1 and {} bytes", i64::MAX))
}

fn parse_fill_byte(value: &str) -> Result<u8, String> {
    u8::try_from(parse_nonnegative_long(value)?)
        .map_err(|_| "fill byte must be between 0 and 255".into())
}

fn parse_permissions(value: &str) -> Result<String, String> {
    if value == "none" {
        return Ok(value.to_owned());
    }
    let mut permissions = String::new();
    for flag in ['r', 'w', 'x'] {
        if value.contains(flag) {
            permissions.push(flag);
        }
    }
    if permissions.is_empty() || permissions.len() != value.len() {
        return Err("use a combination of r, w, x (each at most once), or none".into());
    }
    Ok(permissions)
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
    #[arg(long)]
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
    #[arg(long = "bytes", value_name = "HEX")]
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
    /// Inspect raw function P-code or structured decompiler values and control flow
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
    /// Return structured High P-code with result-local IDs, def/use, and High CFG
    #[arg(long)]
    pub high: bool,
    /// Maximum High IR entities: operations, values, blocks, variables, and symbols (default: 1000)
    #[arg(long, value_name = "N", requires = "high", value_parser = clap::value_parser!(u32).range(1..=i32::MAX as i64))]
    pub max_nodes: Option<u32>,
    /// Maximum High IR relationships (default: 4000)
    #[arg(long, value_name = "N", requires = "high", value_parser = clap::value_parser!(u32).range(1..=i32::MAX as i64))]
    pub max_edges: Option<u32>,
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
