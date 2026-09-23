use super::{numeric, ObjectOptions, QueryOptions};
use clap::{Args, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum MemoryCommands {
    /// List direct file mapping intervals, optionally matching an original-file offset
    FileMappings(MemoryFileMappingsArgs),
    /// List, create, edit, move, or delete memory blocks
    #[command(subcommand)]
    Block(MemoryBlockCommands),
    /// Show the instruction, data, function, and memory block at a target
    Info(MemoryInfoArgs),
    /// Read memory
    Read(MemReadArgs),
    /// Read explicit virtual-function slots and ABI metadata without changing the program
    ReadVtable(VtableReadArgs),
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
    /// List memory layout as blocks
    List(QueryOptions),
    /// Create a block with explicit initialization and permissions
    Create(MemoryBlockCreateArgs),
    /// Set block attributes together, preserving omitted values
    Set(MemoryBlockSetArgs),
    /// Move a whole block and its analysis within the same address space
    Move(MemoryBlockMoveArgs),
    /// Delete a block and its associated analysis
    Delete(MemoryBlockDeleteArgs),
}

impl MemoryBlockCommands {
    pub fn options(&self) -> QueryOptions {
        match self {
            Self::List(options) => options.clone(),
            Self::Create(args) => (&args.options).into(),
            Self::Set(args) => (&args.options).into(),
            Self::Move(args) => (&args.options).into(),
            Self::Delete(args) => (&args.options).into(),
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
    /// Positive size in bytes, in decimal or 0x hexadecimal
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
    #[arg(long, action = clap::ArgAction::Set, default_value_t = false)]
    pub volatile: bool,
    /// Create a new overlay space with this name over START's physical space
    #[arg(long, value_name = "NAME")]
    pub overlay: Option<String>,
    #[command(flatten)]
    pub options: ObjectOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
#[command(group(clap::ArgGroup::new("edit").required(true).multiple(true).args(["name", "permissions", "volatile"])))]
pub struct MemoryBlockSetArgs {
    /// Exact block start as an explicit address, including its space when needed
    pub block_start: String,
    /// New block display name; preserves its address space
    #[arg(long, value_parser = clap::builder::NonEmptyStringValueParser::new())]
    pub name: Option<String>,
    /// Replacement combination of r, w, x, or none
    #[arg(long, value_parser = parse_permissions)]
    pub permissions: Option<String>,
    /// Whether the block is volatile; omit to preserve its current value
    #[arg(long, action = clap::ArgAction::Set)]
    pub volatile: Option<bool>,
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

fn parse_file_offset(value: &str) -> Result<String, String> {
    numeric::ranged::<i64>(value, 0, i64::MAX as i128)?;
    Ok(value.to_owned())
}

fn parse_block_size(value: &str) -> Result<i64, String> {
    numeric::ranged(value, 1, i64::MAX as i128)
}

fn parse_fill_byte(value: &str) -> Result<u8, String> {
    numeric::parse(value)
}

fn parse_high_ir_limit(value: &str) -> Result<u32, String> {
    numeric::ranged(value, 1, i32::MAX as i128)
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
    /// Number of bytes to read, in decimal or 0x hexadecimal
    #[arg(long, value_parser = numeric::parse::<usize>)]
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
pub struct VtableReadArgs {
    /// Address point (slot 0): exact symbol name or explicit 0x-prefixed address
    #[arg(value_name = "TARGET")]
    pub target: String,
    /// Number of slots to read; the table's length is not inferred
    #[arg(long, value_name = "N", value_parser = |value: &str| numeric::ranged::<u32>(value, 1, 65_536))]
    pub entries: u32,
    /// Explicit C++ ABI used to interpret metadata before slot 0
    #[arg(long, value_enum)]
    pub abi: VtableAbi,
    /// Slot representation; relative32 selects LLVM's relative Itanium layout
    #[arg(long, value_enum, default_value = "absolute")]
    pub encoding: VtableEncoding,
    #[command(flatten)]
    pub options: ObjectOptions,
}

impl VtableReadArgs {
    pub fn validate(&self) -> Result<(), String> {
        if !(1..=65_536).contains(&self.entries) {
            return Err("--entries must be an integer from 1 to 65536".into());
        }
        if self.abi == VtableAbi::Msvc && self.encoding == VtableEncoding::Relative32 {
            return Err("--encoding relative32 requires --abi itanium".into());
        }
        Ok(())
    }
}

#[derive(ValueEnum, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum VtableAbi {
    Itanium,
    Msvc,
}

#[derive(ValueEnum, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum VtableEncoding {
    Absolute,
    Relative32,
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
    #[arg(long, value_name = "N", requires = "high", value_parser = parse_high_ir_limit)]
    pub max_nodes: Option<u32>,
    /// Maximum High IR relationships (default: 4000)
    #[arg(long, value_name = "N", requires = "high", value_parser = parse_high_ir_limit)]
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
