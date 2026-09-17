use super::options::QueryOptions;
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum MemoryCommands {
    /// Show memory map
    Map(QueryOptions),
    /// Read memory
    Read(MemReadArgs),
    /// Write hex bytes to memory
    Write(MemWriteArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct MemReadArgs {
    /// Explicit 0x-prefixed start address or exact symbol name (e.g. main)
    pub address: String,
    /// Number of bytes to read in decimal (e.g. 64)
    pub size: usize,
    #[command(flatten)]
    pub options: QueryOptions,
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
    #[arg(value_name = "TARGET", required_unless_present = "target")]
    pub positional_target: Option<String>,
    /// Exact symbol name or explicit 0x-prefixed address
    #[arg(long = "target", value_name = "TARGET")]
    pub target: Option<String>,
    /// Number of instructions to disassemble
    #[arg(long = "instructions", short = 'n')]
    pub num_instructions: Option<usize>,
    /// Inclusive end bound: explicit 0x-prefixed address or exact symbol name
    #[arg(long, conflicts_with = "num_instructions")]
    pub end: Option<String>,
    #[command(flatten)]
    pub options: QueryOptions,
}

impl DisasmArgs {
    pub fn resolved_target(&self) -> &str {
        self.target
            .as_deref()
            .or(self.positional_target.as_deref())
            .expect("clap should ensure target is provided")
    }
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct DisasmAtArgs {
    /// Explicit 0x-prefixed address or exact symbol name to disassemble at
    pub address: String,
    /// Number of instructions to report back once disassembled
    #[arg(long = "count", short = 'n')]
    pub count: Option<usize>,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct ClearArgs {
    /// Explicit address range START:END, e.g. 0x401000:0x40101f.
    ///
    /// Use overlay:0x1000:0x1010 to inherit the start space, or qualify both endpoints.
    /// Fully qualify segmented endpoints, e.g. ram:0x1234:0x0:ram:0x1234:0x8.
    /// Ambiguous splits are rejected; qualify both endpoints to disambiguate.
    /// The legacy :: spelling is rejected.
    pub range: String,
    /// Re-disassemble at an explicit 0x-prefixed address or exact symbol name after clearing
    #[arg(long)]
    pub disasm_at: Option<String>,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}
