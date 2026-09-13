use super::options::QueryOptions;
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum MemoryCommands {
    /// Show memory map
    Map(QueryOptions),
    /// Read memory
    Read(MemReadArgs),
    /// Write memory
    Write(MemWriteArgs),
    /// Search memory
    Search(MemSearchArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct MemReadArgs {
    /// Start address in hex (e.g. 0x401000), or a symbol name (e.g. main)
    pub address: String,
    /// Number of bytes to read in decimal (e.g. 64)
    pub size: usize,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct MemWriteArgs {
    pub address: String,
    pub bytes: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct MemSearchArgs {
    pub pattern: String,
    #[command(flatten)]
    pub options: QueryOptions,
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
    /// Address (hex, e.g. "0x401000")
    pub address: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct PcodeFunctionArgs {
    /// Function name or address
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
    /// Disassembly target (name | 0xaddr | FUN_<hex>)
    #[arg(value_name = "TARGET", required_unless_present = "target")]
    pub positional_target: Option<String>,
    /// Disassembly target (name | 0xaddr | FUN_<hex>)
    #[arg(long = "target", value_name = "TARGET")]
    pub target: Option<String>,
    /// Number of instructions to disassemble
    #[arg(long = "instructions", short = 'n')]
    pub num_instructions: Option<usize>,
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
    /// Address to disassemble at
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
    /// Address range to clear, as START:END (e.g. 0bf3:0bfa)
    pub range: String,
    /// Clear only, leaving the range as undefined data (no redisassembly)
    #[arg(long, conflicts_with = "disasm_at")]
    pub to_data: bool,
    /// Re-disassemble at this address immediately after clearing
    #[arg(long)]
    pub disasm_at: Option<String>,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum PatchCommands {
    /// Patch bytes
    Bytes(PatchBytesArgs),
    /// NOP instructions
    Nop(PatchNopArgs),
    /// Export patched binary
    Export(PatchExportArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct PatchBytesArgs {
    pub address: String,
    pub hex: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct PatchNopArgs {
    pub address: String,
    #[arg(long)]
    pub count: Option<usize>,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct PatchExportArgs {
    #[arg(short, long)]
    pub output: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}
