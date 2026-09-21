use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum ListingCommands {
    /// Define instructions by following code flow from a name or address.
    /// Returns a change receipt; use disassemble to read the instructions.
    DefineCode(DefineCodeArgs),
    /// Undefine instructions and data overlapping an inclusive address range,
    /// optionally re-disassembling at a precise address
    Undefine(UndefineArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct DefineCodeArgs {
    /// Exact symbol name or explicit 0x-prefixed start address
    #[arg(value_name = "TARGET")]
    pub target: String,
    /// Inclusive end of the permitted instruction-definition range.
    /// Without this bound, follow code flow without an explicit range restriction.
    #[arg(long)]
    pub end: Option<String>,
    /// Target program
    #[arg(long)]
    pub program: Option<String>,
    /// Project name
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct UndefineArgs {
    /// Explicit 0x-prefixed start address; qualify overlay and segmented addresses
    /// with their space name (e.g. overlay:0x1000 or ram:0x1234:0x0)
    pub start: String,
    /// Inclusive end address in the same space; qualify it independently of START
    #[arg(long)]
    pub end: String,
    /// Re-disassemble at an explicit 0x-prefixed address or exact symbol name after clearing.
    /// Failure or cancellation rolls back both clearing and redisassembly.
    #[arg(long = "disassemble-at")]
    pub disasm_at: Option<String>,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}
