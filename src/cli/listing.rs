use super::options::ObjectOptions;
use clap::{Args, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum ListingCommands {
    /// Define instructions by following code flow from a name or address.
    /// Returns a change receipt; use disassemble to read the instructions.
    DefineCode(DefineCodeArgs),
    /// Undefine instructions and data overlapping an inclusive address range,
    /// optionally re-disassembling at a precise address
    Undefine(UndefineArgs),
    /// Inspect and override instruction flow without changing bytes
    #[command(subcommand)]
    Flow(ListingFlowCommands),
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

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum ListingFlowCommands {
    /// Read original and effective instruction flow and fallthrough
    Get(ListingFlowGetArgs),
    /// Set flow override and/or fallthrough; omitted attributes are preserved
    Set(ListingFlowSetArgs),
    /// Restore selected flow attributes to their defaults
    Clear(ListingFlowClearArgs),
}

impl ListingFlowCommands {
    pub fn options(&self) -> &ObjectOptions {
        match self {
            Self::Get(args) => &args.options,
            Self::Set(args) => &args.options,
            Self::Clear(args) => &args.options,
        }
    }

    pub fn address(&self) -> &str {
        match self {
            Self::Get(args) => &args.address,
            Self::Set(args) => &args.address,
            Self::Clear(args) => &args.address,
        }
    }
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct ListingFlowGetArgs {
    /// Explicit 0x-prefixed address of an instruction start
    pub address: String,
    #[command(flatten)]
    pub options: ObjectOptions,
}

#[derive(ValueEnum, Clone, Copy, Serialize, Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub enum FlowOverride {
    Branch,
    Call,
    /// Treat the instruction as a call followed by a return from the caller
    CallReturn,
    Return,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
#[command(group(clap::ArgGroup::new("flow_edit").required(true).multiple(true).args(["flow_override", "fallthrough", "no_fallthrough"])))]
pub struct ListingFlowSetArgs {
    /// Explicit 0x-prefixed address of an instruction start
    pub address: String,
    /// Replace the instruction's flow interpretation
    #[arg(long = "override", value_enum)]
    pub flow_override: Option<FlowOverride>,
    /// Explicit 0x-prefixed address of the next instruction in the same space
    #[arg(long, value_name = "ADDRESS", conflicts_with = "no_fallthrough")]
    pub fallthrough: Option<String>,
    /// Explicitly prohibit fallthrough
    #[arg(long)]
    pub no_fallthrough: bool,
    #[command(flatten)]
    pub options: ObjectOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
#[command(group(clap::ArgGroup::new("flow_clear").required(true).multiple(true).args(["flow_override", "fallthrough"])))]
pub struct ListingFlowClearArgs {
    /// Explicit 0x-prefixed address of an instruction start
    pub address: String,
    /// Remove the flow override
    #[arg(long = "override")]
    pub flow_override: bool,
    /// Restore default fallthrough
    #[arg(long)]
    pub fallthrough: bool,
    #[command(flatten)]
    pub options: ObjectOptions,
}
