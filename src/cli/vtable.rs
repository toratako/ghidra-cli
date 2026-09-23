use super::{numeric, ObjectOptions};
use clap::{Args, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum VtableCommands {
    /// Read explicit virtual-function slots and ABI metadata without changing the program
    Read(VtableReadArgs),
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
