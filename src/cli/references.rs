use super::{ObjectOptions, QueryOptions};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum EquateCommands {
    /// List named integer definitions
    List(QueryOptions),
    /// Inspect one definition and its applications
    Get(EquateNameArgs),
    /// Create a named integer definition without applying it
    Create(EquateCreateArgs),
    /// Apply an existing definition to one instruction operand
    Attach(EquateOperandArgs),
    /// Remove one operand's application, preserving the definition
    Detach(EquateOperandArgs),
    /// Delete a definition and all its applications
    Delete(EquateNameArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct EquateNameArgs {
    /// Exact, case-sensitive definition name
    pub name: String,
    #[command(flatten)]
    pub options: ObjectOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct EquateCreateArgs {
    /// Exact, case-sensitive definition name
    pub name: String,
    /// Signed 64-bit decimal integer or 0x-prefixed 64-bit bit pattern
    #[arg(allow_hyphen_values = true, value_parser = parse_equate_value)]
    pub value: String,
    #[command(flatten)]
    pub options: ObjectOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct EquateOperandArgs {
    /// Explicit address of the instruction start
    pub address: String,
    /// Exact name of an existing definition
    pub name: String,
    /// Zero-based instruction operand index
    #[arg(long = "operand", value_name = "N", value_parser = clap::value_parser!(i32).range(0..))]
    pub operand_index: i32,
    #[command(flatten)]
    pub options: ObjectOptions,
}

fn parse_equate_value(value: &str) -> Result<String, String> {
    let valid = if let Some(digits) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        !digits.is_empty()
            && digits.bytes().all(|digit| digit.is_ascii_hexdigit())
            && u64::from_str_radix(digits, 16).is_ok()
    } else {
        let digits = value
            .strip_prefix('-')
            .or_else(|| value.strip_prefix('+'))
            .unwrap_or(value);
        !digits.is_empty()
            && digits.bytes().all(|digit| digit.is_ascii_digit())
            && value.parse::<i64>().is_ok()
    };
    if valid {
        Ok(value.to_owned())
    } else {
        Err("Expected a signed 64-bit decimal integer or a 0x-prefixed 64-bit bit pattern".into())
    }
}
