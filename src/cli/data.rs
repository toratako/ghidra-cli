use super::{ObjectOptions, QueryOptions};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum DataCommands {
    /// List defined data objects
    List(QueryOptions),
    /// Read values using the data types already applied in the program
    Read(DataReadArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct DataReadArgs {
    /// Exact symbol name or explicit 0x-prefixed address; interior addresses select a component
    #[arg(value_name = "TARGET")]
    pub target: String,
    /// Maximum component nesting depth (0 = the selected object only)
    #[arg(long, default_value = "2", value_parser = |value: &str| super::numeric::ranged::<u32>(value, 0, 64))]
    pub max_depth: u32,
    /// Maximum total expanded components, excluding the selected object (0 = none)
    #[arg(long, default_value = "100", value_parser = |value: &str| super::numeric::ranged::<u32>(value, 0, 100_000))]
    pub max_elements: u32,
    #[command(flatten)]
    pub options: ObjectOptions,
}
