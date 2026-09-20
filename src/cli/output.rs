use crate::error::{GhidraError, Result};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum OutputFormat {
    Full,
    Compact,
    Minimal,
    Json,
    JsonCompact,
    #[value(name = "ndjson", help = "One JSON object per line")]
    #[serde(rename = "ndjson")]
    JsonStream,
    Csv,
    Tsv,
    Table,
    #[value(help = "Assembly text for instruction rows; other rows remain JSON")]
    Asm,
    #[value(help = "Decompiled C text; other rows remain JSON")]
    C,
}

impl std::str::FromStr for OutputFormat {
    type Err = GhidraError;

    fn from_str(s: &str) -> Result<Self> {
        <Self as ValueEnum>::from_str(s, true)
            .map_err(|_| GhidraError::InvalidFormat(format!("Unknown format: {}", s)))
    }
}
