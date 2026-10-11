//! Explicit function ABI locations, shared by partial and complete signature edits.
use super::{numeric, ObjectOptions};
use clap::Args;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct SetStorageArgs {
    /// Exact function name or explicit 0x-prefixed entry address
    pub target: String,
    #[command(flatten)]
    pub storage: FunctionStorageOptions,
    #[command(flatten)]
    pub options: ObjectOptions,
}

#[derive(Args, Clone, Default, Serialize, Deserialize, Debug)]
pub struct FunctionStorageOptions {
    /// Place a named parameter in a register; repeat for different parameters
    #[arg(long, num_args = 2, value_names = ["NAME", "REGISTER"], action = clap::ArgAction::Append)]
    pub param_register: Vec<String>,
    /// Place a parameter at a signed byte offset from the function-entry SP
    #[arg(long, num_args = 2, value_names = ["NAME", "STACK_OFFSET"], action = clap::ArgAction::Append, allow_hyphen_values = true)]
    pub param_stack: Vec<String>,
    /// Place the return value in a register's low bytes, using the type width
    #[arg(long, value_name = "REGISTER")]
    pub return_register: Option<String>,
    /// Place the return value at a signed byte offset from the function-entry SP
    #[arg(long, value_name = "STACK_OFFSET", value_parser = numeric::parse::<i32>, allow_hyphen_values = true)]
    pub return_stack: Option<i32>,
    /// Replace a parameter's storage with pieces; VALUE_OFFSET is a byte offset in its memory representation
    #[arg(long, num_args = 4, value_names = ["NAME", "VALUE_OFFSET", "REGISTER", "SIZE"], action = clap::ArgAction::Append)]
    pub param_register_piece: Vec<String>,
    /// Stack piece of a parameter; repeat pieces to cover its complete type
    #[arg(long, num_args = 4, value_names = ["NAME", "VALUE_OFFSET", "STACK_OFFSET", "SIZE"], action = clap::ArgAction::Append, allow_hyphen_values = true)]
    pub param_stack_piece: Vec<String>,
    /// Register piece of the return value; VALUE_OFFSET is a byte offset in its memory representation
    #[arg(long, num_args = 3, value_names = ["VALUE_OFFSET", "REGISTER", "SIZE"], action = clap::ArgAction::Append)]
    pub return_register_piece: Vec<String>,
    /// Stack piece of the return value; repeat pieces to cover its complete type
    #[arg(long, num_args = 3, value_names = ["VALUE_OFFSET", "STACK_OFFSET", "SIZE"], action = clap::ArgAction::Append, allow_hyphen_values = true)]
    pub return_stack_piece: Vec<String>,
}

#[derive(Serialize)]
pub struct StorageEdits {
    pub parameters: Vec<ParameterStorage>,
    #[serde(rename = "return", skip_serializing_if = "Option::is_none")]
    pub return_storage: Option<Vec<StoragePiece>>,
}

#[derive(Serialize)]
pub struct ParameterStorage {
    pub name: String,
    pub pieces: Vec<StoragePiece>,
}

#[derive(Serialize)]
pub struct StoragePiece {
    #[serde(flatten)]
    pub location: StorageLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_offset: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u32>,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StorageLocation {
    Register { register: String },
    Stack { stack_offset: i32 },
}

impl FunctionStorageOptions {
    pub fn edits(&self) -> Result<Option<StorageEdits>, String> {
        let mut parameters: BTreeMap<String, Vec<StoragePiece>> = BTreeMap::new();
        let mut returns = Vec::new();
        for (values, register, pieces) in [
            (&self.param_register, true, false),
            (&self.param_stack, false, false),
            (&self.param_register_piece, true, true),
            (&self.param_stack_piece, false, true),
        ] {
            for group in groups(values, if pieces { 4 } else { 2 })? {
                if group[0].trim().is_empty() {
                    return Err("Parameter name must not be empty".into());
                }
                parameters.entry(group[0].clone()).or_default().push(piece(
                    &group[1..],
                    register,
                    pieces,
                )?);
            }
        }
        if let Some(register) = &self.return_register {
            returns.push(piece(std::slice::from_ref(register), true, false)?);
        }
        if let Some(stack_offset) = self.return_stack {
            returns.push(StoragePiece {
                location: StorageLocation::Stack { stack_offset },
                value_offset: None,
                size: None,
            });
        }
        for (values, register) in [
            (&self.return_register_piece, true),
            (&self.return_stack_piece, false),
        ] {
            for group in groups(values, 3)? {
                returns.push(piece(group, register, true)?);
            }
        }
        if parameters.is_empty() && returns.is_empty() {
            return Ok(None);
        }
        for (name, pieces) in &mut parameters {
            validate_pieces(name, pieces)?;
        }
        validate_pieces("return", &mut returns)?;
        Ok(Some(StorageEdits {
            parameters: parameters
                .into_iter()
                .map(|(name, pieces)| ParameterStorage { name, pieces })
                .collect(),
            return_storage: (!returns.is_empty()).then_some(returns),
        }))
    }
}

fn groups(values: &[String], size: usize) -> Result<std::slice::ChunksExact<'_, String>, String> {
    let groups = values.chunks_exact(size);
    if !groups.remainder().is_empty() {
        return Err(format!("Storage option requires groups of {size} values"));
    }
    Ok(groups)
}

fn piece(values: &[String], register: bool, explicit: bool) -> Result<StoragePiece, String> {
    let (location, value_offset, size) = if explicit {
        (
            &values[1],
            Some(numeric::ranged(&values[0], 0, i32::MAX as i128)?),
            Some(numeric::ranged(&values[2], 1, i32::MAX as i128)?),
        )
    } else {
        (&values[0], None, None)
    };
    let location = if register {
        if location.trim().is_empty() {
            return Err("Register name must not be empty".into());
        }
        StorageLocation::Register {
            register: location.clone(),
        }
    } else {
        StorageLocation::Stack {
            stack_offset: numeric::parse(location)?,
        }
    };
    Ok(StoragePiece {
        location,
        value_offset,
        size,
    })
}

fn validate_pieces(name: &str, pieces: &mut [StoragePiece]) -> Result<(), String> {
    if pieces.len() > 1 && pieces.iter().any(|p| p.value_offset.is_none()) {
        return Err(format!(
            "Storage for {name}: use one simple location or a complete set of pieces"
        ));
    }
    pieces.sort_by_key(|p| p.value_offset);
    let mut end = 0_u64;
    for piece in pieces {
        if let (Some(offset), Some(size)) = (piece.value_offset, piece.size) {
            if u64::from(offset) != end {
                return Err(format!("Storage pieces for {name} must cover consecutive bytes starting at 0 without gaps or overlaps"));
            }
            end += u64::from(size);
            if end > i32::MAX as u64 {
                return Err(format!("Storage for {name} is too large"));
            }
        }
    }
    Ok(())
}
