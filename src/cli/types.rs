use super::options::QueryOptions;
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum TypeCommands {
    /// List data types
    List(QueryOptions),
    /// Get type definition
    Get(TypeGetArgs),
    /// Create a struct, union, enum, or typedef
    #[command(subcommand)]
    Create(TypeCreateCommands),
    /// Apply type to address
    Apply(ApplyTypeArgs),
    /// Import C type definitions
    ImportC(ImportCArgs),
    /// Delete a data type
    Delete(TypeDeleteArgs),
    /// Rename a data type
    Rename(TypeRenameArgs),
    /// Append a field to a struct or union type
    AddField(TypeAddFieldArgs),
    /// Edit a struct field by offset or a union member by ordinal
    SetField(TypeSetFieldArgs),
    /// Clear a field to undefined bytes, preserving structure size and offsets
    ClearField(TypeClearFieldArgs),
    /// Remove a field from a struct or union type
    DelField(TypeDelFieldArgs),
    /// Remove one enum member by exact name
    DelEnumMember(TypeDelEnumMemberArgs),
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum TypeCreateCommands {
    /// Create an empty struct; add fields with `type set-field` or `type add-field`
    Struct(CreateStructArgs),
    /// Create an empty union; add members with `type add-field`
    Union(CreateUnionArgs),
    /// Create an enum type
    Enum(CreateEnumArgs),
    /// Create a typedef (type alias)
    Typedef(TypedefArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct TypeGetArgs {
    pub name: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct CreateStructArgs {
    /// Bare identifier for the new (empty) struct type -- NOT a C-style
    /// struct definition. Build fields afterward with `type set-field` or
    /// `type add-field`; use `type import-c` to parse C declarations.
    #[arg(value_name = "NAME")]
    pub name: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct CreateUnionArgs {
    /// Bare identifier for the new empty union
    pub name: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct ApplyTypeArgs {
    /// Explicit address, e.g. 0x404000 or overlay:0x1000
    pub address: String,
    pub type_name: String,
    /// Clear conflicting code/data units (including instructions) before applying the type
    #[arg(long)]
    pub force: bool,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
#[command(group(clap::ArgGroup::new("source").required(true).args(["code", "file", "stdin"])))]
pub struct ImportCArgs {
    /// C code containing type definitions
    pub code: Option<String>,
    /// Read C definitions from a UTF-8 file (relative to the CLI working directory)
    #[arg(long, value_name = "PATH")]
    pub file: Option<std::path::PathBuf>,
    /// Read C definitions from standard input
    #[arg(long)]
    pub stdin: bool,
    /// Category path to store imported types in
    #[arg(long)]
    pub category: Option<String>,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct TypeDeleteArgs {
    /// Name or path of the type to delete
    pub name: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct TypeRenameArgs {
    /// Current name of the type
    pub old_name: String,
    /// New name for the type
    pub new_name: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct CreateEnumArgs {
    /// Enum type name
    pub name: String,
    /// Comma-separated KEY=VALUE pairs, e.g. "RED=0,GREEN=1,BLUE=2"
    #[arg(long)]
    pub values: String,
    /// Size in bytes (1, 2, 4, or 8)
    #[arg(long, default_value = "4")]
    pub size: i32,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct TypedefArgs {
    /// Name for the new typedef
    pub name: String,
    /// Base type to alias (e.g., "int", "dword", "MyStruct")
    pub base_type: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct TypeAddFieldArgs {
    /// Struct or union name or full type path
    pub type_name: String,
    /// Field name
    #[arg(long)]
    pub name: String,
    /// Field type (e.g., "int", "byte", "pointer", a custom struct name)
    #[arg(long = "type")]
    pub field_type: String,
    /// Field size override
    #[arg(long)]
    pub size: Option<i32>,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
#[command(group(clap::ArgGroup::new("field_selector").required(true).args(["name", "ordinal"])))]
pub struct TypeDelFieldArgs {
    /// Struct or union name or full type path
    pub type_name: String,
    /// Exact field name to remove
    #[arg(long)]
    pub name: Option<String>,
    /// Union member's zero-based ordinal from `type get`
    #[arg(long, value_parser = clap::value_parser!(i32).range(0..))]
    pub ordinal: Option<i32>,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct TypeDelEnumMemberArgs {
    /// Enum name or full type path
    pub type_name: String,
    /// Exact member name to remove
    #[arg(long)]
    pub name: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

fn parse_field_offset(value: &str) -> Result<i32, String> {
    let (digits, radix) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .map(|digits| (digits, 16))
        .unwrap_or((value, 10));
    if digits.is_empty()
        || !digits
            .chars()
            .all(|c| c.is_ascii_hexdigit() && c.is_digit(radix))
    {
        return Err("offset must be a nonnegative decimal or 0x hexadecimal integer".into());
    }
    i32::from_str_radix(digits, radix).map_err(|_| "offset exceeds 2147483647".into())
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
#[command(group(clap::ArgGroup::new("field_edit").required(true).multiple(true).args(["name", "field_type", "comment"])))]
#[command(group(clap::ArgGroup::new("field_selector").required(true).args(["offset", "ordinal"])))]
pub struct TypeSetFieldArgs {
    /// Struct or union name or full type path
    pub type_name: String,
    /// Struct field's starting byte offset, in decimal or 0x hexadecimal
    #[arg(long, value_parser = parse_field_offset)]
    pub offset: Option<i32>,
    /// Existing union member's zero-based ordinal from `type get`
    #[arg(long, value_parser = clap::value_parser!(i32).range(0..))]
    pub ordinal: Option<i32>,
    /// New field name; omit to preserve an existing name
    #[arg(long, value_parser = clap::builder::NonEmptyStringValueParser::new())]
    pub name: Option<String>,
    /// Field type; required when creating a field in undefined space
    #[arg(long = "type", value_parser = clap::builder::NonEmptyStringValueParser::new())]
    pub field_type: Option<String>,
    /// Field size override; requires --type
    #[arg(long, requires = "field_type")]
    pub size: Option<i32>,
    /// Field comment; an empty string clears it, omission preserves it
    #[arg(long)]
    pub comment: Option<String>,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct TypeClearFieldArgs {
    /// Structure name or full type path
    pub type_name: String,
    /// Field starting byte offset, in decimal or 0x hexadecimal
    #[arg(long, value_parser = parse_field_offset)]
    pub offset: i32,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}
