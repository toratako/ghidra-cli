use super::options::{ObjectOptions, QueryOptions};
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
    /// Clone a named type definition, sharing its referenced types
    Clone(TypeCloneArgs),
    /// Resize only the undefined tail of a nonpacked struct
    Resize(TypeResizeArgs),
    /// Move a named type to an existing category
    Move(TypeMoveArgs),
    /// Organize data type categories
    #[command(subcommand)]
    Category(TypeCategoryCommands),
    /// Edit struct and union fields
    #[command(subcommand)]
    Field(TypeFieldCommands),
    /// Edit enum definitions
    #[command(subcommand)]
    Enum(TypeEnumCommands),
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum TypeFieldCommands {
    /// Append a field using the type's packing and alignment
    Append(TypeFieldAppendArgs),
    /// Place a bitfield in a nonpacked struct without shifting other fields
    CreateBitfield(TypeFieldCreateBitfieldArgs),
    /// Update a field, or create one at a struct offset in undefined space
    Set(TypeFieldSetArgs),
    /// Replace a struct field with undefined bytes, preserving size and later offsets
    Clear(TypeFieldClearArgs),
    /// Delete a field; ordinary struct fields shift later bytes, nonpacked bitfields preserve offsets
    Delete(TypeFieldDeleteArgs),
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum TypeCategoryCommands {
    /// List immediate child categories and their direct type counts
    List(TypeCategoryListArgs),
    /// Create a category and any missing parents
    Create(TypeCategoryArgs),
    /// Delete an empty category
    Delete(TypeCategoryArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct TypeCategoryListArgs {
    /// Category path whose immediate children to list, e.g. /
    pub path: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct TypeCategoryArgs {
    /// Category path, e.g. /Protocol/Draft
    pub path: String,
    #[command(flatten)]
    pub options: ObjectOptions,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum TypeEnumCommands {
    /// Edit named enum members
    #[command(subcommand)]
    Member(TypeEnumMemberCommands),
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum TypeEnumMemberCommands {
    /// Remove one enum member by exact name
    Delete(TypeEnumMemberDeleteArgs),
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum TypeCreateCommands {
    /// Create an empty struct; add fields with `type field set` or `type field append`
    Struct(CreateStructArgs),
    /// Create an empty union; add members with `type field append`
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
    pub options: ObjectOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct CreateStructArgs {
    /// Bare identifier for the new (empty) struct type -- NOT a C-style
    /// struct definition. Build fields afterward with `type field set` or
    /// `type field append`; use `type import-c` to parse C declarations.
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
pub struct TypeCloneArgs {
    /// Registered struct, union, enum, typedef, or function type name or path
    pub type_name: String,
    /// New name for the cloned definition
    pub new_name: String,
    /// Existing destination category; omit to keep the source category
    #[arg(long)]
    pub category: Option<String>,
    #[command(flatten)]
    pub options: ObjectOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct TypeResizeArgs {
    /// Nonpacked struct name or full type path
    pub type_name: String,
    /// New total byte size, in decimal or 0x hexadecimal; zero is allowed
    #[arg(value_parser = parse_type_integer)]
    pub size: i32,
    #[command(flatten)]
    pub options: ObjectOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct TypeMoveArgs {
    /// Registered struct, union, enum, typedef, or function type name or path
    pub type_name: String,
    /// Existing destination category path
    pub category: String,
    #[command(flatten)]
    pub options: ObjectOptions,
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
pub struct TypeFieldAppendArgs {
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
pub struct TypeFieldCreateBitfieldArgs {
    /// Nonpacked struct name or full type path
    pub type_name: String,
    /// Storage byte offset, in decimal or 0x hexadecimal
    #[arg(long, value_parser = parse_type_integer)]
    pub offset: i32,
    /// Storage byte length interpreted using the Program's byte order
    #[arg(long, value_parser = parse_positive_type_integer)]
    pub storage_size: i32,
    /// Bit offset from the storage integer's least significant bit
    #[arg(long, value_parser = parse_type_integer)]
    pub bit_offset: i32,
    /// Positive bit width; must fit the storage and base type
    #[arg(long, value_parser = parse_positive_type_integer)]
    pub bit_size: i32,
    /// Integer, enum, or typedef base type
    #[arg(long = "type", value_parser = clap::builder::NonEmptyStringValueParser::new())]
    pub field_type: String,
    /// Field name; omit for an unnamed bitfield
    #[arg(long, value_parser = clap::builder::NonEmptyStringValueParser::new())]
    pub name: Option<String>,
    /// Field comment
    #[arg(long)]
    pub comment: Option<String>,
    #[command(flatten)]
    pub options: ObjectOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct TypeFieldDeleteArgs {
    /// Struct or union name or full type path
    pub type_name: String,
    #[command(flatten)]
    pub selector: TypeFieldSelector,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct TypeEnumMemberDeleteArgs {
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

fn parse_type_integer(value: &str) -> Result<i32, String> {
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
        return Err("must be a nonnegative decimal or 0x hexadecimal integer".into());
    }
    i32::from_str_radix(digits, radix).map_err(|_| "must not exceed 2147483647".into())
}

fn parse_positive_type_integer(value: &str) -> Result<i32, String> {
    let value = parse_type_integer(value)?;
    if value == 0 {
        return Err("must be greater than zero".into());
    }
    Ok(value)
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
#[command(group(clap::ArgGroup::new("field_edit").required(true).multiple(true).args(["name", "field_type", "bit_size", "comment"])))]
pub struct TypeFieldSetArgs {
    /// Struct or union name or full type path
    pub type_name: String,
    #[command(flatten)]
    pub selector: TypeFieldSelector,
    /// New field name; omit to preserve an existing name
    #[arg(long, value_parser = clap::builder::NonEmptyStringValueParser::new())]
    pub name: Option<String>,
    /// Field type; required when creating a field in undefined space
    #[arg(long = "type", value_parser = clap::builder::NonEmptyStringValueParser::new())]
    pub field_type: Option<String>,
    /// Ordinary field byte size override; requires --type
    #[arg(long, requires = "field_type", conflicts_with = "bit_size")]
    pub size: Option<i32>,
    /// New width of an existing nonpacked struct bitfield within its current storage
    #[arg(long, value_parser = parse_positive_type_integer, conflicts_with = "offset")]
    pub bit_size: Option<i32>,
    /// Field comment; an empty string clears it, omission preserves it
    #[arg(long)]
    pub comment: Option<String>,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct TypeFieldClearArgs {
    /// Structure name or full type path
    pub type_name: String,
    #[command(flatten)]
    pub selector: TypeFieldSelector,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
#[group(id = "field_selector", required = true, multiple = false)]
pub struct TypeFieldSelector {
    /// Struct field's starting byte offset, in decimal or 0x hexadecimal
    #[arg(long, value_parser = parse_type_integer)]
    pub offset: Option<i32>,
    /// Struct or union component's zero-based ordinal from the latest `type get`
    #[arg(long, value_parser = clap::value_parser!(i32).range(0..))]
    pub ordinal: Option<i32>,
    /// Exact existing field name (not its generated display name)
    #[arg(long, value_parser = clap::builder::NonEmptyStringValueParser::new())]
    pub field: Option<String>,
}
