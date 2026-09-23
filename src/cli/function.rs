use super::options::{ObjectOptions, QueryOptions};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum FunctionCommands {
    /// List all functions
    List(FunctionListArgs),
    /// Get function details
    Get(FunctionGetArgs),
    /// List calling conventions supported by the program's compiler specification
    ListCallingConventions(QueryOptions),
    /// List existing instructions in the function body, including disjoint ranges.
    /// An address inside a function selects its whole body; --limit 0 returns all instructions.
    #[command(name = "disassemble")]
    Disasm(FunctionDisasmArgs),
    /// Rename function
    Rename(FunctionRenameArgs),
    /// Create function
    Create(CreateFunctionArgs),
    /// Delete function
    Delete(FunctionDeleteArgs),
    /// Set function signature from C-style string
    SetSignature(SetSignatureArgs),
    /// Set function return type while preserving inferred parameters
    SetReturnType(SetReturnTypeArgs),
    /// Set function calling convention
    SetCallingConvention(SetCallingConventionArgs),
    /// Set or clear the function's stack pointer change after return
    SetStackPurge(SetStackPurgeArgs),
    /// Replace the whole function body with inclusive address ranges
    SetBody(SetBodyArgs),
    /// Set or replace the function's direct thunk target
    SetThunk(SetThunkArgs),
    /// Clear the thunk relationship and use the function's own saved signature
    ClearThunk(ClearThunkArgs),
    /// Read and edit a prototype override at one call site
    #[command(subcommand)]
    CallSignature(CallSignatureCommands),
    /// Inspect and edit decompiler variables
    #[command(subcommand)]
    Var(FunctionVarCommands),
    /// Mark a function as never returning to its call site (fixes bogus
    /// decompiled fallthrough tails at every call site in one shot)
    #[command(name = "set-noreturn")]
    SetNoReturn(SetNoReturnArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct FunctionRenameArgs {
    /// Exact function name or explicit 0x-prefixed address
    pub old_name: String,
    pub new_name: String,
    /// Explicit 0x-prefixed function entry address to disambiguate the old name
    #[arg(long)]
    pub address: Option<String>,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct SetNoReturnArgs {
    /// Exact function name or explicit 0x-prefixed address
    #[arg(value_name = "TARGET")]
    pub target: String,
    /// Set to false to clear a previously-set no-return flag
    #[arg(long, required = true, action = clap::ArgAction::Set)]
    pub value: bool,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct FunctionListArgs {
    /// Only functions carrying this tag (repeatable; multiple tags = AND)
    #[arg(long = "tag", value_name = "NAME")]
    pub tags: Vec<String>,
    /// Only functions with no tags
    #[arg(long, conflicts_with = "tags")]
    pub untagged: bool,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct FunctionGetArgs {
    /// Exact function name or explicit 0x-prefixed address
    #[arg(value_name = "TARGET")]
    pub target: String,
    /// Include Program-defined parameter/return types and storage without decompiling
    #[arg(long)]
    pub with_signature: bool,
    /// Include the saved stack frame and stack variables without decompiling
    #[arg(long)]
    pub with_frame: bool,
    #[command(flatten)]
    pub options: ObjectOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct FunctionDisasmArgs {
    /// Exact function name or explicit 0x-prefixed address
    #[arg(value_name = "TARGET")]
    pub target: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct FunctionDeleteArgs {
    /// Exact function name or explicit 0x-prefixed address
    #[arg(value_name = "TARGET")]
    pub target: String,
    /// Target program
    #[arg(long)]
    pub program: Option<String>,
    /// Project name
    #[arg(long)]
    pub project: Option<String>,
    /// Fields to include in the deletion receipt (comma-separated)
    #[arg(long, conflicts_with = "exclude_fields")]
    pub fields: Option<String>,
    /// Fields to exclude from the deletion receipt (comma-separated)
    #[arg(long)]
    pub exclude_fields: Option<String>,
    /// Output format (omitted: compact on TTY, json-compact otherwise)
    #[arg(long, value_enum, ignore_case = true)]
    pub format: Option<super::OutputFormat>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct CreateFunctionArgs {
    /// Explicit 0x-prefixed address or exact symbol name for the new entry point
    pub address: String,
    pub name: Option<String>,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct SetSignatureArgs {
    /// Exact function name or explicit 0x-prefixed address
    #[arg(value_name = "TARGET")]
    pub target: String,
    /// C-style signature string, e.g. "int main(int argc, char** argv)"
    #[arg(long)]
    pub signature: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct SetReturnTypeArgs {
    /// Exact function name or explicit 0x-prefixed address
    #[arg(value_name = "TARGET")]
    pub target: String,
    /// Return type name
    #[arg(long = "type")]
    pub return_type: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct SetCallingConventionArgs {
    /// Exact function name or explicit 0x-prefixed address
    #[arg(value_name = "TARGET")]
    pub target: String,
    /// Supported name from `function list-calling-conventions`
    #[arg(long)]
    pub convention: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
#[command(group(clap::ArgGroup::new("stack_purge").required(true).args(["bytes", "unknown"])))]
pub struct SetStackPurgeArgs {
    /// Exact function name or explicit 0x-prefixed address
    #[arg(value_name = "TARGET")]
    pub target: String,
    /// Signed stack pointer change in bytes, excluding the normal return-address pop
    #[arg(long, allow_hyphen_values = true, value_parser = |value: &str| super::numeric::ranged::<i32>(value, i32::MIN as i128, 0xffffff))]
    pub bytes: Option<i32>,
    /// Clear the explicit stack purge value without changing the calling convention
    #[arg(long)]
    pub unknown: bool,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct SetBodyArgs {
    /// Exact function name or explicit 0x-prefixed address
    #[arg(value_name = "TARGET")]
    pub target: String,
    /// Inclusive range; repeat to replace the body with a disjoint union.
    /// Shrinking may delete labels and stack/register references outside the new body.
    #[arg(long = "range", required = true, num_args = 2, value_names = ["START", "END"], action = clap::ArgAction::Append)]
    pub ranges: Vec<String>,
    #[command(flatten)]
    pub options: ObjectOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct SetThunkArgs {
    /// Function to change: exact name or explicit 0x-prefixed address
    #[arg(value_name = "FUNCTION")]
    pub target: String,
    /// Direct thunk target: exact function name or explicit 0x-prefixed address
    #[arg(long = "target", value_name = "FUNCTION")]
    pub thunk_target: String,
    #[command(flatten)]
    pub options: ObjectOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct ClearThunkArgs {
    /// Function to change: exact name or explicit 0x-prefixed address
    #[arg(value_name = "FUNCTION")]
    pub target: String,
    #[command(flatten)]
    pub options: ObjectOptions,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum CallSignatureCommands {
    /// Read a saved prototype override, including one outside the current body
    Get(CallSignatureGetArgs),
    /// Set a prototype at one current call instruction; leaves the callee unchanged
    Set(CallSignatureSetArgs),
    /// Remove a saved prototype override, even if the call no longer exists
    Clear(CallSignatureGetArgs),
}

impl CallSignatureCommands {
    pub fn options(&self) -> &ObjectOptions {
        match self {
            Self::Get(args) | Self::Clear(args) => &args.options,
            Self::Set(args) => &args.options,
        }
    }

    pub fn at(&self) -> &str {
        match self {
            Self::Get(args) | Self::Clear(args) => &args.at,
            Self::Set(args) => &args.at,
        }
    }
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct CallSignatureGetArgs {
    /// Exact caller function name or explicit 0x-prefixed address
    #[arg(value_name = "TARGET")]
    pub target: String,
    /// Explicit 0x-prefixed call-site address
    #[arg(long, value_name = "ADDRESS")]
    pub at: String,
    #[command(flatten)]
    pub options: ObjectOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct CallSignatureSetArgs {
    /// Exact caller function name or explicit 0x-prefixed address
    #[arg(value_name = "TARGET")]
    pub target: String,
    /// Explicit 0x-prefixed address of the call instruction
    #[arg(long, value_name = "ADDRESS")]
    pub at: String,
    /// C-style prototype; its function name does not rename a symbol
    #[arg(long, value_parser = clap::builder::NonEmptyStringValueParser::new())]
    pub signature: String,
    /// Supported calling convention; omitted uses the Program default
    #[arg(long, value_name = "NAME", value_parser = clap::builder::NonEmptyStringValueParser::new())]
    pub convention: Option<String>,
    #[command(flatten)]
    pub options: ObjectOptions,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum FunctionVarCommands {
    /// List decompiler parameters and locals, including unsaved inferred variables
    List(FunctionVarListArgs),
    /// Read one decompiler variable and its corresponding saved definition
    Get(FunctionVarGetArgs),
    /// Rename and/or retype one variable; returns saved definitions before and after
    Set(FunctionVarSetArgs),
    /// Infer a structure with Ghidra from one variable, without registering or applying it
    InferStruct(FunctionVarInferStructArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct FunctionVarListArgs {
    /// Exact function name or explicit 0x-prefixed address
    #[arg(value_name = "TARGET")]
    pub target: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct FunctionVarSelection {
    /// Exact function name or explicit 0x-prefixed address
    #[arg(value_name = "TARGET")]
    pub target: String,
    /// Current variable name (exact match, from function var list)
    #[arg(long = "var", value_name = "NAME", value_parser = clap::builder::NonEmptyStringValueParser::new())]
    pub var_name: String,
    /// Narrow same-name candidates using their list fields; must select exactly one
    #[arg(long = "where", value_name = "EXPR")]
    pub where_expr: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct FunctionVarGetArgs {
    #[command(flatten)]
    pub selection: FunctionVarSelection,
    #[command(flatten)]
    pub options: ObjectOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct FunctionVarInferStructArgs {
    #[command(flatten)]
    pub selection: FunctionVarSelection,
    /// Include LOAD/STORE evidence recorded by Ghidra's structure recovery
    #[arg(long)]
    pub with_accesses: bool,
    /// Maximum returned access records (default: 1000); does not limit inference
    #[arg(long, value_name = "N", requires = "with_accesses", value_parser = |value: &str| super::numeric::ranged::<u32>(value, 1, i32::MAX as i128))]
    pub max_accesses: Option<u32>,
    #[command(flatten)]
    pub options: ObjectOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
#[command(group(clap::ArgGroup::new("edit").required(true).multiple(true).args(["new_name", "type_name"])))]
pub struct FunctionVarSetArgs {
    #[command(flatten)]
    pub selection: FunctionVarSelection,
    /// New variable name; omit to retain the name
    #[arg(long = "name", value_parser = clap::builder::NonEmptyStringValueParser::new())]
    pub new_name: Option<String>,
    /// New type name (e.g., "int", "char *", "MyStruct")
    #[arg(long = "type", value_parser = clap::builder::NonEmptyStringValueParser::new())]
    pub type_name: Option<String>,
    #[command(flatten)]
    pub options: ObjectOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct DecompileArgs {
    /// Exact function name or explicit 0x-prefixed address
    #[arg(value_name = "TARGET")]
    pub target: String,
    /// Include local variable details (name, type, storage)
    #[arg(long)]
    pub with_vars: bool,
    /// Include parameter details (name, type, storage)
    #[arg(long)]
    pub with_params: bool,
    /// Include recovered switch jump tables
    #[arg(long)]
    pub with_jump_tables: bool,
    /// Include related instruction addresses for each decompiled C line
    #[arg(long)]
    pub with_addresses: bool,
    #[command(flatten)]
    pub options: ObjectOptions,
}
