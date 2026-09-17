use super::options::QueryOptions;
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum FunctionCommands {
    /// List all functions
    #[command(alias = "ls")]
    List(FunctionListArgs),
    /// Get function details
    #[command(alias = "show", alias = "detail")]
    Get(FunctionGetArgs),
    /// List existing instructions in the function body, including disjoint ranges.
    /// An address inside a function selects its whole body; --limit 0 returns all instructions.
    #[command(alias = "disassemble", alias = "dis")]
    Disasm(FunctionGetArgs),
    /// List outgoing call sites and callees inside this function
    Calls(FunctionGetArgs),
    /// Rename function
    Rename(FunctionRenameArgs),
    /// Create function
    Create(CreateFunctionArgs),
    /// Delete function
    Delete(FunctionGetArgs),
    /// Set function signature from C-style string
    SetSignature(SetSignatureArgs),
    /// Set function return type
    SetReturnType(SetReturnTypeArgs),
    /// Set function calling convention
    SetCallingConvention(SetCallingConventionArgs),
    /// Rename and/or retype a local variable or parameter
    EditVar(EditVarArgs),
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
    #[arg(value_name = "TARGET", required_unless_present = "target")]
    pub positional_target: Option<String>,
    /// Exact function name or explicit 0x-prefixed address
    #[arg(long = "target", value_name = "TARGET")]
    pub target: Option<String>,
    /// Set to false to clear a previously-set no-return flag
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub value: bool,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

impl SetNoReturnArgs {
    pub fn resolved_target(&self) -> &str {
        self.target
            .as_deref()
            .or(self.positional_target.as_deref())
            .expect("clap should ensure target is provided")
    }
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
    #[arg(value_name = "TARGET", required_unless_present = "target")]
    pub positional_target: Option<String>,
    /// Exact function name or explicit 0x-prefixed address
    #[arg(long = "target", value_name = "TARGET")]
    pub target: Option<String>,
    #[command(flatten)]
    pub options: QueryOptions,
}

impl FunctionGetArgs {
    pub fn resolved_target(&self) -> &str {
        self.target
            .as_deref()
            .or(self.positional_target.as_deref())
            .expect("clap should ensure target is provided")
    }
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
    #[arg(value_name = "TARGET", required_unless_present = "target")]
    pub positional_target: Option<String>,
    /// Exact function name or explicit 0x-prefixed address
    #[arg(long = "target", value_name = "TARGET")]
    pub target: Option<String>,
    /// C-style signature string, e.g. "int main(int argc, char** argv)"
    #[arg(long)]
    pub signature: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

impl SetSignatureArgs {
    pub fn resolved_target(&self) -> &str {
        self.target
            .as_deref()
            .or(self.positional_target.as_deref())
            .expect("clap should ensure target is provided")
    }
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct SetReturnTypeArgs {
    /// Exact function name or explicit 0x-prefixed address
    #[arg(value_name = "TARGET", required_unless_present = "target")]
    pub positional_target: Option<String>,
    /// Exact function name or explicit 0x-prefixed address
    #[arg(long = "target", value_name = "TARGET")]
    pub target: Option<String>,
    /// Return type name
    #[arg(long = "type")]
    pub return_type: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

impl SetReturnTypeArgs {
    pub fn resolved_target(&self) -> &str {
        self.target
            .as_deref()
            .or(self.positional_target.as_deref())
            .expect("clap should ensure target is provided")
    }
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct SetCallingConventionArgs {
    /// Exact function name or explicit 0x-prefixed address
    #[arg(value_name = "TARGET", required_unless_present = "target")]
    pub positional_target: Option<String>,
    /// Exact function name or explicit 0x-prefixed address
    #[arg(long = "target", value_name = "TARGET")]
    pub target: Option<String>,
    /// Calling convention name (e.g., "__cdecl", "__stdcall", "__fastcall")
    #[arg(long)]
    pub convention: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

impl SetCallingConventionArgs {
    pub fn resolved_target(&self) -> &str {
        self.target
            .as_deref()
            .or(self.positional_target.as_deref())
            .expect("clap should ensure target is provided")
    }
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
#[command(group(clap::ArgGroup::new("edit").required(true).multiple(true).args(["new_name", "type_name"])))]
pub struct EditVarArgs {
    /// Exact function name or explicit 0x-prefixed address
    #[arg(value_name = "TARGET", required_unless_present = "target")]
    pub positional_target: Option<String>,
    /// Exact function name or explicit 0x-prefixed address
    #[arg(long = "target", value_name = "TARGET")]
    pub target: Option<String>,
    /// Current variable name (exact match, from decompile --with-vars/--with-params)
    #[arg(long = "var", value_parser = clap::builder::NonEmptyStringValueParser::new())]
    pub var_name: String,
    /// New variable name; omit to retain the name
    #[arg(long = "name", value_parser = clap::builder::NonEmptyStringValueParser::new())]
    pub new_name: Option<String>,
    /// New type name (e.g., "int", "char *", "MyStruct")
    #[arg(long = "type", value_parser = clap::builder::NonEmptyStringValueParser::new())]
    pub type_name: Option<String>,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

impl EditVarArgs {
    pub fn resolved_target(&self) -> &str {
        self.target
            .as_deref()
            .or(self.positional_target.as_deref())
            .expect("clap should ensure target is provided")
    }
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct DecompileArgs {
    /// Exact function name or explicit 0x-prefixed address
    #[arg(value_name = "TARGET", required_unless_present = "target")]
    pub positional_target: Option<String>,
    /// Exact function name or explicit 0x-prefixed address
    #[arg(long = "target", value_name = "TARGET")]
    pub target: Option<String>,
    /// Include local variable details (name, type, storage)
    #[arg(long)]
    pub with_vars: bool,
    /// Include parameter details (name, type, storage)
    #[arg(long)]
    pub with_params: bool,
    #[command(flatten)]
    pub options: QueryOptions,
}

impl DecompileArgs {
    pub fn resolved_target(&self) -> &str {
        self.target
            .as_deref()
            .or(self.positional_target.as_deref())
            .expect("clap should ensure target is provided")
    }
}
