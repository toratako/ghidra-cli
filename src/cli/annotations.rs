use super::options::{ObjectOptions, QueryOptions};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct RenameArgs {
    /// Exact symbol name; bare hex and generated names are not inferred addresses
    pub old_name: String,
    pub new_name: String,
    /// Explicit 0x-prefixed address of the symbol to rename. Required when `old_name`
    /// is shared by more than one symbol -- Ghidra reuses auto-generated
    /// names (`caseD_XX`, `LAB_XXXX`, ...) across unrelated addresses
    /// program-wide, so a bare name alone is not a safe rename target.
    /// Segmented selectors require the space name, e.g. ram:0x1234:0x0005.
    #[arg(long)]
    pub address: Option<String>,
    /// Filter expression (same syntax as `--filter` on query commands) used
    /// to narrow which of the name's matches get renamed, e.g.
    /// `--filter 'address=0xc200'`.
    #[arg(short, long)]
    pub filter: Option<String>,
    /// Rename every symbol named `old_name`, program-wide. Without this (or
    /// `--address`/`--filter`), an ambiguous name is a hard error rather
    /// than silently renaming every match.
    #[arg(long)]
    pub all: bool,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum SymbolCommands {
    /// List all symbols
    List(QueryOptions),
    /// Get symbol details
    Get(SymbolGetArgs),
    /// List Ghidra external symbols and their libraries
    Externals(QueryOptions),
    /// List symbols marked as external entry points in Ghidra
    EntryPoints(QueryOptions),
    /// Create a label at an address
    CreateLabel(CreateLabelArgs),
    /// Delete symbol
    Delete(SymbolDeleteArgs),
    /// Rename symbol
    Rename(RenameArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct SymbolGetArgs {
    /// Exact symbol name or explicit 0x-prefixed address
    pub name: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct SymbolDeleteArgs {
    /// Exact symbol name; bare hex and generated names are not inferred addresses
    pub name: String,
    /// Explicit 0x-prefixed address of the symbol to delete. Required when `name` is
    /// shared by more than one symbol -- Ghidra reuses auto-generated names
    /// (`caseD_XX`, `LAB_XXXX`, ...) across unrelated addresses
    /// program-wide, so a bare name alone is not a safe delete target.
    /// Segmented selectors require the space name, e.g. ram:0x1234:0x0005.
    #[arg(long)]
    pub address: Option<String>,
    /// Delete every symbol named `name`, program-wide. Without this (or
    /// `--address`/`--filter`), an ambiguous name is a hard error rather
    /// than silently deleting every match.
    #[arg(long)]
    pub all: bool,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct CreateLabelArgs {
    /// Explicit address, e.g. 0x404000 or overlay:0x1000
    pub address: String,
    pub name: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum TagCommands {
    /// List all function tags (or one function's tags with --function)
    List(TagListArgs),
    /// Get function tag details
    Get(TagGetArgs),
    /// Create a function tag
    Create(TagCreateArgs),
    /// Delete a tag (detaches it from all functions)
    Delete(TagDeleteArgs),
    /// Rename a tag everywhere it is used
    Rename(TagRenameArgs),
    /// Set or clear a tag's comment ("" clears)
    SetComment(TagSetCommentArgs),
    /// Attach tags to a function (auto-creates missing tags)
    Add(TagAttachArgs),
    /// Detach tags from a function
    Remove(TagDetachArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct TagListArgs {
    /// Only tags attached to this exact function name or explicit 0x-prefixed address
    #[arg(long = "function", value_name = "TARGET")]
    pub function: Option<String>,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct TagGetArgs {
    /// Tag name (case-sensitive)
    pub name: String,
    #[command(flatten)]
    pub options: ObjectOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct TagCreateArgs {
    /// Tag name (case-sensitive; commas and semicolons not allowed)
    pub name: String,
    /// Optional comment describing the tag's meaning
    #[arg(long)]
    pub comment: Option<String>,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct TagDeleteArgs {
    /// Tag name
    pub name: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct TagRenameArgs {
    /// Current tag name
    pub old_name: String,
    /// New tag name
    pub new_name: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct TagSetCommentArgs {
    /// Tag name
    pub name: String,
    /// New comment text; empty string clears the comment
    pub comment: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct TagAttachArgs {
    /// Exact function name or explicit 0x-prefixed address
    #[arg(value_name = "TARGET")]
    pub target: String,
    /// One or more tag names to attach
    // `required = true` is mandatory: num_args = 1.. alone does NOT make a
    // positional required — `ghidra-cli tag add crypto` would parse with the tag
    // name consumed as TARGET and an empty tag list.
    #[arg(value_name = "TAG", required = true, num_args = 1..)]
    pub tags: Vec<String>,
    /// Error instead of auto-creating tags that don't exist yet
    #[arg(long)]
    pub no_create: bool,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct TagDetachArgs {
    /// Exact function name or explicit 0x-prefixed address
    #[arg(value_name = "TARGET")]
    pub target: String,
    /// Tag names to detach
    #[arg(value_name = "TAG", num_args = 0.., required_unless_present = "all")]
    pub tags: Vec<String>,
    /// Detach every tag from the function
    #[arg(long, conflicts_with = "tags")]
    pub all: bool,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum CommentCommands {
    /// List all comments
    List(QueryOptions),
    /// Get comment at address
    Get(CommentGetArgs),
    /// Set comment
    Set(CommentSetArgs),
    /// Delete one comment type at an address, or all supported types with --all
    Delete(CommentDeleteArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct CommentGetArgs {
    /// Explicit address, e.g. 0x401000 or overlay:0x1000
    pub address: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
#[command(group(clap::ArgGroup::new("scope").required(true).args(["comment_type", "all"])))]
pub struct CommentDeleteArgs {
    /// Explicit address, e.g. 0x401000 or overlay:0x1000
    pub address: String,
    /// Comment type to delete
    #[arg(long, value_parser = ["eol", "pre", "post", "plate"], ignore_case = true)]
    pub comment_type: Option<String>,
    /// Delete all EOL, PRE, POST, and PLATE comments at this address
    #[arg(long)]
    pub all: bool,
    /// Target program
    #[arg(long)]
    pub program: Option<String>,
    /// Project name
    #[arg(long)]
    pub project: Option<String>,
    /// Fields to include in the deletion receipt (comma-separated)
    #[arg(long)]
    pub fields: Option<String>,
    /// Output format (omitted: compact on TTY, json-compact otherwise)
    #[arg(long, short = 'o', value_enum, ignore_case = true)]
    pub format: Option<super::OutputFormat>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct CommentSetArgs {
    /// Explicit address, e.g. 0x401000 or overlay:0x1000
    pub address: String,
    /// Comment text. Omit when using --stdin or --text-file: a shell argument
    /// is subject to shell metacharacter expansion (e.g. backticks) before
    /// ghidra-cli ever sees it, which can silently corrupt free-form prose.
    #[arg(required_unless_present_any = ["stdin", "text_file"])]
    pub text: Option<String>,
    #[arg(long, value_parser = ["eol", "pre", "post", "plate"], ignore_case = true)]
    pub comment_type: Option<String>,
    /// Read comment text from stdin instead of the TEXT argument
    #[arg(long, conflicts_with_all = ["text", "text_file"])]
    pub stdin: bool,
    /// Read comment text from a file instead of the TEXT argument
    #[arg(long, conflicts_with = "text")]
    pub text_file: Option<std::path::PathBuf>,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}
