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
    /// Selection expression (same syntax as `--filter` on query commands) used
    /// to narrow which of the name's matches get renamed, e.g.
    /// `--where 'address=0xc200'`.
    #[arg(long = "where", value_name = "EXPR")]
    pub where_expr: Option<String>,
    /// Rename every symbol named `old_name`, program-wide. Without this (or
    /// `--address`/`--where`), an ambiguous name is a hard error rather
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
    /// Move one local label or function into an existing namespace or class
    SetNamespace(SymbolSetNamespaceArgs),
    /// Make one saved local label the primary symbol at its address
    SetPrimary(SymbolSetPrimaryArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct SymbolSelectionArgs {
    /// Exact symbol name
    pub name: String,
    /// Explicit address to narrow the selection; segmented addresses require their space name
    #[arg(long)]
    pub address: Option<String>,
    /// Expression selecting one symbol, e.g. id='12345' or namespace=app
    #[arg(long = "where", value_name = "EXPR")]
    pub where_expr: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct SymbolSetNamespaceArgs {
    #[command(flatten)]
    pub selection: SymbolSelectionArgs,
    /// Existing namespace/class path from global scope
    #[arg(long, required_unless_present = "global", conflicts_with = "global")]
    pub namespace: Option<String>,
    /// Move the symbol to global scope
    #[arg(long)]
    pub global: bool,
    #[command(flatten)]
    pub options: ObjectOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct SymbolSetPrimaryArgs {
    #[command(flatten)]
    pub selection: SymbolSelectionArgs,
    #[command(flatten)]
    pub options: ObjectOptions,
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
    /// Selection expression used to narrow which of the name's matches get deleted,
    /// e.g. --where 'address=0xc200'.
    #[arg(long = "where", value_name = "EXPR")]
    pub where_expr: Option<String>,
    /// Delete every symbol named `name`, program-wide. Without this (or
    /// `--address`/`--where`), an ambiguous name is a hard error rather
    /// than silently deleting every match.
    #[arg(long)]
    pub all: bool,
    #[command(flatten)]
    pub options: ObjectOptions,
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
pub enum BookmarkCommands {
    /// List all bookmarks
    List(QueryOptions),
    /// Get bookmarks at an address
    Get(BookmarkGetArgs),
    /// Set the text of one exact address/type/category bookmark
    Set(BookmarkSetArgs),
    /// Delete one exact address/type/category bookmark
    Delete(BookmarkDeleteArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct BookmarkSetArgs {
    /// Explicit address; no function-start normalization is performed
    pub address: String,
    /// Bookmark text; an empty string leaves an empty bookmark
    #[arg(long, required_unless_present_any = ["stdin", "text_file"])]
    pub text: Option<String>,
    /// Read bookmark text from stdin
    #[arg(long, conflicts_with_all = ["text", "text_file"])]
    pub stdin: bool,
    /// Read bookmark text from a UTF-8 file
    #[arg(long = "file", conflicts_with = "text")]
    pub text_file: Option<std::path::PathBuf>,
    /// Exact, case-sensitive bookmark type
    #[arg(long = "type", default_value = "Note")]
    pub bookmark_type: String,
    /// Exact, case-sensitive bookmark category
    #[arg(long)]
    pub category: String,
    #[command(flatten)]
    pub options: ObjectOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct BookmarkDeleteArgs {
    /// Explicit address; no function-start normalization is performed
    pub address: String,
    /// Exact, case-sensitive bookmark type
    #[arg(long = "type", default_value = "Note")]
    pub bookmark_type: String,
    /// Exact, case-sensitive bookmark category
    #[arg(long)]
    pub category: String,
    #[command(flatten)]
    pub options: ObjectOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct BookmarkGetArgs {
    /// Explicit address, e.g. 0x401000 or overlay:0x1000
    pub address: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum CommentCommands {
    /// List EOL, PRE, POST, and PLATE comments
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
    #[arg(long = "type", value_parser = ["eol", "pre", "post", "plate"], ignore_case = true)]
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
pub struct CommentSetArgs {
    /// Explicit address, e.g. 0x401000 or overlay:0x1000
    pub address: String,
    /// Comment text. Omit when using --stdin or --file: a shell argument
    /// is subject to shell metacharacter expansion (e.g. backticks) before
    /// ghidra-cli ever sees it, which can silently corrupt free-form prose.
    #[arg(long, required_unless_present_any = ["stdin", "text_file"])]
    pub text: Option<String>,
    #[arg(long = "type", value_parser = ["eol", "pre", "post", "plate"], ignore_case = true)]
    pub comment_type: Option<String>,
    /// Read comment text from stdin instead of --text
    #[arg(long, conflicts_with_all = ["text", "text_file"])]
    pub stdin: bool,
    /// Read comment text from a file instead of --text
    #[arg(long = "file", conflicts_with = "text")]
    pub text_file: Option<std::path::PathBuf>,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}
