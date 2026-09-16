mod scripts;
mod symbols;

use crate::cli::{self, Commands};
use crate::ipc::client::BridgeClient;

pub(super) fn validate_supported_command(command: &Commands) -> anyhow::Result<()> {
    match command {
        Commands::Memory(cli::MemoryCommands::Write(_)) => {
            anyhow::bail!(
                "memory write is not implemented (WIP); use patch bytes for supported byte edits"
            )
        }
        Commands::Memory(cli::MemoryCommands::Search(_)) => {
            anyhow::bail!(
                "memory search is not implemented (WIP); use find bytes for byte-pattern searches"
            )
        }
        _ => Ok(()),
    }
}

/// Resolve `comment set`'s text from `--stdin`, `--text-file`, or the TEXT
/// positional (in that priority order; clap already rejects combining them).
/// Reading from stdin/a file bypasses the shell entirely, so callers building
/// comment text programmatically never risk the metacharacter-expansion
/// corruption a shell argument is exposed to (e.g. backticks silently running
/// as command substitution before ghidra-cli ever sees the string).
fn resolve_comment_text(args: &cli::CommentSetArgs) -> anyhow::Result<String> {
    if args.stdin {
        crate::terminal::read_stdin("comment text")
    } else if let Some(path) = &args.text_file {
        std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Failed to read --text-file {}: {}", path.display(), e))
    } else {
        args.text
            .clone()
            .ok_or_else(|| anyhow::anyhow!("TEXT argument required (or use --stdin / --text-file)"))
    }
}

fn resolve_c_source(args: &cli::ImportCArgs) -> anyhow::Result<String> {
    let code = if args.stdin {
        crate::terminal::read_stdin("C definitions")?
    } else if let Some(path) = &args.file {
        std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Failed to read --file {}: {}", path.display(), e))?
    } else {
        args.code
            .clone()
            .ok_or_else(|| anyhow::anyhow!("C code, --file, or --stdin required"))?
    };
    anyhow::ensure!(!code.trim().is_empty(), "C definitions must not be empty");
    Ok(code)
}

/// Execute a command via the bridge client.
pub(super) fn execute_via_bridge(
    client: &BridgeClient,
    command: &Commands,
    quiet: bool,
    fetch: &crate::query::FetchParams,
) -> anyhow::Result<serde_json::Value> {
    use serde_json::json;

    let list_limit = fetch.limit;

    match command {
        // Analyze shares the generic dispatch path with all query commands
        Commands::Analyze(_) => {
            if !quiet {
                eprintln!("Analyzing...");
            }
            let result = client.analyze()?;
            if !quiet {
                eprintln!("Analysis complete!");
            }
            Ok(json!({
                "command": "analyze",
                "status": "success",
                "data": result
            }))
        }
        Commands::Query(args) => match args.data_type {
            cli::QueryDataType::Functions => {
                client.list_functions(list_limit, fetch.filter.clone(), &[], false, fetch.offset)
            }
            cli::QueryDataType::Strings => {
                client.list_strings(list_limit, fetch.filter.clone(), fetch.offset)
            }
            cli::QueryDataType::Imports => client.list_imports(list_limit),
            cli::QueryDataType::Exports => client.list_exports(list_limit),
            cli::QueryDataType::Memory => client.memory_map(),
        },
        Commands::Decompile(args) => client.decompile(
            args.resolved_target().to_string(),
            args.with_vars,
            args.with_params,
        ),
        Commands::Function(cmd) => {
            use cli::FunctionCommands;
            match cmd {
                FunctionCommands::List(args) => client.list_functions(
                    list_limit,
                    fetch.filter.clone(),
                    &args.tags,
                    args.untagged,
                    fetch.offset,
                ),
                FunctionCommands::Decompile(args) => client.decompile(
                    args.resolved_target().to_string(),
                    args.with_vars,
                    args.with_params,
                ),
                FunctionCommands::Get(args) => client.send_command(
                    "get_function",
                    Some(json!({"address": args.resolved_target()})),
                ),
                FunctionCommands::Disasm(args) => client.disasm(args.resolved_target(), None),
                FunctionCommands::Calls(args) => client.function_calls(args.resolved_target()),
                FunctionCommands::XRefs(args) => {
                    client.xrefs_to(args.resolved_target().to_string())
                }
                FunctionCommands::Rename(args) => client.send_command(
                    "rename_function",
                    Some(json!({
                        "old_name": args.old_name,
                        "new_name": args.new_name,
                        "address": args.address,
                    })),
                ),
                FunctionCommands::Create(args) => client.send_command(
                    "create_function",
                    Some(json!({
                        "address": args.address,
                        "name": args.name,
                    })),
                ),
                FunctionCommands::Delete(args) => client.send_command(
                    "delete_function",
                    Some(json!({
                        "address": args.resolved_target(),
                    })),
                ),
                FunctionCommands::SetSignature(args) => client.send_command(
                    "function_set_signature",
                    Some(json!({
                        "target": args.resolved_target(),
                        "signature": args.signature,
                    })),
                ),
                FunctionCommands::SetReturnType(args) => client.send_command(
                    "function_set_return_type",
                    Some(json!({
                        "target": args.resolved_target(),
                        "return_type": args.return_type,
                    })),
                ),
                FunctionCommands::SetCallingConvention(args) => client.send_command(
                    "function_set_calling_convention",
                    Some(json!({
                        "target": args.resolved_target(),
                        "convention": args.convention,
                    })),
                ),
                FunctionCommands::EditVar(args) => client.send_command(
                    "function_edit_var",
                    Some(json!({
                        "target": args.resolved_target(),
                        "var_name": args.var_name,
                        "new_name": args.new_name,
                        "type_name": args.type_name,
                    })),
                ),
                FunctionCommands::SetNoReturn(args) => {
                    client.function_set_noreturn(args.resolved_target(), args.value)
                }
                FunctionCommands::Tag(cmd) => {
                    use cli::FunctionTagCommands;
                    match cmd {
                        FunctionTagCommands::Add(args) => {
                            client.function_tag_add(&args.target, &args.tag_name)
                        }
                        FunctionTagCommands::Remove(args) => {
                            client.function_tag_remove(&args.target, &args.tag_name)
                        }
                        FunctionTagCommands::List(args) => {
                            client.function_tag_list(args.target.as_deref())
                        }
                    }
                }
            }
        }
        Commands::Strings(cmd) => {
            use cli::StringsCommands;
            match cmd {
                StringsCommands::List(_) => {
                    client.list_strings(list_limit, fetch.filter.clone(), fetch.offset)
                }
                StringsCommands::Refs(args) => client.string_refs(args.string.clone()),
            }
        }
        Commands::Memory(cmd) => {
            use cli::MemoryCommands;
            match cmd {
                MemoryCommands::Map(_) => client.memory_map(),
                MemoryCommands::Read(args) => client.send_command(
                    "read_memory",
                    Some(json!({
                        "address": args.address,
                        "size": args.size,
                    })),
                ),
                MemoryCommands::Write(_) | MemoryCommands::Search(_) => {
                    validate_supported_command(command)?;
                    unreachable!("unsupported memory commands are rejected")
                }
            }
        }
        Commands::Dump(cmd) => {
            use cli::DumpCommands;
            match cmd {
                DumpCommands::Imports(_) => client.list_imports(list_limit),
                DumpCommands::Exports(_) => client.list_exports(list_limit),
                DumpCommands::Functions(_) => client.list_functions(
                    list_limit,
                    fetch.filter.clone(),
                    &[],
                    false,
                    fetch.offset,
                ),
                DumpCommands::Strings(_) => {
                    client.list_strings(list_limit, fetch.filter.clone(), fetch.offset)
                }
            }
        }
        Commands::Summary(_) => client.program_info(),
        Commands::XRef(cmd) => {
            use cli::XRefCommands;
            match cmd {
                XRefCommands::To(args) => client.xrefs_to(args.resolved_target().to_string()),
                XRefCommands::From(args) => client.xrefs_from(args.resolved_target().to_string()),
                XRefCommands::List(args) => client.send_command(
                    "xrefs_list",
                    Some(json!({"address": args.resolved_target()})),
                ),
            }
        }
        Commands::Program(cmd) => {
            use cli::ProgramCommands;
            match cmd {
                ProgramCommands::List(_) => client.list_programs(),
                ProgramCommands::Open(args) => {
                    let program = args.program.as_ref().ok_or_else(|| {
                        anyhow::anyhow!("Program name required. Use --program <name>")
                    })?;
                    client.open_program(program)
                }
                ProgramCommands::Close(_) => client.program_close(),
                ProgramCommands::Delete(args) => {
                    let program = args
                        .program
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("Program name required"))?;
                    client.program_delete(program)
                }
                ProgramCommands::Info(_) => client.program_info(),
                ProgramCommands::Export(args) => {
                    let output = args
                        .output
                        .as_deref()
                        .map(std::path::absolute)
                        .transpose()?;
                    client.program_export(
                        &args.format,
                        output
                            .as_deref()
                            .map(|path| path.to_string_lossy())
                            .as_deref(),
                    )
                }
                // Top-level save handles a stopped bridge without auto-start;
                // inside a batch, the bridge is already available.
                ProgramCommands::Save(_) => client.program_save(),
            }
        }
        Commands::Symbol(cmd) => symbols::execute(client, cmd, fetch),
        Commands::Type(cmd) => {
            use cli::TypeCommands;
            match cmd {
                TypeCommands::List(_) => client.type_list(list_limit, fetch.filter.as_deref(), fetch.offset),
                TypeCommands::Get(args) => client.type_get(&args.name),
                TypeCommands::Create(args) => client.type_create(&args.definition),
                TypeCommands::Apply(args) => {
                    client.type_apply_force(&args.address, &args.type_name, args.force)
                }
                TypeCommands::ImportC(args) => {
                    client.type_import_c(&resolve_c_source(args)?, args.category.as_deref())
                }
                TypeCommands::Delete(args) => {
                    client.send_command("type_delete", Some(json!({"name": args.name})))
                }
                TypeCommands::Rename(args) => client.send_command(
                    "type_rename",
                    Some(json!({"old_name": args.old_name, "new_name": args.new_name})),
                ),
                TypeCommands::CreateEnum(args) => client.send_command(
                    "type_create_enum",
                    Some(json!({
                        "name": args.name,
                        "values": args.values,
                        "size": args.size,
                    })),
                ),
                TypeCommands::Typedef(args) => client.send_command(
                    "type_typedef",
                    Some(json!({
                        "name": args.name,
                        "base_type": args.base_type,
                    })),
                ),
                TypeCommands::AddField(args) => client.send_command(
                    "type_add_field",
                    Some(json!({
                        "type_name": args.type_name,
                        "field_name": args.name,
                        "field_type": args.field_type,
                        "offset": args.offset,
                        "size": args.size,
                    })),
                ),
                TypeCommands::SetField(args) => client.send_command(
                    "type_set_field",
                    Some(json!({"type_name": args.type_name, "offset": args.offset,
                        "field_name": args.name, "field_type": args.field_type, "comment": args.comment})),
                ),
                TypeCommands::ClearField(args) => client.send_command(
                    "type_clear_field",
                    Some(json!({"type_name": args.type_name, "offset": args.offset})),
                ),
                TypeCommands::DelField(args) => client.send_command(
                    "type_del_field",
                    Some(json!({
                        "type_name": args.type_name,
                        "field_name": args.name,
                    })),
                ),
            }
        }
        Commands::Tag(cmd) => {
            use cli::TagCommands;
            match cmd {
                TagCommands::List(args) => client.tag_list(list_limit, args.function.as_deref()),
                TagCommands::Get(args) => client.tag_get(&args.name, list_limit),
                TagCommands::Create(args) => client.send_command(
                    "tag_create",
                    Some(json!({"name": args.name, "comment": args.comment})),
                ),
                TagCommands::Delete(args) => {
                    client.send_command("tag_delete", Some(json!({"name": args.name})))
                }
                TagCommands::Rename(args) => client.send_command(
                    "tag_rename",
                    Some(json!({"name": args.old_name, "new_name": args.new_name})),
                ),
                TagCommands::SetComment(args) => client.send_command(
                    "tag_set_comment",
                    Some(json!({"name": args.name, "comment": args.comment})),
                ),
                TagCommands::Add(args) => client.send_command(
                    "tag_add",
                    Some(json!({
                        "function": args.target,
                        "tags": args.tags,
                        "no_create": args.no_create,
                    })),
                ),
                TagCommands::Remove(args) => client.send_command(
                    "tag_remove",
                    Some(json!({
                        "function": args.target,
                        "tags": args.tags,
                        "all": args.all,
                    })),
                ),
            }
        }
        Commands::Comment(cmd) => {
            use cli::CommentCommands;
            match cmd {
                CommentCommands::List(_) => {
                    client.comment_list(list_limit, fetch.filter.as_deref(), fetch.offset)
                }
                CommentCommands::Get(args) => client.comment_get(&args.address),
                CommentCommands::Set(args) => {
                    let text = resolve_comment_text(args)?;
                    client.comment_set(&args.address, &text, args.comment_type.as_deref())
                }
                CommentCommands::Delete(args) => client.comment_delete(&args.address),
            }
        }
        Commands::Graph(cmd) => {
            use cli::GraphCommands;
            match cmd {
                GraphCommands::Calls(_) => client.graph_calls(list_limit),
                GraphCommands::Callers(args) => {
                    client.graph_callers(args.resolved_target(), args.depth, list_limit)
                }
                GraphCommands::Callees(args) => {
                    client.graph_callees(args.resolved_target(), args.depth, list_limit)
                }
                GraphCommands::Export(args) => client.graph_export(&args.format),
            }
        }
        Commands::Find(cmd) => {
            use cli::FindCommands;
            match cmd {
                FindCommands::String(args) => client.find_string(&args.pattern),
                FindCommands::Bytes(args) => client.find_bytes(&args.hex),
                FindCommands::Instruction(args) => client.find_instruction(
                    &args.pattern,
                    args.start.as_deref(),
                    args.end.as_deref(),
                    args.case_sensitive,
                    list_limit,
                ),
                FindCommands::Function(args) => client.find_function(&args.pattern),
                FindCommands::Calls(args) => client.find_calls(args.resolved_target()),
                FindCommands::Crypto(_) => client.find_crypto(),
                FindCommands::Interesting(_) => client.find_interesting(),
            }
        }
        Commands::Diff(cmd) => {
            use cli::DiffCommands;
            match cmd {
                DiffCommands::Functions(args) => client.diff_functions(&args.func1, &args.func2),
            }
        }
        Commands::Patch(cmd) => {
            use cli::PatchCommands;
            match cmd {
                PatchCommands::Bytes(args) => client.patch_bytes(&args.address, &args.hex),
                PatchCommands::Nop(args) => client.patch_nop(&args.address, args.count),
                PatchCommands::Export(args) => {
                    client.patch_export(&std::path::absolute(&args.output)?.to_string_lossy())
                }
            }
        }
        Commands::Script(cmd) => scripts::execute(client, cmd),
        Commands::Disasm(args) => match &args.end {
            Some(end) => client.disasm_range(args.resolved_target(), end, list_limit),
            None => client.disasm(args.resolved_target(), args.num_instructions),
        },
        Commands::DisasmAt(args) => client.disasm_at(&args.address, args.count),
        Commands::Clear(args) => {
            let (start, end) = split_range(&args.range).ok_or_else(|| {
                anyhow::anyhow!(
                    "Invalid range '{}': expected START:END, e.g. 0bf3:0bfa \
                     (overlay addresses are supported, e.g. rom1::5512:551d or \
                     rom1::5512:rom1::551d)",
                    args.range
                )
            })?;
            client.clear_range(&start, &end, args.disasm_at.as_deref())
        }
        Commands::Stats(_) => client.stats(),
        Commands::Pcode(cmd) => {
            use cli::PcodeCommands;
            match cmd {
                PcodeCommands::At(args) => client.pcode_at(&args.address),
                PcodeCommands::Function(args) => client.pcode_function(&args.function, args.high),
            }
        }
        Commands::Analyzer(cmd) => {
            use cli::AnalyzerCommands;
            match cmd {
                AnalyzerCommands::List(_) => client.analyzer_list(),
                AnalyzerCommands::Set(args) => client.analyzer_set(&args.name, args.enabled),
                AnalyzerCommands::Run(_) => client.analyze_run(),
            }
        }
        Commands::Rename(args) => symbols::rename(client, args),
        _ => anyhow::bail!("Command not supported"),
    }
}

/// Split a `clear` RANGE argument into (start, end) addresses, treating `::`
/// (the overlay-space separator, e.g. `rom20::69f0`) as a single unit rather
/// than a split point -- a bare `split_once(':')` breaks on it, taking
/// everything before the first `:` (just the overlay space name) as the
/// whole start address.
///
/// If only the start address carries an overlay-space prefix and the end
/// address is bare (e.g. `rom1::5512:551d`), the end address inherits the
/// start's space (`rom1::551d`) rather than resolving in the default space.
fn split_range(range: &str) -> Option<(String, String)> {
    let bytes = range.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b':' {
            if i + 1 < bytes.len() && bytes[i + 1] == b':' {
                i += 2;
                continue;
            }
            let start = &range[..i];
            let end = &range[i + 1..];
            return Some(match start.split_once("::") {
                Some((space, _)) if !end.contains("::") && !end.is_empty() => {
                    (start.to_string(), format!("{}::{}", space, end))
                }
                _ => (start.to_string(), end.to_string()),
            });
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_range_plain_addresses() {
        assert_eq!(
            split_range("0bf3:0bfa"),
            Some(("0bf3".to_string(), "0bfa".to_string()))
        );
    }

    #[test]
    fn split_range_overlay_start_bare_end_inherits_space() {
        // ghidra-bug.md: naive split_once(':') took "rom1" as the whole start
        // address; the correct split is on the ':' after the overlay prefix,
        // and the bare end address inherits the start's overlay space.
        assert_eq!(
            split_range("rom1::5512:551d"),
            Some(("rom1::5512".to_string(), "rom1::551d".to_string()))
        );
    }

    #[test]
    fn split_range_overlay_both_sides_qualified() {
        assert_eq!(
            split_range("rom1::5512:rom1::551d"),
            Some(("rom1::5512".to_string(), "rom1::551d".to_string()))
        );
    }

    #[test]
    fn split_range_overlay_end_in_different_space() {
        assert_eq!(
            split_range("rom1::5512:rom2::551d"),
            Some(("rom1::5512".to_string(), "rom2::551d".to_string()))
        );
    }

    #[test]
    fn split_range_missing_colon_is_none() {
        assert_eq!(split_range("rom1::5512"), None);
        assert_eq!(split_range("0bf3"), None);
    }
}
