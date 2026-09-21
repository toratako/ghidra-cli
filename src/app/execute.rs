mod scripts;
mod symbols;

use crate::cli::{self, Commands};
use crate::ipc::client::BridgeClient;

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

/// Validate locally parsed command syntax before any program selection or edits.
pub(super) fn validate_command_syntax(command: &Commands) -> anyhow::Result<()> {
    if let Commands::Clear(args) = command {
        parse_clear_range(&args.range)?;
    }
    let selector = match command {
        Commands::Symbol(cli::SymbolCommands::Rename(args)) => {
            Some((args.address.as_deref(), args.filter.as_deref()))
        }
        Commands::Symbol(cli::SymbolCommands::Delete(args)) => {
            Some((args.address.as_deref(), args.options.filter.as_deref()))
        }
        _ => None,
    };
    if let Some((address, filter)) = selector {
        symbols::parse_selector(address, filter)?;
    }
    if let Commands::Script(cli::ScriptCommands::Run(args)) = command {
        scripts::validate_expect_specs(&args.expect)?;
    }
    Ok(())
}

fn parse_clear_range(range: &str) -> anyhow::Result<(String, String)> {
    split_range(range).ok_or_else(|| {
        anyhow::anyhow!(
            "Invalid or ambiguous range '{}': use 0x-prefixed START:END, \
             e.g. 0x1000:0x1010 or overlay:0x1000:overlay:0x1010; \
             specify both segment components for segmented endpoints",
            range
        )
    })
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
        Commands::Analysis(cli::AnalysisCommands::Run(_)) => {
            if !quiet {
                eprintln!("Analyzing...");
            }
            let result = client.analysis_run()?;
            if !quiet {
                eprintln!("Analysis complete!");
            }
            Ok(json!({
                "command": "analysis run",
                "status": "success",
                "data": result
            }))
        }
        Commands::Decompile(args) => client.decompile(
            args.target.clone(),
            args.with_vars,
            args.with_params,
            args.with_jump_tables,
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
                FunctionCommands::Get(args) => {
                    client.send_command("get_function", Some(json!({"address": args.target})))
                }
                FunctionCommands::ListCallingConventions(_) => {
                    client.function_list_calling_conventions()
                }
                FunctionCommands::Disasm(args) => client.function_disasm(&args.target, list_limit),
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
                        "address": args.target,
                    })),
                ),
                FunctionCommands::SetSignature(args) => client.send_command(
                    "function_set_signature",
                    Some(json!({
                        "target": args.target,
                        "signature": args.signature,
                    })),
                ),
                FunctionCommands::SetReturnType(args) => client.send_command(
                    "function_set_return_type",
                    Some(json!({
                        "target": args.target,
                        "return_type": args.return_type,
                    })),
                ),
                FunctionCommands::SetCallingConvention(args) => client.send_command(
                    "function_set_calling_convention",
                    Some(json!({
                        "target": args.target,
                        "convention": args.convention,
                    })),
                ),
                FunctionCommands::EditVar(args) => client.function_edit_var(
                    &args.target,
                    &args.var_name,
                    args.new_name.as_deref(),
                    args.type_name.as_deref(),
                ),
                FunctionCommands::SetNoReturn(args) => {
                    client.function_set_noreturn(&args.target, args.value)
                }
            }
        }
        Commands::Strings(cmd) => {
            use cli::StringsCommands;
            match cmd {
                StringsCommands::List(_) => {
                    client.list_strings(list_limit, fetch.filter.clone(), fetch.offset)
                }
                StringsCommands::Refs(args) => client.string_refs(args.pattern.clone()),
            }
        }
        Commands::Memory(cmd) => {
            use cli::MemoryCommands;
            match cmd {
                MemoryCommands::Map(_) => client.memory_map(),
                MemoryCommands::Info(args) => client.memory_info(&args.target),
                MemoryCommands::Write(args) => client.memory_write(&args.address, &args.hex),
                MemoryCommands::Read(args) => client.send_command(
                    "read_memory",
                    Some(json!({
                        "address": args.address,
                        "size": args.size,
                    })),
                ),
            }
        }
        Commands::XRef(cmd) => {
            use cli::XRefCommands;
            match cmd {
                XRefCommands::To(args) => client.xrefs_to(args.target.clone()),
                XRefCommands::From(args) => client.xrefs_from(args.target.clone(), args.function),
            }
        }
        Commands::Program(cmd) => {
            use cli::ProgramCommands;
            match cmd {
                ProgramCommands::Import(_) => {
                    unreachable!("program import is dispatched before bridge execution")
                }
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
                ProgramCommands::Stats(_) => client.stats(),
                ProgramCommands::ListRelocations(_) => client.program_list_relocations(),
                ProgramCommands::Export(args) => {
                    let output = std::path::absolute(&args.output)?;
                    client.program_export(&args.format, Some(&output.to_string_lossy()))
                }
                // Top-level save handles a stopped bridge without auto-start;
                // inside a batch, the bridge is already available.
                ProgramCommands::Save(_) => client.program_save(),
            }
        }
        Commands::Symbol(cmd) => symbols::execute(client, cmd, fetch),
        Commands::Type(cmd) => {
            use cli::{TypeCommands, TypeCreateCommands};
            match cmd {
                TypeCommands::List(_) => {
                    client.type_list(list_limit, fetch.filter.as_deref(), fetch.offset)
                }
                TypeCommands::Get(args) => client.type_get(&args.name),
                TypeCommands::Create(cmd) => match cmd {
                    TypeCreateCommands::Struct(args) => client.type_create(&args.name),
                    TypeCreateCommands::Union(args) => {
                        client.send_command("type_create_union", Some(json!({"name": args.name})))
                    }
                    TypeCreateCommands::Enum(args) => client.send_command(
                        "type_create_enum",
                        Some(json!({
                            "name": args.name,
                            "values": args.values,
                            "size": args.size,
                        })),
                    ),
                    TypeCreateCommands::Typedef(args) => client.send_command(
                        "type_typedef",
                        Some(json!({
                            "name": args.name,
                            "base_type": args.base_type,
                        })),
                    ),
                },
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
                TypeCommands::Field(cmd) => match cmd {
                    cli::TypeFieldCommands::Append(args) => client.send_command(
                        "type_field_append",
                        Some(json!({
                            "type_name": args.type_name,
                            "field_name": args.name,
                            "field_type": args.field_type,
                            "size": args.size,
                        })),
                    ),
                    cli::TypeFieldCommands::Set(args) => client.send_command(
                        "type_field_set",
                        Some(json!({
                            "type_name": args.type_name,
                            "offset": args.selector.offset,
                            "ordinal": args.selector.ordinal,
                            "field": args.selector.field,
                            "field_name": args.name,
                            "field_type": args.field_type,
                            "size": args.size,
                            "comment": args.comment,
                        })),
                    ),
                    cli::TypeFieldCommands::Clear(args) => client.send_command(
                        "type_field_clear",
                        Some(json!({"type_name": args.type_name, "offset": args.offset,
                            "field": args.field})),
                    ),
                    cli::TypeFieldCommands::Delete(args) => client.send_command(
                        "type_field_delete",
                        Some(json!({
                            "type_name": args.type_name,
                            "offset": args.selector.offset,
                            "ordinal": args.selector.ordinal,
                            "field": args.selector.field,
                        })),
                    ),
                },
                TypeCommands::Enum(cli::TypeEnumCommands::Member(cmd)) => match cmd {
                    cli::TypeEnumMemberCommands::Delete(args) => client.send_command(
                        "type_enum_member_delete",
                        Some(json!({"type_name": args.type_name, "member_name": args.name})),
                    ),
                },
            }
        }
        Commands::Tag(cmd) => {
            use cli::TagCommands;
            match cmd {
                TagCommands::List(args) => client.tag_list(list_limit, args.function.as_deref()),
                TagCommands::Get(args) => client.tag_get(&args.name),
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
        Commands::Bookmark(cmd) => match cmd {
            cli::BookmarkCommands::List(_) => client.bookmark_list(),
            cli::BookmarkCommands::Get(args) => client.bookmark_get(&args.address),
        },
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
                CommentCommands::Delete(args) => {
                    client.comment_delete(&args.address, args.comment_type.as_deref(), args.all)
                }
            }
        }
        Commands::Graph(cmd) => {
            use cli::GraphCommands;
            match cmd {
                GraphCommands::Calls(_) => client.graph_calls(list_limit),
                GraphCommands::Callers(args) => {
                    client.graph_callers(&args.target, args.depth, list_limit)
                }
                GraphCommands::Callees(args) => {
                    client.graph_callees(&args.target, args.depth, list_limit)
                }
            }
        }
        Commands::Find(cmd) => {
            use cli::FindCommands;
            match cmd {
                FindCommands::String(args) => client.find_string_page(
                    &args.pattern,
                    list_limit,
                    fetch.filter.clone(),
                    fetch.offset,
                ),
                FindCommands::Bytes(args) => {
                    if args.regex {
                        client.find_bytes_regex_with_limit(&args.hex, list_limit)
                    } else {
                        client.find_bytes_with_limit(&args.hex, list_limit)
                    }
                }
                FindCommands::Text(args) => {
                    client.find_text_with_limit(&args.text, &args.encoding, list_limit)
                }
                FindCommands::Instruction(args) => client.find_instruction(
                    &args.pattern,
                    args.start.as_deref(),
                    args.end.as_deref(),
                    args.case_sensitive,
                    list_limit,
                ),
                FindCommands::Constant(args) => client.send_command(
                    "find_constant",
                    Some(json!({
                        "value": args.value, "min": args.min, "max": args.max,
                        "bits": args.bits, "start": args.start, "end": args.end,
                        "limit": list_limit,
                    })),
                ),
            }
        }
        Commands::Script(cmd) => scripts::execute(client, cmd),
        Commands::Disasm(args) => match &args.end {
            Some(end) => client.disasm_range(&args.target, end, list_limit),
            None => client.disasm(&args.target, list_limit),
        },
        Commands::DefineCode(args) => client.define_code(&args.target, args.end.as_deref()),
        Commands::Clear(args) => {
            let (start, end) = parse_clear_range(&args.range)?;
            client.clear_range(&start, &end, args.disasm_at.as_deref())
        }
        Commands::Pcode(cmd) => {
            use cli::PcodeCommands;
            match cmd {
                PcodeCommands::At(args) => client.pcode_at(&args.address),
                PcodeCommands::Function(args) => client.pcode_function(&args.function, args.high),
            }
        }
        Commands::Analysis(cli::AnalysisCommands::Option(cmd)) => {
            use cli::AnalysisOptionCommands;
            match cmd {
                AnalysisOptionCommands::List(_) => client.analysis_option_list(),
                AnalysisOptionCommands::Get(args) => client.analysis_option_get(&args.name),
                AnalysisOptionCommands::Set(args) => {
                    client.analysis_option_set(&args.name, &args.value)
                }
            }
        }
        _ => anyhow::bail!("Command not supported"),
    }
}

/// Require one unambiguous split into two explicit addresses. An unqualified
/// end inherits the start's space; segmented endpoints require a space name.
fn split_range(range: &str) -> Option<(String, String)> {
    let mut result = None;
    for (i, _) in range.match_indices(':') {
        let (start, end) = (&range[..i], &range[i + 1..]);
        let (Some(start_address), Some(end_address)) = (
            crate::address::ExplicitAddress::parse_canonical(start),
            crate::address::ExplicitAddress::parse_canonical(end),
        ) else {
            continue;
        };
        if result.is_some() {
            return None;
        }
        let end = match (start_address.space, end_address.space) {
            (Some(space), None) => format!("{space}:{}", end.trim()),
            _ => end.trim().to_owned(),
        };
        result = Some((start.trim().to_owned(), end));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_range_plain_addresses() {
        assert_eq!(
            split_range("0x0bf3:0x0bfa"),
            Some(("0x0bf3".to_string(), "0x0bfa".to_string()))
        );
    }

    #[test]
    fn split_range_overlay_start_bare_end_inherits_space() {
        assert_eq!(
            split_range("rom1:0x5512:0x551d"),
            Some(("rom1:0x5512".to_string(), "rom1:0x551d".to_string()))
        );
    }

    #[test]
    fn split_range_overlay_both_sides_qualified() {
        assert_eq!(
            split_range("rom1:0x5512:rom1:0x551d"),
            Some(("rom1:0x5512".to_string(), "rom1:0x551d".to_string()))
        );
    }

    #[test]
    fn split_range_overlay_end_in_different_space() {
        assert_eq!(
            split_range("rom1:0x5512:rom2:0x551d"),
            Some(("rom1:0x5512".to_string(), "rom2:0x551d".to_string()))
        );
    }

    #[test]
    fn split_range_missing_colon_is_none() {
        for invalid in [
            "rom1:0x5512",
            "0x0bf3",
            "0bf3:0bfa",
            "rom1::5512:551d",
            "0x1234:0x0:0x8",
            "0x1234:0x1000:0x100010",
            "0x1000:",
            ":0x1000",
        ] {
            assert_eq!(split_range(invalid), None, "{invalid}");
        }
    }

    #[test]
    fn split_range_preserves_segmented_endpoints() {
        assert_eq!(
            split_range("ram:0x1234:0x0:ram:0x1234:0x8"),
            Some(("ram:0x1234:0x0".into(), "ram:0x1234:0x8".into()))
        );
    }

    #[test]
    fn split_range_numeric_space_names_do_not_become_segments() {
        assert_eq!(
            split_range("0x1234:0x1000.0:0x1234:0x100010.0"),
            Some(("0x1234:0x1000.0".into(), "0x1234:0x100010.0".into()))
        );
        assert_eq!(
            split_range("rom:0x10000:0x1234:0x0005"),
            Some(("rom:0x10000".into(), "0x1234:0x0005".into()))
        );
    }
}
