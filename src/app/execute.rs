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
    if let Commands::Listing(cli::ListingCommands::Undefine(args)) = command {
        for (label, value) in [("START", &args.start), ("--end", &args.end)] {
            anyhow::ensure!(
                crate::address::ExplicitAddress::parse_canonical(value).is_some(),
                "Invalid {label} address '{value}': use a 0x-prefixed address, \
                 qualifying overlay and segmented addresses with their space name"
            );
        }
    }
    let selector = match command {
        Commands::Symbol(cli::SymbolCommands::Rename(args)) => {
            Some((args.address.as_deref(), args.filter.as_deref()))
        }
        Commands::Symbol(cli::SymbolCommands::Delete(args)) => {
            Some((args.address.as_deref(), args.filter.as_deref()))
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
        Commands::Analysis(cli::AnalysisCommands::Run(args)) => {
            if !quiet {
                eprintln!("Analyzing...");
            }
            let result =
                client.analysis_run(args.start.as_deref(), args.end.as_deref(), args.pending)?;
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
                    client.send_command("get_function", Some(json!({
                        "address": args.target,
                        "with_signature": args.with_signature,
                    })))
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
                FunctionCommands::SetReturnType(args) => {
                    client.function_set_return_type(&args.target, &args.return_type)
                }
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
                FunctionCommands::SetStackPurge(args) => client.send_command(
                    "function_set_stack_purge",
                    Some(json!({"target": args.target, "bytes": args.bytes, "unknown": args.unknown})),
                ),
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
                        "source": args.source,
                    })),
                ),
            }
        }
        Commands::Data(cmd) => match cmd {
            cli::DataCommands::List(_) => {
                client.send_command("data_list", Some(json!({"limit": list_limit})))
            }
            cli::DataCommands::Read(args) => client.send_command(
                "data_read",
                Some(json!({
                    "target": args.target,
                    "max_depth": args.max_depth,
                    "max_elements": args.max_elements,
                })),
            ),
        },
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
                ProgramCommands::Context(cmd) => match cmd {
                    cli::ProgramContextCommands::List(_) => client.program_context_list(),
                    cli::ProgramContextCommands::Get(args) => {
                        client.program_context_get(&args.register, &args.start, args.end.as_deref())
                    }
                    cli::ProgramContextCommands::Set(args) => client.program_context_set(
                        &args.register,
                        &args.value,
                        &args.start,
                        &args.end,
                    ),
                    cli::ProgramContextCommands::Clear(args) => {
                        client.program_context_clear(&args.register, &args.start, &args.end)
                    }
                },
                ProgramCommands::Rebase(args) => client.program_rebase(&args.base),
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
        Commands::Listing(cmd) => match cmd {
            cli::ListingCommands::DefineCode(args) => {
                client.define_code(&args.target, args.end.as_deref())
            }
            cli::ListingCommands::Undefine(args) => client.clear_range(
                args.start.trim(),
                args.end.trim(),
                args.disasm_at.as_deref(),
            ),
        },
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
