mod functions;
mod memory;
mod scripts;
mod symbols;

use crate::cli::{self, Commands};
use crate::ipc::client::BridgeClient;

/// Read free-form annotation text without changing whitespace or line endings.
fn resolve_annotation_text(
    text: &Option<String>,
    stdin: bool,
    text_file: Option<&std::path::Path>,
    description: &str,
) -> anyhow::Result<String> {
    if stdin {
        crate::terminal::read_stdin(description)
    } else if let Some(path) = text_file {
        std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Failed to read --text-file {}: {}", path.display(), e))
    } else {
        text.clone()
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
    if let Commands::Function(cli::FunctionCommands::SetBody(args)) = command {
        anyhow::ensure!(
            !args.ranges.is_empty() && args.ranges.len().is_multiple_of(2),
            "--range requires START END pairs"
        );
        for address in &args.ranges {
            anyhow::ensure!(
                crate::address::ExplicitAddress::parse(address).is_some(),
                "Invalid --range address '{address}': use an explicit 0x-prefixed address"
            );
        }
    }
    if let Commands::Memory(command) = command {
        memory::validate(command)?;
    }
    if let Commands::Listing(cli::ListingCommands::Undefine(args)) = command {
        for (label, value) in [("START", &args.start), ("--end", &args.end)] {
            anyhow::ensure!(
                crate::address::ExplicitAddress::parse_canonical(value).is_some(),
                "Invalid {label} address '{value}': use a 0x-prefixed address, \
                 qualifying overlay and segmented addresses with their space name"
            );
        }
    }
    let edit_addresses: Vec<&str> = match command {
        Commands::Function(cli::FunctionCommands::CallSignature(cmd)) => vec![cmd.at()],
        Commands::Listing(cli::ListingCommands::Flow(cmd)) => {
            let mut addresses = vec![cmd.address()];
            if let cli::ListingFlowCommands::Set(args) = cmd {
                if let Some(address) = &args.fallthrough {
                    addresses.push(address);
                }
            }
            addresses
        }
        Commands::XRef(cli::XRefCommands::Create(cli::XRefCreateCommands::Memory(args))) => {
            vec![&args.from, &args.to]
        }
        Commands::XRef(cli::XRefCommands::Delete(args) | cli::XRefCommands::SetPrimary(args)) => {
            vec![&args.from, &args.to]
        }
        Commands::Equate(cli::EquateCommands::Attach(args) | cli::EquateCommands::Detach(args)) => {
            vec![&args.address]
        }
        Commands::Bookmark(cli::BookmarkCommands::Set(args)) => vec![&args.address],
        Commands::Bookmark(cli::BookmarkCommands::Delete(args)) => vec![&args.address],
        _ => vec![],
    };
    for address in edit_addresses {
        anyhow::ensure!(
            crate::address::ExplicitAddress::parse(address).is_some(),
            "Invalid address '{address}': use an explicit 0x-prefixed address"
        );
    }
    let selector = match command {
        Commands::Function(cli::FunctionCommands::Var(cli::FunctionVarCommands::Get(args))) => {
            Some((None, args.selection.filter.as_deref()))
        }
        Commands::Function(cli::FunctionCommands::Var(cli::FunctionVarCommands::Set(args))) => {
            Some((None, args.selection.filter.as_deref()))
        }
        Commands::Symbol(cli::SymbolCommands::Rename(args)) => {
            Some((args.address.as_deref(), args.filter.as_deref()))
        }
        Commands::Symbol(cli::SymbolCommands::Delete(args)) => {
            Some((args.address.as_deref(), args.filter.as_deref()))
        }
        Commands::Symbol(cli::SymbolCommands::SetNamespace(args)) => Some((
            args.selection.address.as_deref(),
            args.selection.filter.as_deref(),
        )),
        Commands::Symbol(cli::SymbolCommands::SetPrimary(args)) => Some((
            args.selection.address.as_deref(),
            args.selection.filter.as_deref(),
        )),
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
        Commands::Function(cmd) => functions::execute(client, cmd, fetch),
        Commands::Strings(cmd) => {
            use cli::StringsCommands;
            match cmd {
                StringsCommands::List(_) => {
                    client.list_strings(list_limit, fetch.filter.clone(), fetch.offset)
                }
                StringsCommands::Refs(args) => client.string_refs(args.pattern.clone()),
            }
        }
        Commands::Memory(cmd) => memory::execute(client, cmd),
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
                XRefCommands::Create(cli::XRefCreateCommands::Memory(args)) => client.send_command(
                    "xref_create_memory",
                    Some(json!({"from": args.from, "to": args.to, "operand_index": args.operand_index,
                        "ref_type": args.ref_type.to_ascii_uppercase()})),
                ),
                XRefCommands::Delete(args) | XRefCommands::SetPrimary(args) => client.send_command(
                    if matches!(cmd, XRefCommands::Delete(_)) { "xref_delete" } else { "xref_set_primary" },
                    Some(json!({"from": args.from, "to": args.to, "operand_index": args.operand_index,
                        "source": args.source.to_ascii_uppercase()})),
                ),
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
        Commands::Equate(cmd) => match cmd {
            cli::EquateCommands::List(_) => client.send_command("equate_list", None),
            cli::EquateCommands::Get(args) => client.send_command("equate_get", Some(json!({"name": args.name}))),
            cli::EquateCommands::Create(args) => client.send_command(
                "equate_create", Some(json!({"name": args.name, "value": args.value})),
            ),
            cli::EquateCommands::Attach(args) | cli::EquateCommands::Detach(args) => client.send_command(
                if matches!(cmd, cli::EquateCommands::Attach(_)) { "equate_attach" } else { "equate_detach" },
                Some(json!({"address": args.address, "name": args.name, "operand_index": args.operand_index})),
            ),
            cli::EquateCommands::Delete(args) => client.send_command("equate_delete", Some(json!({"name": args.name}))),
        },
        Commands::Namespace(cmd) => match cmd {
            cli::NamespaceCommands::List(_) => client.send_command("namespace_list", None),
            cli::NamespaceCommands::Get(args) => client.send_command("namespace_get", Some(json!({"path": args.path}))),
            cli::NamespaceCommands::Create(args) => client.send_command(
                "namespace_create", Some(json!({"name": args.name, "parent": args.parent, "kind": args.kind})),
            ),
        },
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
                TypeCommands::Clone(args) => client.send_command(
                    "type_clone",
                    Some(json!({"type_name": args.type_name, "new_name": args.new_name,
                        "category": args.category})),
                ),
                TypeCommands::Move(args) => client.send_command(
                    "type_move",
                    Some(json!({"type_name": args.type_name, "category": args.category})),
                ),
                TypeCommands::Category(cmd) => match cmd {
                    cli::TypeCategoryCommands::List(args) => client.send_command(
                        "type_category_list", Some(json!({"path": args.path})),
                    ),
                    cli::TypeCategoryCommands::Create(args) => client.send_command(
                        "type_category_create", Some(json!({"path": args.path})),
                    ),
                    cli::TypeCategoryCommands::Delete(args) => client.send_command(
                        "type_category_delete", Some(json!({"path": args.path})),
                    ),
                },
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
                TagCommands::Attach(args) => client.send_command(
                    "tag_attach",
                    Some(json!({
                        "function": args.target,
                        "tags": args.tags,
                    })),
                ),
                TagCommands::Detach(args) => client.send_command(
                    "tag_detach",
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
            cli::BookmarkCommands::Set(args) => client.send_command(
                "bookmark_set", Some(json!({"address": args.address, "type": args.bookmark_type,
                    "category": args.category,
                    "text": resolve_annotation_text(&args.text, args.stdin, args.text_file.as_deref(), "bookmark text")?})),
            ),
            cli::BookmarkCommands::Delete(args) => client.send_command(
                "bookmark_delete", Some(json!({"address": args.address, "type": args.bookmark_type,
                    "category": args.category})),
            ),
        },
        Commands::Comment(cmd) => {
            use cli::CommentCommands;
            match cmd {
                CommentCommands::List(_) => {
                    client.comment_list(list_limit, fetch.filter.as_deref(), fetch.offset)
                }
                CommentCommands::Get(args) => client.comment_get(&args.address),
                CommentCommands::Set(args) => {
                    let text = resolve_annotation_text(&args.text, args.stdin, args.text_file.as_deref(), "comment text")?;
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
            cli::ListingCommands::Flow(cmd) => match cmd {
                cli::ListingFlowCommands::Get(args) => client.send_command(
                    "listing_flow_get", Some(json!({"address": args.address})),
                ),
                cli::ListingFlowCommands::Set(args) => client.send_command(
                    "listing_flow_set", Some(json!({"address": args.address, "override": args.flow_override,
                        "fallthrough": args.fallthrough, "no_fallthrough": args.no_fallthrough})),
                ),
                cli::ListingFlowCommands::Clear(args) => client.send_command(
                    "listing_flow_clear", Some(json!({"address": args.address, "override": args.flow_override,
                        "fallthrough": args.fallthrough})),
                ),
            },
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
