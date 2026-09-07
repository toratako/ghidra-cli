use super::output::describe_query_error;
use crate::cli::{self, Cli, Commands};
use crate::filter;
use crate::ipc::client::BridgeClient;
use clap::Parser;

/// Parse a `--expect` spec (`PATH` or `PATH:MIN_ROWS`) into the wire form
/// `{path, min_rows?}`. The path is made absolute against the *client's* CWD so
/// the bridge validates the same file the script wrote, regardless of the CWD
/// the bridge JVM inherited. A trailing `:<digits>` is treated as MIN_ROWS;
/// anything else (e.g. a Windows drive letter) stays part of the path.
fn parse_expect_spec(spec: &str) -> serde_json::Value {
    let (path_part, min_rows) = match spec.rsplit_once(':') {
        Some((p, n)) if !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()) => {
            (p, n.parse::<u64>().ok())
        }
        _ => (spec, None),
    };
    let abs = std::path::absolute(path_part)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| path_part.to_string());
    let mut obj = serde_json::Map::new();
    obj.insert("path".to_string(), serde_json::Value::String(abs));
    if let Some(n) = min_rows {
        obj.insert("min_rows".to_string(), serde_json::json!(n));
    }
    serde_json::Value::Object(obj)
}

/// Resolve `comment set`'s text from `--stdin`, `--text-file`, or the TEXT
/// positional (in that priority order; clap already rejects combining them).
/// Reading from stdin/a file bypasses the shell entirely, so callers building
/// comment text programmatically never risk the metacharacter-expansion
/// corruption a shell argument is exposed to (e.g. backticks silently running
/// as command substitution before ghidra-cli ever sees the string).
fn resolve_comment_text(args: &cli::CommentSetArgs) -> anyhow::Result<String> {
    if args.stdin {
        let mut buf = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)?;
        Ok(buf)
    } else if let Some(path) = &args.text_file {
        std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Failed to read --text-file {}: {}", path.display(), e))
    } else {
        args.text
            .clone()
            .ok_or_else(|| anyhow::anyhow!("TEXT argument required (or use --stdin / --text-file)"))
    }
}

/// The bridge's list handlers only support a literal substring match on the
/// primary name field, not the full filter DSL implemented client-side in
/// `query::Filter`. When a full filter expression, sort, or count is requested,
/// fetch the complete dataset (no server-side limit/filter) so Rust-side query
/// processing can filter, sort, and paginate correctly.
fn bridge_list_params(
    limit: Option<usize>,
    filter: Option<String>,
    sort: Option<&str>,
    count: bool,
    offset: Option<usize>,
    default_limit: Option<usize>,
) -> (Option<usize>, Option<String>) {
    if filter.is_some() || sort.is_some() || count || offset.is_some() {
        (None, None)
    } else {
        // `--limit 0` means "all rows": suppress both the explicit limit and
        // the config default. Omitting --limit still applies default_limit.
        let limit = match limit {
            Some(0) => None,
            Some(n) => Some(n),
            None => default_limit,
        };
        (limit, filter)
    }
}

/// Resolve which address(es) a symbol mutation (`symbol rename`/`symbol
/// delete`) should touch, given the caller's optional `--address`/`--filter`
/// disambiguators and `--all` opt-in.
///
/// Ghidra auto-generates names (`caseD_XX`, `LAB_XXXX`, ...) that are
/// routinely reused across unrelated addresses program-wide, so a bare name
/// is never a safe mutation target on its own: without this, `symbol
/// rename`/`symbol delete` would silently touch every symbol sharing that
/// name, not just the one address the caller meant. Returns the exact
/// addresses to pass to the bridge; the bridge enforces the same guard
/// independently as a second line of defense.
fn resolve_symbol_addresses(
    client: &BridgeClient,
    name: &str,
    address: Option<&str>,
    filter_expr: Option<&str>,
    all: bool,
) -> anyhow::Result<Vec<String>> {
    let response = client.symbol_get(name)?;
    let mut candidates: Vec<serde_json::Value> = response
        .get("symbols")
        .and_then(|s| s.as_array())
        .cloned()
        .unwrap_or_default();

    if candidates.is_empty() {
        anyhow::bail!("Symbol not found: {}", name);
    }

    if let Some(addr) = address {
        let normalized = addr
            .trim()
            .to_lowercase()
            .trim_start_matches("0x")
            .to_string();
        candidates.retain(|s| {
            s.get("address")
                .and_then(|a| a.as_str())
                .map(|a| a.trim_start_matches("0x").eq_ignore_ascii_case(&normalized))
                .unwrap_or(false)
        });
        if candidates.is_empty() {
            anyhow::bail!("No symbol named '{}' at address {}", name, addr);
        }
    }

    if let Some(expr) = filter_expr {
        let parsed = filter::Filter::parse(expr).map_err(describe_query_error)?;
        candidates.retain(|s| parsed.evaluate(s).unwrap_or(false));
        if candidates.is_empty() {
            anyhow::bail!("No symbol named '{}' matches filter '{}'", name, expr);
        }
    }

    if candidates.len() > 1 && !all {
        let addrs: Vec<String> = candidates
            .iter()
            .map(|s| {
                s.get("address")
                    .and_then(|a| a.as_str())
                    .unwrap_or("?")
                    .to_string()
            })
            .collect();
        anyhow::bail!(
            "'{}' matches {} symbols at addresses [{}] -- pass --address <ADDR> (or a narrower \
             --filter) to pick one, or --all to affect every match",
            name,
            candidates.len(),
            addrs.join(", ")
        );
    }

    Ok(candidates
        .into_iter()
        .filter_map(|s| {
            s.get("address")
                .and_then(|a| a.as_str())
                .map(|s| s.to_string())
        })
        .collect())
}

/// Execute a command via the bridge client.
pub(super) fn execute_via_bridge(
    client: &BridgeClient,
    command: &Commands,
    quiet: bool,
    default_limit: Option<usize>,
) -> anyhow::Result<serde_json::Value> {
    use serde_json::json;

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
        Commands::Query(args) => match args.data_type.as_str() {
            "functions" => {
                let (lim, filt) = bridge_list_params(
                    args.limit,
                    args.filter.clone(),
                    args.sort.as_deref(),
                    args.count,
                    args.offset,
                    default_limit,
                );
                client.list_functions(lim, filt, &[], false)
            }
            "strings" => {
                let (lim, filt) = bridge_list_params(
                    args.limit,
                    args.filter.clone(),
                    args.sort.as_deref(),
                    args.count,
                    args.offset,
                    default_limit,
                );
                client.list_strings(lim, filt)
            }
            "imports" => client.list_imports(args.limit.or(default_limit)),
            "exports" => client.list_exports(args.limit.or(default_limit)),
            "memory" => client.memory_map(),
            other => anyhow::bail!("Query type '{}' not supported", other),
        },
        Commands::Decompile(args) => client.decompile(
            args.resolved_target().to_string(),
            args.with_vars,
            args.with_params,
        ),
        Commands::Function(cmd) => {
            use cli::FunctionCommands;
            match cmd {
                FunctionCommands::List(args) => {
                    let (lim, filt) = bridge_list_params(
                        args.options.limit,
                        args.options.filter.clone(),
                        args.options.sort.as_deref(),
                        args.options.count,
                        args.options.offset,
                        default_limit,
                    );
                    client.list_functions(lim, filt, &args.tags, args.untagged)
                }
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
                FunctionCommands::Calls(args) => client.find_calls(args.resolved_target()),
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
                FunctionCommands::SetVarType(args) => client.send_command(
                    "set_var_type",
                    Some(json!({
                        "function": args.resolved_target(),
                        "var_name": args.var_name,
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
                StringsCommands::List(opts) => {
                    let (lim, filt) = bridge_list_params(
                        opts.limit,
                        opts.filter.clone(),
                        opts.sort.as_deref(),
                        opts.count,
                        opts.offset,
                        default_limit,
                    );
                    client.list_strings(lim, filt)
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
                MemoryCommands::Write(args) => client.send_command(
                    "write_memory",
                    Some(json!({
                        "address": args.address,
                        "bytes": args.bytes,
                    })),
                ),
                MemoryCommands::Search(args) => client.send_command(
                    "search_memory",
                    Some(json!({
                        "pattern": args.pattern,
                    })),
                ),
            }
        }
        Commands::Dump(cmd) => {
            use cli::DumpCommands;
            match cmd {
                DumpCommands::Imports(opts) => client.list_imports(opts.limit.or(default_limit)),
                DumpCommands::Exports(opts) => client.list_exports(opts.limit.or(default_limit)),
                DumpCommands::Functions(opts) => {
                    let (lim, filt) = bridge_list_params(
                        opts.limit,
                        opts.filter.clone(),
                        opts.sort.as_deref(),
                        opts.count,
                        opts.offset,
                        default_limit,
                    );
                    client.list_functions(lim, filt, &[], false)
                }
                DumpCommands::Strings(opts) => {
                    let (lim, filt) = bridge_list_params(
                        opts.limit,
                        opts.filter.clone(),
                        opts.sort.as_deref(),
                        opts.count,
                        opts.offset,
                        default_limit,
                    );
                    client.list_strings(lim, filt)
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
                    client.program_export(&args.format, args.output.as_deref())
                }
                // ProgramCommands::Save is intercepted in `run_command` before
                // reaching here: saving means stopping and restarting the
                // bridge (see `handle_program_save`), not a single request to
                // an already-running one.
                ProgramCommands::Save(_) => unreachable!(
                    "program save is handled by handle_program_save before run_with_bridge"
                ),
            }
        }
        Commands::Symbol(cmd) => {
            use cli::SymbolCommands;
            match cmd {
                SymbolCommands::List(opts) => {
                    let (lim, filt) = bridge_list_params(
                        opts.limit,
                        opts.filter.clone(),
                        opts.sort.as_deref(),
                        opts.count,
                        opts.offset,
                        default_limit,
                    );
                    client.symbol_list(lim, filt.as_deref())
                }
                SymbolCommands::Get(args) => client.symbol_get(&args.name),
                SymbolCommands::Create(args) => client.symbol_create(&args.address, &args.name),
                SymbolCommands::Delete(args) => {
                    let addresses = resolve_symbol_addresses(
                        client,
                        &args.name,
                        args.address.as_deref(),
                        args.options.filter.as_deref(),
                        args.all,
                    )?;
                    client.symbol_delete(&args.name, &addresses)
                }
                SymbolCommands::Rename(args) => {
                    let addresses = resolve_symbol_addresses(
                        client,
                        &args.old_name,
                        args.address.as_deref(),
                        args.filter.as_deref(),
                        args.all,
                    )?;
                    client.symbol_rename(&args.old_name, &args.new_name, &addresses)
                }
            }
        }
        Commands::Type(cmd) => {
            use cli::TypeCommands;
            match cmd {
                TypeCommands::List(opts) => {
                    let (lim, filt) = bridge_list_params(
                        opts.limit,
                        opts.filter.clone(),
                        opts.sort.as_deref(),
                        opts.count,
                        opts.offset,
                        default_limit,
                    );
                    client.type_list(lim, filt.as_deref())
                }
                TypeCommands::Get(args) => client.type_get(&args.name),
                TypeCommands::Create(args) => client.type_create(&args.definition),
                TypeCommands::Apply(args) => {
                    client.type_apply_force(&args.address, &args.type_name, args.force)
                }
                TypeCommands::ImportC(args) => {
                    client.type_import_c(&args.code, args.category.as_deref())
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
                TagCommands::List(args) => {
                    let (lim, _) = bridge_list_params(
                        args.options.limit,
                        args.options.filter.clone(),
                        args.options.sort.as_deref(),
                        args.options.count,
                        args.options.offset,
                        default_limit,
                    );
                    client.tag_list(lim, args.function.as_deref())
                }
                TagCommands::Get(args) => {
                    let (lim, _) = bridge_list_params(
                        args.options.limit,
                        args.options.filter.clone(),
                        args.options.sort.as_deref(),
                        args.options.count,
                        args.options.offset,
                        default_limit,
                    );
                    client.tag_get(&args.name, lim)
                }
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
                CommentCommands::List(opts) => {
                    let (lim, filt) = bridge_list_params(
                        opts.limit,
                        opts.filter.clone(),
                        opts.sort.as_deref(),
                        opts.count,
                        opts.offset,
                        default_limit,
                    );
                    client.comment_list(lim, filt.as_deref())
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
                GraphCommands::Calls(opts) => client.graph_calls(opts.limit.or(default_limit)),
                GraphCommands::Callers(args) => {
                    let (limit, _) = bridge_list_params(
                        args.options.limit,
                        args.options.filter.clone(),
                        args.options.sort.as_deref(),
                        args.options.count,
                        args.options.offset,
                        default_limit,
                    );
                    client.graph_callers(args.resolved_target(), args.depth, limit)
                }
                GraphCommands::Callees(args) => {
                    let (limit, _) = bridge_list_params(
                        args.options.limit,
                        args.options.filter.clone(),
                        args.options.sort.as_deref(),
                        args.options.count,
                        args.options.offset,
                        default_limit,
                    );
                    client.graph_callees(args.resolved_target(), args.depth, limit)
                }
                GraphCommands::Export(args) => client.graph_export(&args.format),
            }
        }
        Commands::Find(cmd) => {
            use cli::FindCommands;
            match cmd {
                FindCommands::String(args) => client.find_string(&args.pattern),
                FindCommands::Bytes(args) => client.find_bytes(&args.hex),
                FindCommands::Function(args) => client.find_function(&args.pattern),
                FindCommands::Calls(args) => client.find_calls(args.resolved_target()),
                FindCommands::Crypto(_) => client.find_crypto(),
                FindCommands::Interesting(_) => client.find_interesting(),
            }
        }
        Commands::Diff(cmd) => {
            use cli::DiffCommands;
            match cmd {
                DiffCommands::Programs(args) => {
                    client.diff_programs(&args.program1, &args.program2)
                }
                DiffCommands::Functions(args) => client.diff_functions(&args.func1, &args.func2),
            }
        }
        Commands::Patch(cmd) => {
            use cli::PatchCommands;
            match cmd {
                PatchCommands::Bytes(args) => client.patch_bytes(&args.address, &args.hex),
                PatchCommands::Nop(args) => client.patch_nop(&args.address, args.count),
                PatchCommands::Export(args) => client.patch_export(&args.output),
            }
        }
        Commands::Script(cmd) => {
            use cli::ScriptCommands;
            match cmd {
                ScriptCommands::Run(args) => {
                    let expect: Vec<serde_json::Value> =
                        args.expect.iter().map(|s| parse_expect_spec(s)).collect();
                    if args.script_path == "-" {
                        // Read a one-off script's Java source from stdin so a
                        // throwaway snippet doesn't need a checked-in file; the
                        // bridge stages it to a temp file and runs it through the
                        // same compile/execute path as `script run PATH`.
                        let mut source = String::new();
                        std::io::Read::read_to_string(&mut std::io::stdin(), &mut source)?;
                        client.script_run_source(&source, &args.args, &expect, args.allow_empty)
                    } else {
                        // Canonicalize client-side so the bridge receives an absolute
                        // path independent of the working directory its JVM inherited.
                        // Fall back to the raw path if the file is missing; the bridge
                        // then reports a clear "Script not found".
                        let path = std::fs::canonicalize(&args.script_path)
                            .map(|p| p.to_string_lossy().into_owned())
                            .unwrap_or_else(|_| args.script_path.clone());
                        client.script_run(&path, &args.args, &expect, args.allow_empty)
                    }
                }
                ScriptCommands::Python(args) => client.script_python(&args.code),
                ScriptCommands::Java(args) => client.script_java(&args.code),
                ScriptCommands::List => client.script_list(),
            }
        }
        Commands::Disasm(args) => client.disasm(args.resolved_target(), args.num_instructions),
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
        Commands::Batch(args) => {
            // Read batch file and execute each command locally
            let content = std::fs::read_to_string(&args.script_file)
                .map_err(|e| anyhow::anyhow!("Failed to read batch file: {}", e))?;
            let lines: Vec<&str> = content
                .lines()
                .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
                .collect();

            let mut results = Vec::new();
            for line in &lines {
                let words: Vec<&str> = std::iter::once("ghidra")
                    .chain(line.split_whitespace())
                    .collect();
                let sub_result = match Cli::try_parse_from(&words) {
                    Ok(sub_cli) => {
                        execute_via_bridge(client, &sub_cli.command, true, default_limit)
                    }
                    Err(e) => Err(anyhow::anyhow!("{}", e)),
                };
                match sub_result {
                    Ok(val) => results.push(json!({"command": line.trim(), "result": val})),
                    Err(e) => results.push(json!({"command": line.trim(), "error": e.to_string()})),
                }
            }

            Ok(json!({
                "commands_parsed": lines.len(),
                "results": results
            }))
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
        Commands::Rename(args) => {
            let addresses = resolve_symbol_addresses(
                client,
                &args.old_name,
                args.address.as_deref(),
                args.filter.as_deref(),
                args.all,
            )?;
            client.symbol_rename(&args.old_name, &args.new_name, &addresses)
        }
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

    #[test]
    fn bridge_list_params_limit_zero_means_unlimited() {
        // Regression (TODO.md Bug 1): --limit 0 must fetch all rows, not zero,
        // and must not fall back to the config default limit.
        let (limit, filter) = bridge_list_params(Some(0), None, None, false, None, Some(1000));
        assert_eq!(limit, None);
        assert_eq!(filter, None);
    }

    #[test]
    fn bridge_list_params_no_limit_uses_default() {
        let (limit, _) = bridge_list_params(None, None, None, false, None, Some(1000));
        assert_eq!(limit, Some(1000));
    }

    #[test]
    fn bridge_list_params_explicit_limit_wins() {
        let (limit, _) = bridge_list_params(Some(25), None, None, false, None, Some(1000));
        assert_eq!(limit, Some(25));
    }

    #[test]
    fn bridge_list_params_filter_fetches_full_dataset() {
        let (limit, filter) = bridge_list_params(
            Some(20),
            Some("name~PK".to_string()),
            None,
            false,
            None,
            Some(1000),
        );
        assert_eq!(limit, None);
        assert_eq!(filter, None);
    }
}
