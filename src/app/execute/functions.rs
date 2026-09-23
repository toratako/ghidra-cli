//! Function dispatch and guarded decompiler-variable selection.

use crate::cli::{self, FunctionCommands};
use crate::ipc::client::BridgeClient;
use anyhow::Context;
use serde_json::{json, Value};

pub(super) fn execute(
    client: &BridgeClient,
    cmd: &FunctionCommands,
    fetch: &crate::query::FetchParams,
) -> anyhow::Result<Value> {
    let list_limit = fetch.limit;
    match cmd {
        FunctionCommands::Tag(cmd) => {
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
        FunctionCommands::List(args) => client.list_functions(
            list_limit,
            fetch.filter.clone(),
            &args.tags,
            args.untagged,
            fetch.offset,
        ),
        FunctionCommands::Get(args) => client.send_command(
            "get_function",
            Some(json!({
                "address": args.target,
                "with_signature": args.with_signature,
                "with_frame": args.with_frame,
            })),
        ),
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
        FunctionCommands::SetBody(args) => client.send_command(
            "function_set_body",
            Some(
                json!({"target": args.target, "ranges": args.ranges.as_chunks::<2>().0.iter()
                .map(|range| json!({"start": range[0], "end": range[1]})).collect::<Vec<_>>()}),
            ),
        ),
        FunctionCommands::SetThunk(args) => client.send_command(
            "function_set_thunk",
            Some(json!({"target": args.target, "thunk_target": args.thunk_target})),
        ),
        FunctionCommands::ClearThunk(args) => {
            client.send_command("function_clear_thunk", Some(json!({"target": args.target})))
        }
        FunctionCommands::CallSignature(cmd) => match cmd {
            cli::CallSignatureCommands::Get(args) => client.send_command(
                "function_call_signature_get",
                Some(json!({"target": args.target, "at": args.at})),
            ),
            cli::CallSignatureCommands::Set(args) => client.send_command(
                "function_call_signature_set",
                Some(json!({"target": args.target, "at": args.at,
                    "signature": args.signature, "convention": args.convention})),
            ),
            cli::CallSignatureCommands::Clear(args) => client.send_command(
                "function_call_signature_clear",
                Some(json!({"target": args.target, "at": args.at})),
            ),
        },
        FunctionCommands::Var(cmd) => match cmd {
            cli::FunctionVarCommands::List(args) => client.function_var_list(&args.target),
            cli::FunctionVarCommands::InferStruct(args) => {
                let selection = resolve_variable(client, &args.selection)?;
                client.function_var_infer_struct(
                    &args.selection.target,
                    &args.selection.var_name,
                    selection.as_ref(),
                    args.with_accesses,
                    args.max_accesses,
                )
            }
            cli::FunctionVarCommands::Get(args) => {
                let selection = resolve_variable(client, &args.selection)?;
                client.function_var_get(
                    &args.selection.target,
                    &args.selection.var_name,
                    selection.as_ref(),
                )
            }
            cli::FunctionVarCommands::Set(args) => {
                let selection = resolve_variable(client, &args.selection)?;
                client.function_var_set(
                    &args.selection.target,
                    &args.selection.var_name,
                    selection.as_ref(),
                    args.new_name.as_deref(),
                    args.type_name.as_deref(),
                )
            }
        },
        FunctionCommands::SetNoReturn(args) => {
            client.function_set_noreturn(&args.target, args.value)
        }
        FunctionCommands::SetStackPurge(args) => client.send_command(
            "function_set_stack_purge",
            Some(json!({"target": args.target, "bytes": args.bytes, "unknown": args.unknown})),
        ),
    }
}

/// A --where expression selects from the full list, before any output projection or limit.
/// The bridge revalidates this snapshot; stale selections are never replayed.
fn resolve_variable(
    client: &BridgeClient,
    selection: &cli::FunctionVarSelection,
) -> anyhow::Result<Option<Value>> {
    let Some(expression) = selection.where_expr.as_deref() else {
        return Ok(None);
    };
    let filter = crate::filter::Filter::parse(expression)
        .map_err(crate::app::output::describe_selector_error)?;
    let response = client.function_var_list(&selection.target)?;
    let rows = response["variables"]
        .as_array()
        .context("Missing variable list rows")?;
    let mut matches = Vec::new();
    for row in rows {
        if row["name"].as_str() == Some(selection.var_name.as_str())
            && filter
                .evaluate(row)
                .map_err(crate::app::output::describe_selector_error)?
        {
            matches.push(row);
        }
    }
    anyhow::ensure!(
        !matches.is_empty(),
        "No variable named '{}' matches --where '{}'",
        selection.var_name,
        expression
    );
    anyhow::ensure!(
        matches.len() == 1,
        "Variable '{}' matches {} candidates: {}. Use a narrower --where to select one",
        selection.var_name,
        matches.len(),
        serde_json::to_string(&matches)?
    );
    let context = |key: &str| -> anyhow::Result<&str> {
        response[key]
            .as_str()
            .with_context(|| format!("Missing variable selection context: {key}"))
    };
    Ok(Some(json!({
        "program": context("program")?,
        "function_address": context("address")?,
        "modification": context("modification")?,
        "variable": matches[0],
    })))
}
