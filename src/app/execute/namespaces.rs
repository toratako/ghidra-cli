//! Namespace dispatch and guarded selection independent of display queries.

use crate::cli::NamespaceCommands;
use crate::ipc::client::BridgeClient;
use anyhow::Context;
use serde_json::{json, Value};

pub(super) fn execute(client: &BridgeClient, command: &NamespaceCommands) -> anyhow::Result<Value> {
    match command {
        NamespaceCommands::List(_) => client.send_command("namespace_list", None),
        NamespaceCommands::Get(args) => {
            client.send_command("namespace_get", Some(json!({"path": args.path})))
        }
        NamespaceCommands::Create(args) => client.send_command(
            "namespace_create",
            Some(json!({"name": args.name, "parent": args.parent, "kind": args.kind})),
        ),
        NamespaceCommands::Rename(args) => {
            let target = resolve_target(
                client,
                &args.selection.path,
                args.selection.where_expr.as_deref(),
            )?;
            client.send_command(
                "namespace_rename",
                Some(json!({"target": target, "new_name": args.new_name})),
            )
        }
        NamespaceCommands::Move(args) => {
            let target = resolve_target(
                client,
                &args.selection.path,
                args.selection.where_expr.as_deref(),
            )?;
            let parent = args
                .parent
                .as_deref()
                .map(|path| resolve_target(client, path, None).with_context(|| format!("Cannot resolve destination parent '{path}'; --where selects only the namespace being moved")))
                .transpose()?;
            client.send_command(
                "namespace_move",
                Some(json!({"target": target, "parent": parent})),
            )
        }
        NamespaceCommands::Delete(args) => {
            let target = resolve_target(
                client,
                &args.selection.path,
                args.selection.where_expr.as_deref(),
            )?;
            client.send_command(
                "namespace_delete",
                Some(json!({"target": target, "recursive": args.recursive})),
            )
        }
    }
}

fn resolve_target(
    client: &BridgeClient,
    path: &str,
    where_expr: Option<&str>,
) -> anyhow::Result<Value> {
    let predicate = super::symbols::parse_selector(None, where_expr)?;
    let response = client.send_command("namespace_list", None)?;
    let rows = response["namespaces"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("Bridge did not return namespace candidates"))?;
    let mut candidates: Vec<_> = rows
        .iter()
        .filter(|row| row["path"].as_str() == Some(path))
        .collect();
    anyhow::ensure!(!candidates.is_empty(), "Namespace not found: {path}");
    if let Some((expression, predicate)) = where_expr.zip(predicate) {
        candidates.retain(|row| predicate.evaluate(row).unwrap_or(false));
        anyhow::ensure!(
            !candidates.is_empty(),
            "No namespace at '{path}' matches --where '{}'",
            expression
        );
    }
    if candidates.len() != 1 {
        let details = candidates
            .iter()
            .map(|row| {
                format!(
                    "id={}, kind={}",
                    row["id"].as_str().unwrap_or("?"),
                    row["kind"].as_str().unwrap_or("?")
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        anyhow::bail!(
            "'{path}' matches {} namespaces [{details}] -- use a narrower --where to select one",
            candidates.len()
        );
    }
    let target = candidates[0];
    anyhow::ensure!(
        target["id"].as_str().is_some(),
        "Bridge did not return a stable namespace ID"
    );
    Ok(target.clone())
}
