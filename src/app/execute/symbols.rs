//! Symbol dispatch and guarded target selection shared by both rename spellings.

use crate::app::output::describe_query_error;
use crate::cli::{RenameArgs, SymbolCommands};
use crate::filter;
use crate::ipc::client::BridgeClient;

pub(super) fn execute(
    client: &BridgeClient,
    cmd: &SymbolCommands,
    list_limit: Option<usize>,
) -> anyhow::Result<serde_json::Value> {
    match cmd {
        SymbolCommands::List(_) => client.symbol_list(list_limit, None),
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
        SymbolCommands::Rename(args) => rename(client, args),
    }
}

pub(super) fn rename(
    client: &BridgeClient,
    args: &RenameArgs,
) -> anyhow::Result<serde_json::Value> {
    let addresses = resolve_symbol_addresses(
        client,
        &args.old_name,
        args.address.as_deref(),
        args.filter.as_deref(),
        args.all,
    )?;
    client.symbol_rename(&args.old_name, &args.new_name, &addresses)
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
