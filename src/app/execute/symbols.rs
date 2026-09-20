//! Symbol dispatch and guarded target selection shared by both rename spellings.

use crate::address::ExplicitAddress;
use crate::app::output::describe_query_error;
use crate::cli::{RenameArgs, SymbolCommands};
use crate::filter;
use crate::ipc::client::BridgeClient;

pub(super) fn execute(
    client: &BridgeClient,
    cmd: &SymbolCommands,
    fetch: &crate::query::FetchParams,
) -> anyhow::Result<serde_json::Value> {
    match cmd {
        SymbolCommands::List(_) => {
            client.symbol_list(fetch.limit, fetch.filter.as_deref(), fetch.offset)
        }
        SymbolCommands::Externals(_) => client.symbol_externals(fetch.limit),
        SymbolCommands::EntryPoints(_) => client.symbol_entry_points(fetch.limit),
        SymbolCommands::Get(args) => client.symbol_get(&args.name),
        SymbolCommands::CreateLabel(args) => client.symbol_create_label(&args.address, &args.name),
        SymbolCommands::Delete(args) => {
            let targets = resolve_symbol_targets(
                client,
                &args.name,
                args.address.as_deref(),
                args.options.filter.as_deref(),
                args.all,
            )?;
            client.symbol_delete_targets(&args.name, &targets)
        }
        SymbolCommands::Rename(args) => rename(client, args),
    }
}

pub(super) fn rename(
    client: &BridgeClient,
    args: &RenameArgs,
) -> anyhow::Result<serde_json::Value> {
    let targets = resolve_symbol_targets(
        client,
        &args.old_name,
        args.address.as_deref(),
        args.filter.as_deref(),
        args.all,
    )?;
    client.symbol_rename_targets(&args.old_name, &args.new_name, &targets)
}

/// Resolve which address(es) a symbol mutation (`symbol rename`/`symbol
/// delete`) should touch, given the caller's optional `--address`/`--filter`
/// disambiguators and `--all` opt-in.
///
/// Ghidra auto-generates names (`caseD_XX`, `LAB_XXXX`, ...) that are
/// routinely reused across unrelated addresses program-wide, so a bare name
/// is never a safe mutation target on its own: without this, `symbol
/// rename`/`symbol delete` would silently touch every symbol sharing that
/// name, not just the one address the caller meant. Returns stable symbol snapshots
/// to pass to the bridge; the bridge enforces the same guard
/// independently as a second line of defense.
fn resolve_symbol_targets(
    client: &BridgeClient,
    name: &str,
    address: Option<&str>,
    filter_expr: Option<&str>,
    all: bool,
) -> anyhow::Result<Vec<serde_json::Value>> {
    if let Some(address) = address {
        anyhow::ensure!(
            ExplicitAddress::parse(address).is_some(),
            "Invalid --address '{}': use a 0x-prefixed address",
            address
        );
    }
    let response = client.symbol_get_by_name(name)?;
    let mut candidates: Vec<serde_json::Value> = response
        .get("symbols")
        .and_then(|s| s.as_array())
        .cloned()
        .unwrap_or_default();

    if candidates.is_empty() {
        anyhow::bail!("Symbol not found: {}", name);
    }

    if let Some(addr) = address {
        candidates.retain(|symbol| address_matches(symbol, addr));
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

    if candidates
        .iter()
        .any(|s| s.get("id").and_then(|id| id.as_str()).is_none())
    {
        anyhow::bail!(
            "Bridge did not return stable symbol IDs; restart the bridge before mutating symbols"
        );
    }
    Ok(candidates)
}

fn address_matches(symbol: &serde_json::Value, requested: &str) -> bool {
    let Some(actual) = symbol.get("address").and_then(|v| v.as_str()) else {
        return false;
    };
    let Some(space) = symbol.get("address_space").and_then(|v| v.as_str()) else {
        return false;
    };
    let is_default = symbol
        .get("is_default_address_space")
        .and_then(|v| v.as_bool())
        == Some(true);
    fn in_space<'a>(
        value: &'a str,
        space: &'a str,
        is_default: bool,
    ) -> Option<ExplicitAddress<'a>> {
        let prefix = format!("{space}:");
        let value = value.trim();
        let (value, qualified) = match value.strip_prefix(&prefix) {
            Some(offset) => (offset, true),
            None if is_default => (value, false),
            None => return None,
        };
        let mut address = ExplicitAddress::parse(value)?;
        // Without the program's space registry, two unqualified components
        // might name a different space instead of a segment. Canonical
        // segmented outputs always carry their space name; require it here.
        if address.space.is_some() || (!qualified && address.components.len() != 1) {
            return None;
        }
        address.space = Some(space);
        Some(address)
    }
    match (
        in_space(requested, space, is_default),
        in_space(actual, space, is_default),
    ) {
        (Some(requested), Some(actual)) => requested.same_location(&actual),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::address_matches;
    use serde_json::json;

    #[test]
    fn address_spellings_preserve_address_spaces() {
        let ram =
            json!({"address":"0x0040AB00", "address_space":"ram", "is_default_address_space":true});
        for spelling in ["0x40ab00", "0X0040AB00", "0x000040ab00", "ram:0x40ab00"] {
            assert!(address_matches(&ram, spelling), "{spelling}");
        }
        for spelling in [
            "40ab00",
            "000040ab00",
            "ram:40ab00",
            "EXTERNAL:0x0040ab00",
            "RAM:0x0040ab00",
            "0x",
            "0x40ab00z",
        ] {
            assert!(!address_matches(&ram, spelling), "{spelling}");
        }
        let external = json!({"address":"EXTERNAL:0x00000100", "address_space":"EXTERNAL", "is_default_address_space":false});
        assert!(address_matches(&external, "EXTERNAL:0X100"));
        for spelling in ["100", "0x100", "ram:0x100", "EXTERNAL:100"] {
            assert!(!address_matches(&external, spelling));
        }
    }

    #[test]
    fn segmented_addresses_preserve_segment_and_space() {
        let segmented = json!({"address":"ram:0x1234:0x00AB", "address_space":"ram", "is_default_address_space":true});
        for spelling in ["ram:0x1234:0xab", "ram:0X001234:0x00ab"] {
            assert!(address_matches(&segmented, spelling), "{spelling}");
        }
        for spelling in [
            "1234:ab",
            "0x1234:0xab",
            "0x1234:ab",
            "0xab",
            "0x5678:0xab",
            "other:0x1234:0xab",
            "0x1234::0xab",
        ] {
            assert!(!address_matches(&segmented, spelling), "{spelling}");
        }
        let overlay = json!({"address":"overlay:0x1234:0x00AB", "address_space":"overlay", "is_default_address_space":false});
        assert!(address_matches(&overlay, "overlay:0x001234:0XAB"));
        assert!(!address_matches(&overlay, "0x1234:0xab"));
        assert!(!address_matches(&overlay, "overlay:0x5678:0xab"));
        assert!(!address_matches(&overlay, "ram:0x1234:0xab"));
    }

    #[test]
    fn word_offsets_are_not_discarded() {
        let symbol = json!({"address":"word:0x0010.1", "address_space":"word", "is_default_address_space":false});
        assert!(address_matches(&symbol, "word:0X10.01"));
        assert!(!address_matches(&symbol, "word:0x10"));
        assert!(!address_matches(&symbol, "word:10.1"));
    }

    #[test]
    fn numeric_space_names_are_not_mistaken_for_segments() {
        let symbol = json!({"address":"0x1234:0x00000010", "address_space":"0x1234", "is_default_address_space":false});
        assert!(address_matches(&symbol, "0x1234:0X10"));
        assert!(!address_matches(&symbol, "0x10"));
        assert!(!address_matches(&symbol, "0x1234:0x20"));
        let segmented = json!({"address":"ram:0x1234:0x0010", "address_space":"ram", "is_default_address_space":true});
        assert!(!address_matches(&segmented, "0x1234:0x10"));
        assert!(address_matches(&segmented, "ram:0x1234:0x10"));
    }
}
