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
    fn normalize_component(value: &str) -> Option<&str> {
        let value = value
            .strip_prefix("0x")
            .or_else(|| value.strip_prefix("0X"))
            .unwrap_or(value);
        if value.is_empty() || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let value = value.trim_start_matches('0');
        Some(if value.is_empty() { "0" } else { value })
    }
    let Some(actual) = symbol.get("address").and_then(|v| v.as_str()) else {
        return false;
    };
    let Some(space) = symbol.get("address_space").and_then(|v| v.as_str()) else {
        return false;
    };
    // Strip only the known space name: remaining colons belong to a segmented
    // address and every segment must participate in the comparison.
    let prefix = format!("{space}:");
    let requested = requested.trim();
    let requested = match requested.strip_prefix(&prefix) {
        Some(address) => address,
        None if symbol
            .get("is_default_address_space")
            .and_then(|v| v.as_bool())
            == Some(true) =>
        {
            requested
        }
        None => return false,
    };
    let actual = actual.trim().strip_prefix(&prefix).unwrap_or(actual.trim());
    let requested_parts: Option<Vec<_>> = requested.split(':').map(normalize_component).collect();
    let actual_parts: Option<Vec<_>> = actual.split(':').map(normalize_component).collect();
    match (requested_parts, actual_parts) {
        (Some(requested), Some(actual)) => {
            requested.len() == actual.len()
                && requested
                    .iter()
                    .zip(actual)
                    .all(|(requested, actual)| requested.eq_ignore_ascii_case(actual))
        }
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
            json!({"address":"0040AB00", "address_space":"ram", "is_default_address_space":true});
        for spelling in [
            "40ab00",
            "0x40ab00",
            "0X0040AB00",
            "000040ab00",
            "ram:0x40ab00",
        ] {
            assert!(address_matches(&ram, spelling), "{spelling}");
        }
        for spelling in ["EXTERNAL:0040ab00", "RAM:0040ab00", "0x", "40ab00z"] {
            assert!(!address_matches(&ram, spelling), "{spelling}");
        }
        let external = json!({"address":"EXTERNAL:00000100", "address_space":"EXTERNAL", "is_default_address_space":false});
        assert!(address_matches(&external, "EXTERNAL:0X100"));
        assert!(!address_matches(&external, "100"));
        assert!(!address_matches(&external, "ram:100"));
    }

    #[test]
    fn segmented_addresses_preserve_segment_and_space() {
        let segmented =
            json!({"address":"1234:00AB", "address_space":"ram", "is_default_address_space":true});
        for spelling in ["1234:ab", "0X001234:0x00ab", "ram:1234:00AB"] {
            assert!(address_matches(&segmented, spelling), "{spelling}");
        }
        for spelling in ["ab", "5678:ab", "other:1234:ab", "ram:5678:ab", "1234::ab"] {
            assert!(!address_matches(&segmented, spelling), "{spelling}");
        }
        let overlay = json!({"address":"overlay:1234:00AB", "address_space":"overlay", "is_default_address_space":false});
        assert!(address_matches(&overlay, "overlay:001234:0XAB"));
        assert!(!address_matches(&overlay, "1234:ab"));
        assert!(!address_matches(&overlay, "overlay:5678:ab"));
        assert!(!address_matches(&overlay, "ram:1234:ab"));
    }
}
