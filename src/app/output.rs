use super::options::extract_query_options;
use crate::cli::{self, Cli, Commands};
use crate::error::GhidraError;
use crate::format::{auto_detect_format, DefaultFormatter, Formatter, OutputFormat};
use crate::query::Query;
use std::io::IsTerminal;

/// Make filter parse failures actionable: the DSL needs a field and operator,
/// so a bare word like `PK` is invalid (use `name~PK` instead).
pub(super) fn describe_query_error(err: GhidraError) -> anyhow::Error {
    match &err {
        GhidraError::FilterParseError(_) | GhidraError::InvalidFilter(_) => anyhow::anyhow!(err)
            .context(
                "invalid --filter expression: expected <field><operator><value>, \
                 e.g. --filter 'name~PK' (contains), --filter 'name=~\"^PK_\"' (regex), \
                 --filter 'size>100'; combine with AND/OR/NOT",
            ),
        _ => anyhow::anyhow!(err),
    }
}

/// Check if a decompile result looks like .NET managed code and warn the user.
fn check_dotnet_decompile_warning(command: &Commands, result: &serde_json::Value) {
    let is_decompile = matches!(
        command,
        Commands::Decompile(_) | Commands::Function(cli::FunctionCommands::Decompile(_))
    );
    if !is_decompile {
        return;
    }

    if let Some(code) = result.get("code").and_then(|c| c.as_str()) {
        if code.contains("halt_baddata()") || code.contains(".NET CLR Managed Code") {
            eprintln!(
                "Warning: This appears to be .NET managed code. Ghidra cannot decompile .NET IL bytecode.\n\
                 Consider using a .NET decompiler (e.g., ilspy-cli) for better results."
            );
        }
    }
}

/// Unwrap bridge response envelopes into a flat array of objects.
///
/// Bridge returns envelopes like `{"count": N, "functions": [...]}`.
/// This extracts the inner array so formatters can render individual items.
fn unwrap_bridge_response(value: serde_json::Value) -> Vec<serde_json::Value> {
    // Already an array - return as-is
    if let serde_json::Value::Array(arr) = &value {
        return arr.clone();
    }

    // Must be an object to unwrap
    let obj = match value {
        serde_json::Value::Object(ref map) => map,
        other => return vec![other],
    };

    // Known array keys from bridge responses
    const ARRAY_KEYS: &[&str] = &[
        "functions",
        "strings",
        "imports",
        "exports",
        "blocks",
        "xrefs",
        "results",
        "programs",
        "types",
        "tags",
        "comments",
        "symbols",
        "callers",
        "callees",
        "calls",
        "instructions",
        "sections",
        "references",
    ];

    // Metadata keys that accompany array keys (not data themselves)
    const META_KEYS: &[&str] = &[
        "count",
        "target",
        "function",
        "command",
        "status",
        "current_program_name",
        "has_current_program",
        "data",
    ];

    // Special case: decompile responses have a "code" key - return as-is for special rendering
    if obj.contains_key("code") {
        return vec![value];
    }

    // Look for a known array key
    for &key in ARRAY_KEYS {
        if let Some(serde_json::Value::Array(arr)) = obj.get(key) {
            // Verify remaining keys are metadata
            let all_meta = obj
                .keys()
                .all(|k| k == key || META_KEYS.contains(&k.as_str()));
            if all_meta {
                return arr.clone();
            }
        }
    }

    // No known array key found - return as single-item vec
    vec![value]
}

pub(super) fn print_result(cli: &Cli, result: serde_json::Value) -> anyhow::Result<()> {
    // Check for .NET decompilation and warn
    if !cli.quiet {
        check_dotnet_decompile_warning(&cli.command, &result);
    }

    // Determine output format: explicit -o flag > --json/--pretty > TTY detection
    let opts = extract_query_options(&cli.command);
    let explicit_format = opts
        .as_ref()
        .and_then(|o| o.format.as_ref())
        .map(|f| OutputFormat::from_str(f))
        .transpose()
        .ok()
        .flatten();

    let format = if let Some(fmt) = explicit_format {
        fmt
    } else if cli.pretty {
        OutputFormat::Json
    } else if cli.json || opts.as_ref().is_some_and(|o| o.json) {
        OutputFormat::JsonCompact
    } else {
        auto_detect_format(std::io::stdout().is_terminal())
    };

    // Unwrap bridge response envelopes before formatting
    let values = unwrap_bridge_response(result);

    // Apply Rust-side query processing (filter, fields, sort) if QueryOptions are present.
    // A parse error (e.g. malformed --filter) must abort: falling through to the
    // default formatter would dump the entire unfiltered dataset (TODO.md Bug 2).
    if let Some(opts) = &opts {
        if let Some(query) = Query::from_options(opts, format).map_err(describe_query_error)? {
            let output = query.process_results(values)?;
            if !output.is_empty() {
                println!("{}", output);
            }
            return Ok(());
        }
    }

    let formatter = DefaultFormatter;
    let output = formatter.format(&values, format)?;
    if !output.is_empty() {
        println!("{}", output);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter;

    #[test]
    fn describe_query_error_mentions_filter_usage() {
        // Regression (TODO.md Bug 2): a bare word is not a valid filter and the
        // error must surface (previously swallowed, dumping the whole dataset).
        let Err(err) = filter::Filter::parse("PK") else {
            panic!("bare word must not parse");
        };
        let msg = format!("{:#}", describe_query_error(err));
        assert!(msg.contains("invalid --filter expression"), "got: {msg}");
    }
}
