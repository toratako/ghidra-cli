use super::options::extract_query_options;
use super::CommandResult;
use crate::cli::{Cli, Commands};
use crate::error::GhidraError;
use crate::format::{auto_detect_format, DefaultFormatter, Formatter, OutputFormat};
use crate::query::Query;
use crate::terminal::write_stdout;
use serde::Serialize;
use std::collections::HashSet;
use std::io::{IsTerminal, Write};

#[derive(Clone, Copy)]
pub(crate) struct Output {
    pub json: bool,
    pub pretty: bool,
    pub quiet: bool,
}

impl Output {
    pub fn new(cli: &Cli) -> Self {
        let format = output_format(cli);
        Self {
            json: matches!(
                format,
                OutputFormat::Json | OutputFormat::JsonCompact | OutputFormat::JsonStream
            ),
            pretty: matches!(format, OutputFormat::Json),
            quiet: cli.quiet,
        }
    }

    pub fn result(&self, value: &impl Serialize, human: &str) -> anyhow::Result<()> {
        if self.json {
            write_stdout(&self.json_string(value)?)
        } else {
            write_stdout(human)
        }
    }

    pub fn json_string(&self, value: &impl Serialize) -> serde_json::Result<String> {
        if self.pretty {
            serde_json::to_string_pretty(value)
        } else {
            serde_json::to_string(value)
        }
    }

    pub fn progress(&self, message: &str) {
        if !self.quiet && !self.json {
            let _ = writeln!(std::io::stderr().lock(), "{message}");
        }
    }
}

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
    let is_decompile = matches!(command, Commands::Decompile(_));
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

/// Identify the same top-level row array for default limits and query output.
fn response_array_key(obj: &serde_json::Map<String, serde_json::Value>) -> Option<&'static str> {
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
        "pattern",
        "function",
        "command",
        "status",
        "current_program_name",
        "has_current_program",
        "data",
    ];

    if obj.contains_key("code") {
        return None;
    }
    ARRAY_KEYS.iter().copied().find(|key| {
        obj.get(*key).is_some_and(serde_json::Value::is_array)
            && obj
                .keys()
                .all(|k| k == key || META_KEYS.contains(&k.as_str()))
    })
}

/// Apply an unconsumed default cap without changing a batch response's shape.
pub(super) fn limit_response_rows(
    mut value: serde_json::Value,
    limit: Option<usize>,
) -> serde_json::Value {
    let Some(limit) = limit.filter(|&n| n != 0) else {
        return value;
    };
    if let Some(rows) = value.as_array_mut() {
        rows.truncate(limit);
    } else if let Some(obj) = value.as_object_mut() {
        if let Some(key) = response_array_key(obj) {
            let rows = obj.get_mut(key).unwrap().as_array_mut().unwrap();
            rows.truncate(limit);
            let count = rows.len();
            if obj.contains_key("count") {
                obj.insert("count".into(), serde_json::json!(count));
            }
        }
    }
    value
}

/// Extract a bridge envelope's row array for standalone or explicit query output.
fn unwrap_bridge_response(value: serde_json::Value) -> Vec<serde_json::Value> {
    match value {
        serde_json::Value::Array(rows) => rows,
        serde_json::Value::Object(mut obj) => {
            if let Some(key) = response_array_key(&obj) {
                if let Some(serde_json::Value::Array(rows)) = obj.remove(key) {
                    return rows;
                }
            }
            vec![serde_json::Value::Object(obj)]
        }
        other => vec![other],
    }
}

fn output_format(cli: &Cli) -> OutputFormat {
    // Error presentation must remain available when config cannot be loaded.
    // Command execution reports configuration errors through its normal path.
    let configured = crate::config::Config::load()
        .ok()
        .and_then(|config| config.default_output_format)
        .and_then(|format| format.parse::<OutputFormat>().ok());
    output_format_with_default(cli, configured)
}

fn output_format_with_default(cli: &Cli, configured: Option<OutputFormat>) -> OutputFormat {
    // Explicit -o > --json/--pretty > configured format > TTY detection.
    let opts = extract_query_options(&cli.command);
    let explicit_format = opts.as_ref().and_then(|o| o.format);

    if let Some(fmt) = explicit_format {
        fmt
    } else if cli.pretty {
        OutputFormat::Json
    } else if cli.json || opts.as_ref().is_some_and(|o| o.json) {
        OutputFormat::JsonCompact
    } else {
        configured.unwrap_or_else(|| auto_detect_format(std::io::stdout().is_terminal()))
    }
}

/// Batch and standalone output consume the residual query from the same plan.
/// Unmodified batch results retain their bridge envelope.
pub(super) fn process_batch_result(result: CommandResult) -> anyhow::Result<serde_json::Value> {
    if let Some(query) = result.query {
        let json = process_query_response(result.value, &query)?;
        return Ok(serde_json::from_str(&json)?);
    }
    Ok(result.value)
}

/// Graph queries select nodes while preserving the graph envelope and outgoing edges.
fn process_query_response(
    mut value: serde_json::Value,
    query: &Query,
) -> crate::error::Result<String> {
    if let (Some(nodes), Some(edges)) = (
        value.get("nodes").and_then(serde_json::Value::as_array),
        value.get("edges").and_then(serde_json::Value::as_array),
    ) {
        let nodes = query.select_rows(nodes.clone())?;
        if query.count_only {
            return Ok(nodes.len().to_string());
        }

        // Match the bridge's limit behavior: keep calls from selected nodes,
        // including destinations outside this page. Resolve IDs before --fields.
        let ids: HashSet<_> = nodes
            .iter()
            .filter_map(|node| node.get("id").and_then(serde_json::Value::as_str))
            .collect();
        let edges: Vec<_> = edges
            .iter()
            .filter(|edge| {
                edge.get("from")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|source| ids.contains(source))
            })
            .cloned()
            .collect();
        value["node_count"] = serde_json::json!(nodes.len());
        value["edge_count"] = serde_json::json!(edges.len());
        value["nodes"] = serde_json::Value::Array(if let Some(fields) = &query.fields {
            query.select_fields(&nodes, fields)?
        } else {
            nodes
        });
        value["edges"] = serde_json::Value::Array(edges);
        return DefaultFormatter.format(&[value], query.format);
    }
    query.process_results(unwrap_bridge_response(value))
}

pub(super) fn print_result(cli: &Cli, result: CommandResult) -> anyhow::Result<()> {
    if !cli.quiet {
        check_dotnet_decompile_warning(&cli.command, &result.value);
    }
    let format = output_format(cli);

    if let Some(mut query) = result.query {
        query.format = format;
        let output = process_query_response(result.value, &query)?;
        if !output.is_empty() {
            crate::terminal::write_stdout(&output)?;
        }
        return Ok(());
    }

    let formatter = DefaultFormatter;
    let output = formatter.format(&unwrap_bridge_response(result.value), format)?;
    if !output.is_empty() {
        crate::terminal::write_stdout(&output)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter;
    use clap::Parser;

    #[test]
    fn default_caps_keep_envelopes_and_do_not_trim_nested_object_fields() {
        use serde_json::json;
        let rows = json!([{"name":"first"}, {"name":"second"}, {"name":"third"}]);
        let envelope = json!({"results": rows, "count": 3, "pattern": "needle"});
        let capped = limit_response_rows(envelope.clone(), Some(2));
        assert_eq!(
            capped,
            json!({"results": [rows[0], rows[1]], "count": 2, "pattern": "needle"})
        );
        assert_eq!(
            unwrap_bridge_response(capped),
            vec![rows[0].clone(), rows[1].clone()]
        );
        assert_eq!(
            limit_response_rows(rows.clone(), Some(2)),
            json!([rows[0], rows[1]])
        );
        for limit in [None, Some(0)] {
            assert_eq!(limit_response_rows(envelope.clone(), limit), envelope);
        }
        for object in [
            json!({"name":"type", "fields": rows}),
            json!({"nodes": rows, "edges": [], "node_count": 3}),
            json!({"code":"return 0;", "instructions": rows}),
        ] {
            assert_eq!(limit_response_rows(object.clone(), Some(1)), object);
        }
    }

    #[test]
    fn output_format_preserves_explicit_flag_precedence() {
        for command in [
            ["program", "imports"].as_slice(),
            ["function", "list"].as_slice(),
            ["program", "info"].as_slice(),
        ] {
            for (flags, expected) in [
                (vec!["--json"], OutputFormat::JsonCompact),
                (vec!["--pretty"], OutputFormat::Json),
                (vec!["--json", "--pretty"], OutputFormat::Json),
                (vec!["--json", "-o", "table"], OutputFormat::Table),
                (
                    vec!["--pretty", "-o", "JSON-COMPACT"],
                    OutputFormat::JsonCompact,
                ),
                (vec!["--pretty", "-o", "NDJSON"], OutputFormat::JsonStream),
            ] {
                let cli = Cli::try_parse_from(
                    ["ghidra-cli"]
                        .into_iter()
                        .chain(command.iter().copied())
                        .chain(flags),
                )
                .unwrap();
                assert_eq!(
                    output_format_with_default(&cli, Some(OutputFormat::Csv)),
                    expected
                );
            }
        }
    }

    #[test]
    fn configured_output_applies_when_no_format_is_explicit() {
        let cli = Cli::try_parse_from(["ghidra-cli", "function", "list"]).unwrap();
        assert_eq!(
            output_format_with_default(&cli, Some(OutputFormat::Csv)),
            OutputFormat::Csv
        );
        assert_eq!(
            output_format_with_default(&cli, None),
            auto_detect_format(std::io::stdout().is_terminal())
        );
    }

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
