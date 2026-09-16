use super::options::extract_query_options;
use super::CommandResult;
use crate::cli::{self, Cli, Commands};
use crate::error::GhidraError;
use crate::format::{auto_detect_format, DefaultFormatter, Formatter, OutputFormat};
use crate::terminal::write_stdout;
use serde::Serialize;
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

fn output_format(cli: &Cli) -> OutputFormat {
    // Error presentation must remain available when config cannot be loaded.
    // Command execution reports configuration errors through its normal path.
    let configured = crate::config::Config::load()
        .ok()
        .and_then(|config| config.default_output_format)
        .and_then(|format| OutputFormat::from_str(&format).ok());
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
        let json = query.process_results(unwrap_bridge_response(result.value))?;
        return Ok(serde_json::from_str(&json)?);
    }
    Ok(result.value)
}

pub(super) fn print_result(cli: &Cli, result: CommandResult) -> anyhow::Result<()> {
    if !cli.quiet {
        check_dotnet_decompile_warning(&cli.command, &result.value);
    }
    let format = output_format(cli);

    // Unwrap bridge response envelopes before formatting
    let values = unwrap_bridge_response(result.value);

    if let Some(mut query) = result.query {
        query.format = format;
        let output = query.process_results(values)?;
        if !output.is_empty() {
            crate::terminal::write_stdout(&output)?;
        }
        return Ok(());
    }

    let formatter = DefaultFormatter;
    let output = formatter.format(&values, format)?;
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
    fn output_format_preserves_explicit_flag_precedence() {
        for command in [["query", "functions"], ["function", "list"]] {
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
                let cli =
                    Cli::try_parse_from(["ghidra-cli"].into_iter().chain(command).chain(flags))
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
