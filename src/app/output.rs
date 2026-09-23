use super::options::extract_query_options;
use super::result::{CommandOutput, ResultShape};
use super::CommandResult;
use crate::cli::{Cli, Commands};
use crate::error::GhidraError;
use crate::format::{auto_detect_format, DefaultFormatter, Formatter, OutputFormat};
use crate::query::Query;
use crate::terminal::write_stdout;
use serde::Serialize;
use std::io::{IsTerminal, Write};

#[derive(Clone, Copy)]
pub(crate) struct Output {
    pub json: bool,
    pub pretty: bool,
    pub quiet: bool,
    format: OutputFormat,
    shape: ResultShape,
}

impl Output {
    pub fn diagnostic(json: bool, pretty: bool, quiet: bool) -> Self {
        Self {
            json,
            pretty,
            quiet,
            format: OutputFormat::JsonCompact,
            shape: ResultShape::Value,
        }
    }

    pub fn new(cli: &Cli) -> Self {
        let format = output_format(cli);
        Self {
            json: matches!(
                format,
                OutputFormat::Json | OutputFormat::JsonCompact | OutputFormat::JsonStream
            ),
            pretty: matches!(format, OutputFormat::Json),
            quiet: cli.quiet,
            format,
            shape: ResultShape::for_command(&cli.command),
        }
    }

    pub fn result(&self, value: &impl Serialize, human: &str) -> anyhow::Result<()> {
        if self.json {
            let result =
                CommandOutput::prepare(serde_json::to_value(value)?, self.shape, None, None)?;
            let text = render(&result, self.format)?;
            if text.is_empty() {
                Ok(())
            } else {
                write_stdout(&text)
            }
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

/// C-only output retains comments, but API diagnostics need a separate stream.
fn c_decompile_diagnostics(
    value: &serde_json::Value,
    query: Option<&Query>,
) -> crate::error::Result<String> {
    let rows = vec![value.clone()];
    if let Some(query) = query {
        if let Some(fields) = &query.fields {
            // A projection without code produces JSON even with --format c.
            if query
                .select_fields(&rows, fields)?
                .iter()
                .any(|row| row.get("code").is_none())
            {
                return Ok(String::new());
            }
        }
    }
    let mut diagnostics = String::new();
    for row in rows {
        if let Some(warnings) = row.get("warnings").and_then(serde_json::Value::as_array) {
            for warning in warnings {
                if warning["source"] != "decompiler" {
                    continue;
                }
                let in_code = warnings.iter().any(|other| {
                    other["source"] == "c_comment"
                        && other["message"]
                            .as_str()
                            .zip(warning["message"].as_str())
                            .is_some_and(|(a, b)| a.split_whitespace().eq(b.split_whitespace()))
                });
                if !in_code {
                    if let Some(text) = crate::format::format_decompile_warning(warning) {
                        diagnostics.push_str(&format!("Warning: {text}\n"));
                    }
                }
            }
        }
    }
    Ok(diagnostics)
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

/// Standalone and batch serialize exactly the same prepared value.
pub(super) fn process_batch_result(result: CommandResult) -> anyhow::Result<serde_json::Value> {
    Ok(serde_json::to_value(prepare(result)?)?)
}

fn prepare(result: CommandResult) -> anyhow::Result<CommandOutput> {
    CommandOutput::prepare(
        result.value,
        result.shape,
        result.query.as_ref(),
        result.page,
    )
}

fn render(result: &CommandOutput, format: OutputFormat) -> anyhow::Result<String> {
    match format {
        OutputFormat::Json => Ok(serde_json::to_string_pretty(result)?),
        OutputFormat::JsonCompact => Ok(serde_json::to_string(result)?),
        _ if result.is_count => Ok(serde_json::to_string(&result.data)?),
        OutputFormat::Compact | OutputFormat::Full => {
            let mut text = DefaultFormatter.format(result.rows(), format)?;
            if let Some(excluded) = result
                .meta
                .get("unsupported_mappings")
                .and_then(serde_json::Value::as_array)
                .filter(|rows| !rows.is_empty())
            {
                if result.rows().is_empty() {
                    text = "No direct file mappings\n".to_string();
                } else if !text.ends_with('\n') {
                    text.push('\n');
                }
                text.push_str("\nUnsupported file mappings (excluded):\n");
                text.push_str(&DefaultFormatter.format(excluded, format)?);
            }
            Ok(text)
        }
        _ => Ok(DefaultFormatter.format(result.rows(), format)?),
    }
}

pub(super) fn print_result(cli: &Cli, result: CommandResult) -> anyhow::Result<()> {
    let format = output_format(cli);
    if !cli.quiet && format == OutputFormat::C && matches!(cli.command, Commands::Decompile(_)) {
        let diagnostics = c_decompile_diagnostics(&result.value, result.query.as_ref())?;
        let _ = std::io::stderr().lock().write_all(diagnostics.as_bytes());
    }
    let output = render(&prepare(result)?, format)?;
    if !output.is_empty() {
        write_stdout(&output)?;
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
        for command in [
            ["symbol", "externals"].as_slice(),
            ["function", "list"].as_slice(),
            ["program", "info"].as_slice(),
            ["program", "stats"].as_slice(),
            ["memory", "read", "0x1000", "64"].as_slice(),
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
