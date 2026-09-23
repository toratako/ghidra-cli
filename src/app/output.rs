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
    describe_expression_error(err, "--filter")
}

pub(super) fn describe_selector_error(err: GhidraError) -> anyhow::Error {
    describe_expression_error(err, "--where")
}

fn describe_expression_error(err: GhidraError, option: &str) -> anyhow::Error {
    match &err {
        GhidraError::FilterParseError(_) | GhidraError::InvalidFilter(_) => anyhow::anyhow!(err)
            .context(format!(
                "invalid {option} expression: expected <field><operator><value>, \
                 e.g. {option} 'name~PK' (contains), {option} 'name=~\"^PK_\"' (regex), \
                 {option} 'size>100'; combine with AND/OR/NOT",
            )),
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
    // Explicit --format > --json/--pretty > configured format > TTY detection.
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
            if result
                .meta
                .get("detector")
                .and_then(serde_json::Value::as_str)
                == Some("ghidra-address-table")
            {
                if let Some(ranges) = result
                    .meta
                    .get("ranges")
                    .and_then(serde_json::Value::as_array)
                {
                    let ranges = ranges
                        .iter()
                        .filter_map(|range| {
                            Some(format!(
                                "{} .. {}",
                                range["start"].as_str()?,
                                range["end"].as_str()?
                            ))
                        })
                        .collect::<Vec<_>>()
                        .join(", ");
                    let ranges = if ranges.is_empty() { "none" } else { &ranges };
                    text = format!("Candidate start ranges: {ranges}\n{text}");
                }
                if !text.ends_with('\n') {
                    text.push('\n');
                }
                match result
                    .meta
                    .get("scan")
                    .and_then(|scan| scan.get("complete"))
                    .and_then(serde_json::Value::as_bool)
                {
                    Some(true) => text.push_str("Scan complete for these candidate start ranges.\n"),
                    Some(false) => text.push_str("Scan stopped at the result limit; use --limit 0 to scan all candidate starts in these ranges.\n"),
                    None => {}
                }
            }
            if let Some(path) = result
                .meta
                .get("target_type_path")
                .and_then(serde_json::Value::as_str)
            {
                text = render_type_uses(result, path, text, format)?;
            }
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

fn render_type_uses(
    result: &CommandOutput,
    path: &str,
    rows: String,
    format: OutputFormat,
) -> anyhow::Result<String> {
    let mut text = if let Some(field) = result.meta.get("target_field") {
        if let Some(name) = field.get("name").and_then(serde_json::Value::as_str) {
            format!("Field uses: {path}.{name}\n")
        } else {
            format!("Field uses: {path} (ordinal {})\n", field["ordinal"])
        }
    } else {
        let kinds = result
            .meta
            .get("kinds")
            .and_then(serde_json::Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();
        format!("Type uses: {path} ({kinds})\n")
    };
    if let Some(scope) = result.meta.get("scope").filter(|scope| scope.is_object()) {
        if let (Some(function), Some(address)) =
            (scope["function"].as_str(), scope["address"].as_str())
        {
            text.push_str(&format!("Function: {function} ({address})\n"));
        }
    }
    text.push_str(&rows);
    let Some(scan) = result.meta.get("scan") else {
        return Ok(text);
    };
    if !text.ends_with('\n') {
        text.push('\n');
    }
    if scan["stop_reason"].as_str() == Some("limit") {
        let scope = if scan.get("total_functions").is_some() {
            "selected functions"
        } else {
            "declarations"
        };
        text.push_str(&format!(
            "Scan stopped at the result limit; use --limit 0 to scan all {scope}.\n"
        ));
    }
    for (key, heading) in [
        ("failed_functions", "Functions that could not be decompiled"),
        ("unresolved", "Unresolved field evidence"),
        ("warnings", "Decompiler warnings"),
    ] {
        if let Some(details) = scan[key].as_array().filter(|rows| !rows.is_empty()) {
            text.push_str(&format!("\n{heading}:\n"));
            text.push_str(&DefaultFormatter.format(details, format)?);
            if !text.ends_with('\n') {
                text.push('\n');
            }
        }
    }
    if scan["complete"].as_bool() == Some(false) && scan["stop_reason"].as_str() != Some("limit") {
        text.push_str("Search incomplete; an empty result does not establish absence of uses.\n");
    }
    Ok(text)
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
    fn semantic_search_reports_failed_and_unresolved_empty_results_in_human_output() {
        let result = CommandOutput::prepare(
            serde_json::json!({
                "target_type_path": "/Recovered/Foo",
                "target_field": {"name": "flags", "ordinal": 1},
                "scope": {"function": "parse_packet", "address": "0x1000"},
                "uses": [],
                "scan": {
                    "complete": false,
                    "stop_reason": "decompile_failed",
                    "failed_functions": [{
                        "function": "parse_packet", "address": "0x1000",
                        "reason": "timeout", "message": "Native timeout"
                    }],
                    "unresolved": [{"reason": "ambiguous field", "instruction_address": "0x1004"}],
                    "warnings": [{"function": "parse_packet", "warnings": ["Unresolved control flow"]}]
                }
            }),
            ResultShape::Rows {
                key: Some("uses"),
                context: &["target_type_path", "target_field", "scope", "scan"],
            },
            None,
            None,
        )
        .unwrap();
        for format in [OutputFormat::Compact, OutputFormat::Full] {
            let text = render(&result, format).unwrap();
            assert!(text.contains("Field uses: /Recovered/Foo.flags"), "{text}");
            assert!(text.contains("parse_packet (0x1000)"), "{text}");
            assert!(text.contains("Native timeout"), "{text}");
            assert!(text.contains("ambiguous field"), "{text}");
            assert!(text.contains("Unresolved control flow"), "{text}");
            assert!(text.contains("Search incomplete"), "{text}");
            assert!(!text.contains("result limit"), "{text}");
        }
    }

    #[test]
    fn output_format_preserves_explicit_flag_precedence() {
        for command in [
            ["symbol", "externals"].as_slice(),
            ["function", "list"].as_slice(),
            ["program", "info"].as_slice(),
            ["program", "stats"].as_slice(),
            ["memory", "read", "0x1000", "--size", "64"].as_slice(),
        ] {
            for (flags, expected) in [
                (vec!["--json"], OutputFormat::JsonCompact),
                (vec!["--pretty"], OutputFormat::Json),
                (vec!["--json", "--pretty"], OutputFormat::Json),
                (vec!["--json", "--format", "table"], OutputFormat::Table),
                (
                    vec!["--pretty", "--format", "JSON-COMPACT"],
                    OutputFormat::JsonCompact,
                ),
                (
                    vec!["--pretty", "--format", "NDJSON"],
                    OutputFormat::JsonStream,
                ),
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
    fn expression_errors_mention_the_correct_option() {
        // Regression (TODO.md Bug 2): a bare word is not a valid filter and the
        // error must surface (previously swallowed, dumping the whole dataset).
        for (option, describe) in [
            (
                "--filter",
                describe_query_error as fn(GhidraError) -> anyhow::Error,
            ),
            (
                "--where",
                describe_selector_error as fn(GhidraError) -> anyhow::Error,
            ),
        ] {
            let Err(err) = filter::Filter::parse("PK") else {
                panic!("bare word must not parse");
            };
            let msg = format!("{:#}", describe(err));
            assert!(
                msg.contains(&format!("invalid {option} expression")),
                "got: {msg}"
            );
            assert!(msg.contains(&format!("{option} 'name~PK'")), "got: {msg}");
        }
    }
}
