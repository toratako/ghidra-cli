//! Client-side script input and artifact preparation before bridge execution.

use crate::cli::ScriptCommands;
use crate::ipc::client::BridgeClient;

pub(super) fn execute(
    client: &BridgeClient,
    cmd: &ScriptCommands,
) -> anyhow::Result<serde_json::Value> {
    match cmd {
        ScriptCommands::Run(args) => {
            let expect = args
                .expect
                .iter()
                .map(|s| parse_expect_spec(s))
                .collect::<anyhow::Result<Vec<_>>>()?;
            if args.script_path == "-" {
                // Read a one-off script's Java source from stdin so a
                // throwaway snippet doesn't need a checked-in file; the
                // bridge stages it to a temp file and runs it through the
                // same compile/execute path as `script run PATH`.
                let source = crate::terminal::read_stdin("Java source")?;
                client.script_run_source(&source, &args.args, &expect, args.allow_empty)
            } else {
                // Canonicalize client-side so the bridge receives an absolute
                // path independent of the working directory its JVM inherited.
                // Use the ordinary Windows form that Ghidra's Java APIs accept.
                // Fall back to the raw path if the file is missing; the bridge
                // then reports a clear "Script not found".
                let path = dunce::canonicalize(&args.script_path)
                    .or_else(|_| std::path::absolute(&args.script_path))
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_else(|_| args.script_path.clone());
                client.script_run(&path, &args.args, &expect, args.allow_empty)
            }
        }
        ScriptCommands::List => client.script_list(),
    }
}

/// Parse a `--expect` spec (`PATH` or `PATH:MIN_ROWS`) into the wire form
/// `{path, min_rows?}`. The path is made absolute against the *client's* CWD so
/// the bridge validates the same file the script wrote, regardless of the CWD
/// the bridge JVM inherited. A trailing `:<digits>` is treated as MIN_ROWS;
/// anything else (e.g. a Windows drive letter) stays part of the path.
fn parse_expect_spec(spec: &str) -> anyhow::Result<serde_json::Value> {
    let (path_part, min_rows) = split_expect_spec(spec)?;
    let abs = std::path::absolute(path_part)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| path_part.to_string());
    let mut obj = serde_json::Map::new();
    obj.insert("path".to_string(), serde_json::Value::String(abs));
    if let Some(n) = min_rows {
        obj.insert("min_rows".to_string(), serde_json::json!(n));
    }
    Ok(serde_json::Value::Object(obj))
}

pub(super) fn validate_expect_specs(specs: &[String]) -> anyhow::Result<()> {
    for spec in specs {
        split_expect_spec(spec)?;
    }
    Ok(())
}

fn split_expect_spec(spec: &str) -> anyhow::Result<(&str, Option<i64>)> {
    match spec.rsplit_once(':') {
        Some((p, n)) if !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()) => {
            let rows = n.parse::<i64>().map_err(|_| {
                anyhow::anyhow!(
                    "Invalid --expect MIN_ROWS '{n}': must be an integer from 0 to {}",
                    i64::MAX
                )
            })?;
            Ok((p, Some(rows)))
        }
        _ => Ok((spec, None)),
    }
}
