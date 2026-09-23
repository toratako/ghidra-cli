//! Client-side script input and artifact preparation before bridge execution.

use crate::cli::ScriptCommands;
use crate::ipc::client::BridgeClient;

pub(super) fn execute(
    client: &BridgeClient,
    cmd: &ScriptCommands,
) -> anyhow::Result<serde_json::Value> {
    match cmd {
        ScriptCommands::Run(args) => {
            validate_expect_specs(&args.expect_rows)?;
            let mut expect: Vec<_> = args
                .expect
                .iter()
                .map(|path| expected_artifact(path, None))
                .collect();
            for [path, rows] in args.expect_rows.as_chunks::<2>().0 {
                expect.push(expected_artifact(path, Some(parse_min_rows(rows)?)));
            }
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

/// Resolve artifact paths against the client's CWD, independent of the bridge JVM.
fn expected_artifact(path: &str, min_rows: Option<i64>) -> serde_json::Value {
    let abs = std::path::absolute(path)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| path.to_string());
    let mut obj = serde_json::Map::new();
    obj.insert("path".to_string(), serde_json::Value::String(abs));
    if let Some(n) = min_rows {
        obj.insert("min_rows".to_string(), serde_json::json!(n));
    }
    serde_json::Value::Object(obj)
}

pub(super) fn validate_expect_specs(expect_rows: &[String]) -> anyhow::Result<()> {
    anyhow::ensure!(
        expect_rows.len().is_multiple_of(2),
        "--expect-rows requires PATH MIN_ROWS"
    );
    for [_, rows] in expect_rows.as_chunks::<2>().0 {
        parse_min_rows(rows)?;
    }
    Ok(())
}

fn parse_min_rows(value: &str) -> anyhow::Result<i64> {
    crate::cli::numeric::ranged::<i64>(value, 0, i64::MAX as i128).map_err(|_| {
        anyhow::anyhow!(
            "Invalid --expect-rows MIN_ROWS '{value}': must be a decimal or 0x integer from 0 to {}",
            i64::MAX
        )
    })
}

#[cfg(test)]
mod tests {
    use super::validate_expect_specs;

    #[test]
    fn artifact_row_validation_rejects_incomplete_pairs_and_negative_minimums() {
        for values in [vec!["rows.jsonl"], vec!["rows.jsonl", "-1"]] {
            let values = values.into_iter().map(String::from).collect::<Vec<_>>();
            assert!(validate_expect_specs(&values).is_err());
        }
    }
}
