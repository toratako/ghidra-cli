# CLI Application (`src/app/`)

`src/main.rs` owns parsing, environment overrides, logging, the setup async
runtime, and error/exit reporting. These private modules own command workflows.

| File | Responsibility |
|------|----------------|
| `mod.rs` | Command routing, early filter validation, bridge/program selection, and one-restart compatibility recovery |
| `options.rs` | Extract project, program, and query options from command variants; classify bridge requirements |
| `execute.rs` | Convert commands to bridge requests, with shared list-fetch limits, range parsing, and symbol mutation guards |
| `batch.rs` | Aggregate attempted command results and stop on save failures or timeouts |
| `import.rs` | Validate loader options and coordinate durable import, bridge startup, and analysis |
| `output.rs` | Warn about managed-code decompilation, select output format, unwrap envelopes, and apply query processing |
| `management.rs` | Start/stop/restart/status/ping/jobs/cancel handlers and explicit save without auto-start |
| `installation.rs` | Setup and doctor commands |
| `local.rs` | Initialization, version, configuration, defaults, and project commands |
| `project.rs` | Configuration override and project path resolution; disk layout comes from `src/ghidra/project.rs` |

Command-level project/program options retain their precedence over global options
and configured defaults. Filter validation runs before bridge work. Bridge recovery
retries at most once after dispatch. A preflight `bridge_info` check upgrades a
bridge lacking automatic saving before sending program commands. Import retains
its stop/start/open/analyze order; `program save` sends an in-place save request
and is a no-op for a stopped bridge. Save failures must never trigger command replay.
Deletion treats `--program` as a file target and never opens it as a selection or
startup program.
Batch errors retain attempted results and structured details in the error
envelope. Ordinary errors allow later commands to run; save failures and timeouts
stop execution. Preserve the timeout error type through batch context for exit 75.
Each batch line uses normal target resolution and compatibility recovery. An
omitted project inherits the batch project; an omitted program keeps that
project's current selection. Query modifiers apply within each structured result.
Output precedence remains explicit format, pretty JSON, compact JSON, then TTY
detection; query processing follows response-envelope extraction.
`output.rs` shares report rendering; `src/terminal.rs` handles the streams:
results use stdout, optional progress uses stderr in text mode, and a closed
stdout pipe is normal. `main.rs` structures errors in JSON modes and preserves
exit 75 for bridge wait timeouts. Setup verification and doctor failures exit 1.

Unit tests stay with their owning helpers; see [validation commands](../../tests/README.md).
