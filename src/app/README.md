# CLI Application (`src/app/`)

`src/main.rs` owns parsing, environment overrides, logging, the setup async
runtime, and error/exit reporting. These private modules own command workflows.

| File | Responsibility |
|------|----------------|
| `mod.rs` | Command routing, early filter validation, bridge/program selection, and one-restart compatibility recovery |
| `options.rs` | Extract project, program, and query options from command variants; classify bridge requirements |
| `execute.rs` | Convert commands to bridge requests, including batch dispatch, range parsing, and symbol mutation guards |
| `import.rs` | Validate loader options and coordinate durable import, bridge startup, and analysis |
| `output.rs` | Warn about managed-code decompilation, select output format, unwrap envelopes, and apply query processing |
| `management.rs` | Start/stop/restart/status/ping/jobs/cancel handlers and save-by-restart workflow |
| `installation.rs` | Setup and doctor commands |
| `local.rs` | Initialization, version, configuration, defaults, and project commands |
| `project.rs` | Configuration override and project path resolution, plus persisted-project checks |

Command-level project/program options retain their precedence over global options
and configured defaults. Filter validation runs before bridge work. Bridge recovery
retries at most once. Import and save retain their stop/start/open/analyze order.
Output precedence remains explicit format, pretty JSON, compact JSON, then TTY
detection; query processing follows response-envelope extraction.

Unit tests stay with their owning helpers; see [validation commands](../../tests/README.md).
