# CLI Application (`src/app/`)

`src/main.rs` owns parsing, environment overrides, logging, setup's async runtime,
and error/exit reporting; these private modules own workflows. `src/cli.rs` owns
the command tree and re-exports family arguments/query options from `src/cli/`.

| File | Responsibility |
|------|----------------|
| `mod.rs` | Command routing, early filter validation, bridge/program selection, and one-restart compatibility recovery |
| `options.rs` | Extract project, program, and query options from command variants; classify bridge requirements |
| `execute.rs` | Dispatch bridge requests, with shared list-fetch limits, range parsing, and comment input resolution |
| `execute/symbols.rs` | Resolve and guard symbol mutation targets; share rename handling with the top-level alias |
| `execute/scripts.rs` | Prepare script paths, stdin source, and expected artifact paths before dispatch |
| `batch.rs` | Aggregate attempted command results and stop on save failures or timeouts |
| `import.rs` | Validate loader options and coordinate durable import, bridge startup, and analysis |
| `output.rs` | Warn about managed-code decompilation, select output format, unwrap envelopes, and apply query processing |
| `management.rs` | Start/stop/restart/status/ping/jobs/cancel handlers and explicit save without auto-start |
| `installation.rs` | Setup and doctor commands |
| `local.rs` | Initialization, version, configuration, defaults, and project commands |
| `project.rs` | Configuration override and project path resolution; disk layout comes from `src/ghidra/project.rs` |

Command-level project/program options override global options and configured
defaults. Validate filters before bridge work. Recovery retries at most once
after dispatch; preflight `bridge_info` upgrades bridges lacking automatic saving
before program commands. Never replay commands after save failures.
Import retains stop/start/open/analyze order. `program save` saves in place and
does nothing for a stopped bridge; deletion treats `--program` as a file target
without opening it as a selection/startup program.

Batch error envelopes retain attempted results and structured detail. Ordinary
errors permit later commands; save failures/timeouts stop them. Preserve the
timeout type for exit 75. Each line uses normal target resolution and recovery:
omitted project inherits the batch project, omitted program keeps that project's
selection, and query modifiers apply within each result.

Output precedence: explicit format, pretty JSON, compact JSON, then TTY detection.
Extract response envelopes before query processing. `output.rs` renders reports;
`src/terminal.rs` sends results to stdout and optional text-mode progress to stderr.
A closed stdout pipe is normal. `main.rs` structures JSON-mode errors; bridge
wait timeouts exit 75, setup verification/doctor failures exit 1.

Unit tests stay with their owning helpers; see [validation commands](../../tests/README.md).
