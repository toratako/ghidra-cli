# CLI Application (`src/app/`)

`src/main.rs` owns parsing, environment overrides, logging, setup's async runtime,
and error/exit reporting; these private modules own workflows. `src/cli.rs` owns
the command tree and re-exports family arguments/query options from `src/cli/`.

| File | Responsibility |
|------|----------------|
| `mod.rs` | Command routing, early filter validation, bridge/program selection, and one-restart compatibility recovery |
| `options.rs` | Extract project, program, and query options from command variants; classify bridge requirements |
| `execute.rs` | Dispatch bridge requests using planned list fetch arguments, range parsing, and comment input resolution |
| `execute/symbols.rs` | Resolve and guard symbol mutation targets |
| `execute/scripts.rs` | Prepare script paths, stdin source, and expected artifact paths before dispatch |
| `batch.rs` | Aggregate attempted command results and apply the error policy; always stop on save failures or timeouts |
| `import.rs` | Validate loader options and coordinate durable import, bridge startup, and analysis |
| `output.rs` | Warn about managed-code decompilation, select output format, unwrap envelopes, and apply query processing |
| `management.rs` | `bridge start/stop/restart/status/ping`, `job list/get/cancel`, and explicit save without auto-start |
| `installation.rs` | Setup and doctor commands |
| `local.rs` | Configuration and project commands |
| `project.rs` | Configuration override and project path resolution; disk layout comes from `src/ghidra/project.rs` |

Command-level project/program options override global options and configured
defaults. `project info` follows the same rule, with its positional name first.
`--projects-dir` overrides the environment through a nonserialized Config field,
so per-line batch overrides do not leak into later commands or saved settings.
Validate filters before bridge work.
Function rename rejects symbol-only bulk flags (`--filter`, `--all`).
Function and comment deletion accept only their target and receipt output options; filtering,
sorting, pagination, and count flags are rejected before bridge work. Preflight
requires `bridge_info.explicit_addresses: true` before program dispatch and
before compatibility recovery. Missing support fails with restart guidance;
never downgrade to inferred address parsing. Recovery for other compatibility
failures retries at most once after dispatch. Compatibility restart captures the
selected project file path (never the internal Program name or a default); if it
cannot determine the selection, it leaves the bridge running. Stop errors prevent restart.
Never replay commands after save failures.
Symbol deletion validates its target filter before bridge work and consumes it
only for target selection; output processing must retain the deletion receipt.
Import retains stop/start/open/analyze order. `program save` saves in place and
does nothing for a stopped bridge; deletion treats `--program` as a file target
without opening it as a selection/startup program.

`src/address.rs` validates explicit address syntax for client-side selectors,
import base addresses, and `clear START:END`; Ghidra validates the selected
address space and numeric bounds. Every numeric colon component requires
`0x`/`0X`. `clear` can inherit the start space for an unqualified end, requires
complete segmented endpoints, and rejects ambiguous splits and legacy `::`.
Fully qualify both endpoints to disambiguate a range, for example
`ram:0x1234:0x0:ram:0x1234:0x8`; the delimiter remains a single colon.
Name-or-address operations keep exact names such as `dead` and `FUN_...`; they
never derive a numeric address from them. Offsets and byte patterns are separate.
Client-side comparisons read canonical segmented addresses with a space name;
symbol `--address` requires that name for segmented targets because the client
cannot distinguish an unnamed segment from a numeric-looking registered space.

Batch errors retain attempted results internally, including nested reports. The
outer invocation prints the report to stdout using the same format as a successful
batch, then reports summary diagnostics on stderr and exits nonzero. Stderr no
longer contains `detail.results`. Ordinary
errors follow `--on-error continue|stop` (default: continue); nested batches
inherit the policy unless overridden. Save failures/timeouts always stop them.
Preserve the timeout type for exit 75. Each line uses normal target resolution
and recovery: omitted project inherits the batch project, omitted program keeps
that project's selection, and query modifiers apply within each result.
Target defaults come from config; CLI target selection does not read environment
variables. Config `default_program` applies at bridge startup, while a running
bridge retains its selected program unless explicitly overridden.

Output precedence: explicit format, pretty JSON, compact JSON, configured
`default_output_format`, then TTY detection. The shared
[query plan](../query/README.md) applies `default_limit` after row selection,
whether it happens in Java or Rust. Count ignores the configured cap; explicit
zero is unlimited. The residual query travels with each command result so
standalone and batch output cannot apply a server offset twice.
Extract response envelopes before query processing. `output.rs` renders reports;
`src/terminal.rs` sends results to stdout and optional text-mode progress to stderr.
A closed stdout pipe is normal. `main.rs` structures JSON-mode errors; bridge
wait timeouts exit 75, setup verification/doctor failures exit 1.

Unit tests stay with their owning helpers; see [validation commands](../../tests/README.md).
