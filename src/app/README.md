# CLI Application (`src/app/`)

`src/main.rs` owns parsing, environment overrides, logging, setup's async runtime,
and error/exit reporting; these private modules own workflows. `src/cli.rs` owns
the command tree and re-exports family arguments/query options from `src/cli/`.
The library exposes that same definition to `xtask` for documentation generation.
`src/cli/output.rs` owns output format names and parsing; `src/format/` owns rendering.

| File | Responsibility |
|------|----------------|
| `mod.rs` | Command routing, early filter validation, and bridge/program selection |
| `options.rs` | Extract project, program, and query options from command variants; classify bridge requirements |
| `execute.rs` | Dispatch bridge requests using planned list fetch arguments, range parsing, and comment input resolution |
| `execute/symbols.rs` | Resolve and guard symbol mutation targets |
| `execute/scripts.rs` | Prepare script paths, stdin source, and expected artifact paths before dispatch |
| `batch.rs` | Aggregate attempted command results and apply the error policy; always stop on transaction/save failures or timeouts |
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
`memory read`, `program info`, and `program stats` use `ObjectOptions` for target,
field, and output selection. They reject filtering, sorting, pagination, and count
flags during parsing. Convert these options to a projection-only `QueryOptions`
for the shared output path; nested memory bytes and pointers are not result rows.
`program export` requires `--output` during parsing for every export format.
Function rename rejects symbol-only bulk flags (`--filter`, `--all`).
Function and comment deletion accept only their target and receipt output options; filtering,
sorting, pagination, and count flags are rejected before bridge work.
`connect_program_bridge(port)` requires `bridge_info.explicit_addresses: true`,
`auto_save: true`, and `atomic_edits: true` before program dispatch.
Missing support fails with explicit restart guidance;
never downgrade address/transaction semantics or automatically upgrade for missing
capabilities. `program save` uses the direct management path without this gate,
preserving in-place recovery of pending edits before an explicit restart.
Dispatch each command once and propagate its result or error. Do not restart
the bridge or replay a command after a response failure.
Symbol deletion validates its target filter before bridge work and consumes it
only for target selection; output processing must retain the deletion receipt.
Multi-symbol deletion is one atomic bridge request; failure detail describes
`attempted_deleted`, `failed`, and `not_attempted`, without a committed deletion
count. Preserve `rolled_back`, `cancelled`, `transaction_failed`, and save-failure
detail through error reporting.
Import retains stop/start/open/analyze order. `program save` saves in place and
does nothing for a stopped bridge; deletion treats `--program` as a file target
without opening it as a selection/startup program.

`src/address.rs` validates explicit address syntax for client-side selectors,
import base addresses, and `clear START:END`; Ghidra validates the selected
address space and numeric bounds. Every numeric colon component requires
`0x`/`0X`. `clear` can inherit the start space for an unqualified end, requires
complete segmented endpoints, and rejects ambiguous splits.
Fully qualify both endpoints to disambiguate a range, for example
`ram:0x1234:0x0:ram:0x1234:0x8`; the delimiter remains a single colon.
Name-or-address operations keep exact names such as `dead` and `FUN_...`; they
never derive a numeric address from them. Offsets and byte patterns are separate.
Commands taking `TARGET` require exactly one positional target, including
function edits and queries, decompilation, disassembly,
xrefs, call searches, and caller/callee graphs.
`define-code` also accepts an optional inclusive `--end`.
It forwards a bounded mutation and returns only its receipt, without query options
or a configured row limit. Use `disassemble` separately to read the definitions.
Client-side comparisons read canonical segmented addresses with a space name;
symbol `--address` requires that name for segmented targets because the client
cannot distinguish an unnamed segment from a numeric-looking registered space.

Batch errors retain attempted results internally, including nested reports. The
outer invocation prints the report to stdout using the same format as a successful
batch, then reports summary diagnostics on stderr and exits nonzero. Stderr no
longer contains `detail.results`. Commands run sequentially, with one transaction
boundary per bridge request; a batch is never atomic. A failed ordinary request
rolls back its own edits while earlier completed commands remain saved. Ordinary
errors follow `--on-error continue|stop` (default: continue); nested batches
inherit the policy unless overridden. Transaction/save failures and timeouts
always stop them, including failures at the end of nested batches.
Preserve the timeout type for exit 75. Each line uses normal target resolution:
omitted project inherits the batch project, omitted program keeps that project's
selection, and query modifiers apply within each result.
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
wait timeouts exit 75, setup verification/doctor failures exit 1. Human-readable
errors state when changes were rolled back or partial changes were saved without
requiring verbose mode; JSON errors retain the structured detail flags.

Unit tests stay with their owning helpers; see [validation commands](../../tests/README.md).
