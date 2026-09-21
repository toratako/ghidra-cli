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
| `batch.rs`, `batch/recovery.rs` | Validate and freeze selected batch input before bridge work; aggregate execution results, apply the error policy, and derive recovery guidance |
| `import.rs` | Validate loader options and coordinate durable import, bridge startup, and analysis |
| `output.rs` | Select output format, unwrap envelopes, apply query processing, and route C-only decompiler diagnostics to stderr |
| `management.rs` | `bridge start/stop/restart/status/ping`, `job list/get/cancel`, and explicit save without auto-start |
| `installation.rs` | Setup and doctor commands |
| `local.rs` | Configuration and project commands |
| `project.rs` | Configuration override and project path resolution; disk layout comes from `src/ghidra/project.rs` |

Command-level project/program options override global options and configured
defaults. `project info` follows the same rule, with its positional name first.
`--projects-dir` overrides the environment through a nonserialized Config field,
so per-line batch overrides do not leak into later commands or saved settings.
Validate filters before bridge work. Single-object commands use `ObjectOptions`,
converted to projection-only `QueryOptions` for shared output; nested memory
bytes and pointers are not result rows. Function/comment deletion and
`listing define-code` return receipts without row-query options.
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
Multi-symbol deletion is one atomic bridge request. Preserve structured failure
detail through error reporting; see the [wire contract](../ipc/README.md).
Decompilation diagnostics are result fields in JSON and human formats. C-only
output retains the generated C and sends API diagnostics absent from its warning
comments to stderr; count, filtering, field projection, and quiet mode still apply.
`program import` owns its startup and selection workflow; `--name` is the saved
file name, independent of global `--program` and configured target defaults.
Import retains stop/start/open/analyze order. `program save` saves in place and
does nothing for a stopped bridge; deletion treats `--program` as a file target
without opening it as a selection/startup program.

`src/address.rs` validates explicit address syntax for client-side selectors,
import base addresses, and `listing undefine START --end END`; Ghidra validates
the selected address spaces and numeric bounds. Every numeric colon component
requires `0x`/`0X`. `listing undefine` validates each endpoint independently before
bridge work; qualify overlay and segmented endpoints with their space names,
for example `ram:0x1234:0x0 --end ram:0x1234:0x8`.
Name-or-address operations keep exact names such as `dead` and `FUN_...`; they
never derive a numeric address from them. Offsets and byte patterns are separate.
Client-side comparisons read canonical segmented addresses with a space name;
symbol `--address` requires that name for segmented targets because the client
cannot distinguish an unnamed segment from a numeric-looking registered space.

Batch preflight parses every selected line and nested batch before configuration/project
resolution or bridge startup. It validates locally parsed query options and
ranges, aggregates file/line diagnostics, and retains the parsed command tree
for execution. Nested paths remain relative to the invocation's working
directory; canonical paths detect include cycles. All included batch files must
exist before execution. Program-dependent validation remains execution-time.
Preflight failure reports `validation_failed`, `validation_errors`, and zero
`commands_executed`, regardless of `--on-error`.
`--from-line` selects an inclusive one-based physical source line before parsing;
skipped lines and their includes are not checked. Nested selections are local to
each file. Reports retain original line numbers and count only selected commands.

Batch execution errors retain attempted results internally, including nested reports. The
outer invocation prints the report to stdout using the same format as a successful
batch, then reports summary diagnostics on stderr and exits nonzero. Commands run
sequentially, with one transaction boundary per bridge request; a batch is never
atomic. Earlier completed commands remain saved. Ordinary errors follow `--on-error continue|stop` (default: continue); nested batches
inherit the policy unless overridden. Transaction/save failures and unknown outcomes
always stop them, including failures at the end of nested batches.
Preserve the timeout type for exit 75. Each line uses normal target resolution:
omitted project inherits the batch project, omitted program keeps that project's
selection, and query modifiers apply within each result.
Target defaults come from config; CLI target selection does not read environment
variables. Config `default_program` applies at bridge startup, while a running
bridge retains its selected program unless explicitly overridden.

The outer batch adds structured `recovery` and matching diagnostic text. A
restart command requires a confirmed rollback, no later attempts or nested
failure, a known failed-request program, and a remaining range using one project.
Use the program identity from the error response, never a later control snapshot.
Other cases direct the caller to inspect state or review attempted results.
Recovery command arguments are authoritative in JSON; displayed commands use
POSIX quoting on Unix and PowerShell quoting on Windows and name the required
working directory.

Output precedence: explicit format, pretty JSON, compact JSON, configured
`default_output_format`, then TTY detection. Carry the residual
[query plan](../query/README.md) with each command result; rebuilding it for output
can apply a server offset twice.
Extract response envelopes before query processing. `output.rs` renders reports;
`src/terminal.rs` sends results to stdout and optional text-mode progress to stderr.
A closed stdout pipe is normal. `main.rs` structures JSON-mode errors; bridge
wait timeouts exit 75, setup verification/doctor failures exit 1. Human-readable
errors state when changes were rolled back or partial changes were saved without
requiring verbose mode; JSON errors retain the structured detail flags.

Unit tests stay with their owning helpers; see [validation commands](../../tests/README.md).
