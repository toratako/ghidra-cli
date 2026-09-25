# CLI Application (`src/app/`)

`src/main.rs` owns parsing, environment overrides, logging,
and error/exit reporting; these private modules own workflows. `src/cli.rs` owns
the command tree and re-exports family arguments/query options from `src/cli/`.
The library exposes that same definition to `xtask` for documentation generation.
`src/cli/output.rs` owns output format names and parsing; `src/format/` owns rendering.
Rendering dispatch stays in `format/mod.rs`; `human.rs`, `tabular.rs`, and
`code.rs` own human-readable, table/CSV/TSV, and C/assembly output respectively.
CLI parsing tests are grouped under `src/cli/tests/`, with shared command-tree
and target checks in `src/cli/tests.rs`.

| File | Responsibility |
|------|----------------|
| `mod.rs` | Command routing, early filter validation, and bridge/program selection |
| `options.rs`, `options/target.rs`, `options/query.rs` | Classify bridge requirements; extract project/program targets and query options from command variants |
| `execute.rs` | Dispatch bridge requests using planned list fetch arguments, range parsing, and comment input resolution |
| `execute/functions.rs` | Function dispatch and guarded selection of one decompiler variable |
| `execute/symbols.rs` | Resolve and guard symbol mutation targets |
| `execute/namespaces.rs` | Resolve exact namespace paths and guard mutation targets and destination parents |
| `execute/type_archives.rs` | Resolve GDT paths and select roots with guarded source snapshots |
| `execute/scripts.rs` | Prepare script paths, stdin source, and expected artifact paths before dispatch |
| `batch.rs`, `batch/recovery.rs` | Validate and freeze selected batch input before bridge work; aggregate execution results, apply the error policy, and derive recovery guidance |
| `import.rs` | Validate loader options and coordinate durable import, bridge startup, and analysis |
| `result.rs` | Declare command result shapes, retain context/page metadata, and apply queries to produce the common result value |
| `output.rs` | Render common results for standalone/batch/management output and route C-only decompiler diagnostics to stderr |
| `management.rs` | Bridge lifecycle, `job list/get/result/cancel`, and explicit save without auto-start |
| `recovery.rs` | Unknown-outcome job recovery with resolved project paths and shared shell quoting |
| `installation.rs` | Doctor command |
| `local.rs` | Configuration and project commands |
| `project.rs` | Configuration override and project path resolution; disk layout comes from `src/ghidra/project.rs` |

Command-level project/program options override global options and configured
defaults; positional program operands take precedence over program options.
`project info` follows the same rule, with its positional name first.
`--projects-dir` overrides the environment through a nonserialized Config field,
so per-line batch overrides do not leak into later commands or saved settings.
Validate filters before bridge work. Single-object commands use `ObjectOptions`,
converted to projection-only `QueryOptions` for shared output; nested memory
bytes and pointers are not result rows. Function/comment deletion and
`listing define-code` return receipts without row-query options.
`connect_program_bridge(port)` requires protocol version 4,
`bridge_info.explicit_addresses: true`, `auto_save: true`, and `atomic_edits: true`
before program dispatch.
Missing support fails with explicit restart guidance;
never downgrade address/transaction semantics or automatically upgrade for missing
capabilities. `program save` uses the direct management path; a targeted save
requires protocol version 4, while an unscoped save bypasses these checks for
in-place recovery of pending edits.
Dispatch each command once and propagate its result or error. Do not restart
the bridge or replay a command after a response failure.
Bind an explicit program to the `BridgeClient` so every operation carries it in
the request envelope, including both reads and edits in guarded helpers. Selection
and execution share one queued job; do not send a preparatory `open_program`.
Symbol deletion validates its `--where` predicate before bridge work and consumes it
only for target selection; output processing must retain the deletion receipt.
Multi-symbol deletion is one atomic bridge request. Preserve structured failure
detail through error reporting; see the [wire contract](../ipc/README.md).
Namespace mutations select one exact full path from uncapped namespace rows,
then apply `--where` to disambiguate it. They send the complete target snapshot;
movement also guards the selected parent, with explicit null for Global.
Selection predicates are validated during standalone and batch preflight and
never filter mutation receipts. Display limits and field projection do not
select mutation targets.
`function var list` applies ordinary list queries to decompiler rows. Get/set/infer-struct
use `--where` only to narrow the exact `--var` name to one candidate, then send
its project/program/function/modification/row guard for bridge revalidation. Their
projection-only output controls never change target selection or filter receipts.
Decompilation diagnostics are result fields in JSON and human formats. C-only
output sends API diagnostics absent from its warning comments to stderr; field
projection and quiet mode still apply. `--with-addresses` retains the raw `code`
and adds `line_addresses` in JSON. Compact/full rendering adds a line/address
gutter; C rendering appends address comments to mapped lines. Projecting away
`line_addresses` leaves the C unannotated.
`program import` owns its startup and selection workflow; `--name` is the saved
file name, independent of global `--program` and configured target defaults.
Import binds follow-up analysis or information requests to the imported program.
`program save` saves in place and does nothing for a stopped bridge.
`program list/delete` ignore a direct `--program`; deletion uses its positional
file operand. In a batch they still carry the inherited selection context.

`type archive inspect` uses the project bridge without selecting a Program and
preserves batch selection intent. Explicit `--program` is rejected before
execution; configured and inherited targets do not apply. GDT transfers parse
`--where` during preflight, evaluate it on uncapped candidates, and pass exact
paths plus the source guard to the final request. File validation happens when
the line executes, allowing export followed by import in the same batch. Output
projection and configured display limits never select mutation roots.

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
resolution or bridge startup. It validates locally parsed query options, ranges,
and required `program open/delete` targets, aggregates file/line diagnostics, and
retains the parsed command tree for execution. Nested paths remain relative to the
invocation's working directory; canonical paths detect include cycles. All included
batch files must exist before execution. Program-dependent validation remains execution-time.
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
Preserve the timeout type for exit 75. Omitted project inherits the batch project,
and query modifiers apply within each result.
One invocation shares a project-to-program selection map across nested batches.
Outer and nested `--program` values set selection intent; each line's explicit
target overrides the inherited target. The actual selection reported by each
executed response updates that project's context on success or error; an explicit
null clears it so later lines use ordinary implicit selection. Bind the inherited
target to every request for that line, rather than relying on the bridge's shared
current program. Batch setup neither opens a program nor starts a bridge: an empty
batch has no selection effect, and the first line's explicit target can supersede
the outer target before any program opens.
Target defaults come from config; CLI target selection does not read environment
variables. Config `default_program` applies at bridge startup, while a running
bridge retains its selected program unless explicitly overridden.

The outer batch adds structured `recovery` and matching diagnostic text. A
restart command requires a confirmed rollback, no later attempts or nested
failure, a known failed-request program, and a remaining range using one project.
Use the program identity from the error response, never a later control snapshot.
Other cases direct the caller to inspect state or review attempted results.
Unknown program outcomes carry the sent operation's UUID and direct callers to
`job result`; nested batch recovery keeps the failed line's own project and ID.
IDs are per bridge operation, so recovery must not equate a preparatory operation's
completion with completion of the entire CLI command or batch line.
Recovery command arguments are authoritative in JSON; displayed commands use
POSIX quoting on Unix and PowerShell quoting on Windows and name the required
working directory.

Output precedence: explicit format, pretty JSON, compact JSON, configured
`default_output_format`, then TTY detection. Carry the residual
[query plan](../query/README.md) with each command result; rebuilding it for output
can apply a server offset twice.
`result.rs` classifies results by command, never by payload keys. Normal JSON
contains `data` and optional nonempty `meta`; standalone output and batch entries
serialize the same prepared result. Single values retain their JSON type, lists
use arrays, and graphs retain their nodes and edges. Row extraction and contextual
metadata fields are declared together. Lists report `returned`; paged operations
retain the effective `offset`/`limit` from before pushdown (`null` is unlimited).
Count results retain page/context metadata without `returned`. Fields project
data only; graph projection applies to nodes after matching outgoing edges.
Receipts, nested fields, and warnings remain data. No result wrapper implies
success: doctor and failed batches can print diagnostic results before exiting
nonzero. Stderr errors keep their separate contract.

Instruction CFG and High P-code are single structured values. Their node/edge
budgets run in Java; Rust preserves their references, provenance and completion
information unchanged in standalone and batch results. Do not apply the call
graph's node queries to these structures.

NDJSON renders list elements individually, other results as one JSON value,
and empty lists as no output; it omits the outer wrapper and metadata. Batch
NDJSON is one report value whose entries retain the common result envelopes.
Compact/full file-mapping output also renders excluded ranges and reasons from
metadata, including when no direct mapping rows remain. Count output stays numeric.
Management output uses the same preparation and preserves its text rendering.
`output.rs` renders reports;
`src/terminal.rs` sends results to stdout and optional text-mode progress to stderr.
A closed stdout pipe is normal. `main.rs` structures JSON-mode errors; bridge
wait timeouts exit 75, doctor failures exit 1. Human-readable
errors state when changes were rolled back or partial changes were saved without
requiring verbose mode; JSON errors retain the structured detail flags.
Normal results and confirmed errors do not display job IDs. Unknown program
outcomes add `detail.job_id`, the actual wire command, and `recovery.argv` to
diagnostics. `job result` prints the retained record even for failed jobs; exit 0
means retrieval. Pending results use status `pending` and exit 75 without claiming
a new timeout or unknown mutation; unavailable results exit 1. It never starts a
bridge, selects a program, or reruns the original CLI output/query transformations.

Unit tests stay with their owning helpers; see [validation commands](../../tests/README.md).
