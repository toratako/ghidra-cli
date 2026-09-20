---
name: ghidra-cli
description: Use ghidra-cli for native-binary reverse engineering with Ghidra, including import of programs, code queries and decompilation, type and annotation edits, Java scripts, patches, and binary export.
---

# Ghidra CLI

The executable is `ghidra-cli`. Use `ghidra-cli <command> --help` for exact
arguments. Read the references below only when their details are needed.

Global `--project PROJECT --program PROGRAM` select the target. Each project
reuses a JVM bridge; program operations are serialized while `bridge status`,
`job list`, `job get`, and `job cancel` remain responsive.
Command-level `--project`/`--program` options override globals and configured defaults.

Use `0x`-prefixed addresses and retain any space/segment qualifiers.
Name-or-address targets treat unprefixed values, including `FUN_...`, as exact names.

## Start with a program

Use `ghidra-cli doctor` for prerequisite checks; `doctor --runtime` also verifies
Ghidra startup, bridge communication, and shutdown.

If an AI agent sandbox restricts writes on Linux, set `XDG_*` values to absolute, writable workspace paths before
running the CLI.

For a new executable or library:

```bash
ghidra-cli import ./target.bin --project target --program target.bin
ghidra-cli program info --project target --program target.bin
```

Import creates the project and starts its bridge as needed, and runs analysis
by default. Use `--no-analyze` to defer analysis.

If `main` is absent, use `function list` to choose a name or address.
Raw/headerless input needs explicit language and load parameters; see
[raw import](references/programs.md#raw-import).
On import, `--program NAME` sets the saved project file name; an existing
explicit name is rejected. Use the returned `program` for later commands.
If an import error reports `detail.import_status: "saved"`, do not re-import:
the error retains the program, analysis status, and recovery command arguments.

## Basic Batch

Batch files contain one subcommand per line, without `ghidra-cli`.

```text
# List candidate functions.
function list --fields name,address,size --limit 100
# Find a literal substring in defined strings (case-insensitive).
find string "password"
# Read a function; use its address if the name is ambiguous.
decompile main
# List outgoing calls from this function.
function calls main
# Find references to a function name or data address.
xref to 0x404000
# Read 32 bytes.
memory read 0x404000 32
```

```bash
ghidra-cli batch ./queries.ghidra --project target --program target.bin --json
```

For text not yet defined as strings, use
[memory text search](references/exploration.md#search-strings-xrefs-and-graphs).

Quote multiword arguments; shell variables, command substitutions, and wildcards
are not expanded. See [batch syntax and targeting](references/batch.md) for details.

## Results, edits, and jobs

Output defaults to human-readable on a terminal and compact JSON when piped.
`--json` and `--pretty` explicitly select JSON. Format precedence is `--format`,
`--pretty`, `--json`, the configured format, then terminal detection.
Use `--format ndjson` for newline-delimited JSON. Results go to stdout; errors
and progress go to stderr. JSON modes include structured error detail and
suppress progress.

Edits are saved automatically before success is returned, including analysis,
scripts, and each operation in a batch.
Ordinary edits roll back the request's changes on failure or cancellation
(`detail.rolled_back: true`). Analysis, scripts, imports, exports, and program
open/close/save/delete can retain partial changes or external effects.
After `detail.save_failed: true`, keep the bridge running and retry `program save`
with the same project/program; edits may remain in memory. Do not repeat the edit.
`detail.transaction_failed: true` leaves rollback unconfirmed. Keep the bridge
running and close any outstanding transaction through its owning script before
saving or retrying.

`batch` exits nonzero if any command fails; its report remains on stdout.
Commands run sequentially; later failures do not undo completed edits.
`--on-error continue` (default) continues after ordinary errors, including completed
rollbacks; use `--on-error stop` for dependent edits. Transaction-boundary failures,
save failures, and timeouts always stop the batch. Do not replay successful edits.
See [batch results](references/batch.md#result-structure) for per-command results
and error details.

A socket timeout does not cancel the job. Inspect `job list` for active, queued,
and recent jobs, or `job get ID` for one job, before retrying a mutation.
`job cancel [ID]` defaults to the active job when the ID is omitted.
Queued jobs are removed immediately; running jobs cancel cooperatively.
A timeout is reported with exit 75, distinct from a command failure.

## Read details as needed

| When                                                                       | Reference                                        |
| -------------------------------------------------------------------------- | ------------------------------------------------ |
| Check decompiler metadata, search modes, graphs, filters, or result limits | [Exploration](references/exploration.md)         |
| Refine names, comments, variables, signatures, types, symbols, or tags     | [Refinement](references/refinement.md)           |
| Inspect instructions or PCode, repair analysis boundaries, or patch code   | [Low-level analysis](references/low-level.md)    |
| Run custom Java processing and validate its artifacts                      | [Scripting](references/scripting.md)             |
| Manage projects/programs, import raw input, reanalyze, or export artifacts | [Programs and artifacts](references/programs.md) |
| Check batch quoting, target inheritance, nesting, or result structure      | [Batch](references/batch.md)                     |
