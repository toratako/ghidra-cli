---
name: ghidra-cli
description: Use ghidra-cli for native-binary reverse engineering with Ghidra, including import of programs, code queries and decompilation, type and annotation edits, Java scripts, patches, and binary export.
---

# Ghidra CLI

Use `ghidra-cli <command> --help` for exact arguments.

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

```bash
ghidra-cli program import ./target.bin --project target --name target.bin
ghidra-cli program info target.bin --project target
```

Import creates the project and starts its bridge as needed, and runs analysis
by default. Use `--no-analyze` to defer analysis.

Raw/headerless input needs explicit language and load parameters; see
[raw import](references/programs.md#raw-import).
Use the imported `program` name returned by the CLI for later commands.
If an import error reports `detail.import_status: "saved"`, do not re-import:
the error retains the program, analysis status, and recovery command arguments.

## Basic Batch

Batch files contain one subcommand per line, without `ghidra-cli`.

```text
function list --fields name,address,size --limit 100
find string "password"
decompile main
graph callees main
xref to 0x404000
memory read 0x404000 --size 32
```

```bash
ghidra-cli batch ./queries.ghidra --project target --program target.bin --json
```

For text not yet defined as strings, use
[memory text search](references/exploration.md#search-strings-xrefs-and-graphs).

Shell variables, command substitutions, and wildcards are not expanded.
See [batch syntax and targeting](references/batch.md).

## Results, edits, and jobs

Output defaults to human-readable on a terminal and compact JSON when piped.
`--json` and `--pretty` explicitly select JSON. Format precedence is `--format`,
`--pretty`, `--json`, the configured format, then terminal detection.
Read normal JSON results from `.data`; batch entries use
`.data.results[].result.data`.
Use `--format ndjson` for one list element per line without the outer wrapper or
metadata. Results go to stdout; errors and progress go to stderr. JSON modes
include structured error detail and suppress progress.

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
save failures, timeouts, and unknown command outcomes always stop the batch.
Do not replay successful edits; see [resuming a stopped batch](references/batch.md#resuming).
See [batch results](references/batch.md#result-structure) for per-command results
and error details.

A socket timeout does not cancel the job. For lost responses or timeouts, run
`recovery.argv` from the error to retrieve that operation with `job result ID`.
Exit 0 means retrieval succeeded: inspect `response.status` and `response.detail`
for the original outcome. Exit 75 means it is still pending. Results are temporary
and disappear on bridge restart; an unavailable result does not prove non-execution.
One CLI command can send several operations, so check the recovered `command`
before deciding whether to repeat a batch line. Use `job list` to find jobs and
`job get ID` to inspect progress or result availability.
`job cancel` removes queued jobs immediately; running jobs cancel cooperatively.
A timeout is reported with exit 75, distinct from a command failure.

## Read details as needed

| When                                                                       | Reference                                        |
| -------------------------------------------------------------------------- | ------------------------------------------------ |
| Check decompiler metadata, pointer/VTables, file mappings, search modes, graphs, or result limits | [Exploration](references/exploration.md)         |
| Refine names, types, prototypes, variables, namespaces, references, constants, or annotations | [Refinement](references/refinement.md)           |
| Inspect instructions/PCode, fix function boundaries, flow or decoding context, model RAM/MMIO/overlays, or patch code | [Low-level analysis](references/low-level.md) |
| Run custom Java processing and validate its artifacts                      | [Scripting](references/scripting.md)             |
| Import or rebase programs, choose reanalysis scope, manage projects, or export | [Programs and artifacts](references/programs.md) |
| Check batch quoting, target inheritance, nesting, or result structure      | [Batch](references/batch.md)                     |
