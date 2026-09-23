---
name: ghidra-cli
description: Use ghidra-cli for native-binary reverse engineering with Ghidra, including import of programs, code queries and decompilation, type and annotation edits, Java scripts, patches, and binary export.
---

# Ghidra CLI

Use `ghidra-cli <command> --help` for exact arguments.

## Target and output

Global `--project PROJECT --program PROGRAM` select the target. Each project
reuses a JVM bridge; program operations are serialized while `bridge status`,
`job list`, `job get`, and `job cancel` remain responsive.
Command-level `--project`/`--program` options override globals and configured defaults.

Addresses use `0x` with any space/segment qualifiers.
Name-or-address targets treat unprefixed values, including `FUN_...`, as exact names.

Output defaults to human-readable on a terminal and compact JSON when piped.
`--json` and `--pretty` explicitly select JSON. Format precedence is `--format`,
`--pretty`, `--json`, the configured format, then terminal detection.
Normal JSON results are in `.data`; batch entries use
`.data.results[].result.data`.
`--format ndjson` emits one list element per line without the outer wrapper or
metadata. Results go to stdout; errors and progress go to stderr. JSON modes
include structured error detail and suppress progress.

## Start

Use `ghidra-cli doctor` for prerequisite checks; `doctor --runtime` also verifies
Ghidra startup, bridge communication, and shutdown.

If an AI agent sandbox restricts writes on Linux, set `XDG_*` values to absolute, writable workspace paths before running the CLI.

```bash
ghidra-cli program import ./target.bin --project target --name target.bin
ghidra-cli program info target.bin --project target
```

Import creates the project and starts its bridge as needed, and runs analysis
by default; `--no-analyze` defers analysis.

Raw/headerless input needs explicit language and load parameters; see
[raw import](references/programs.md#raw-import).
An import error with `detail.import_status: "saved"` means the program was saved;
the error retains its name, analysis status, and recovery command arguments.

## Batch

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

Shell variables, command substitutions, and wildcards are not expanded.
See [batch syntax and targeting](references/batch.md).

`find string` searches defined strings;
[memory text search](references/exploration.md#search-strings-xrefs-and-graphs)
also covers undefined memory.

## Results, edits, and jobs

Edits are saved automatically before success is returned, including analysis,
scripts, and each operation in a batch.
Ordinary edits roll back the request's changes on failure or cancellation
(`detail.rolled_back: true`). Analysis, scripts, imports, exports, and program
open/close/save/delete can retain partial changes or external effects.
After `detail.save_failed: true`, edits may remain only in the live bridge.
`program save` with the same project/program retries persistence without repeating
the edit. `detail.transaction_failed: true` leaves rollback unconfirmed;
recovery involves closing any outstanding transaction through its owning script
in the live bridge, then saving.

`batch` exits nonzero if any command fails; its report remains on stdout.
Commands run sequentially; later failures do not undo completed edits.
`--on-error continue` (default) continues after ordinary errors, including completed
rollbacks. Transaction-boundary failures, save failures, timeouts, and unknown
command outcomes always stop the batch. See [batch results](references/batch.md#result-structure)
and [resuming a stopped batch](references/batch.md#resuming).

A socket timeout (exit 75) does not cancel the job. For lost responses or timeouts,
the error's `recovery.argv` retrieves the operation with `job result ID`.
Retrieval exits 75 while pending; exit 0 means retrieval succeeded. The original
outcome is in `response.status` and `response.detail`.
Results are temporary and lost on bridge restart; unavailable does not mean
unexecuted. One CLI command can send several operations; the recovered `command`
identifies which operation the result describes.
`job cancel` removes queued jobs immediately; running jobs cancel cooperatively.

## Read details as needed

| When | Reference |
| --- | --- |
| Locate relevant code or data, follow references, or interpret decompiler and query results | [Exploration](references/exploration.md) |
| Record recovered names, prototypes, variable types, or annotations | [Refinement](references/refinement.md) |
| Resolve calls through tables or thunks, or correct call-site prototypes and ABI metadata | [Calls and ABI](references/calls.md) |
| Find uses of a type or field, define types, or recover object layouts | [Types](references/types.md) |
| Inspect CFG/P-code, repair instruction or function definitions, model memory, or patch bytes | [Low-level analysis](references/low-level.md) |
| Correct import settings or image base, choose reanalysis scope, share types, or archive/export work | [Programs and artifacts](references/programs.md) |
| Group queries or edits, select batch targets, or resume a stopped batch | [Batch](references/batch.md) |
| Run Java scripts or validate their artifacts | [Scripting](references/scripting.md) |
