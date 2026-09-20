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
Global `--project`, `--program`, `--projects-dir`, `--json`, and `--pretty` may
appear with subcommands. Command-level project/program options override globals
and configured defaults.

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

Import creates the project as needed and starts the bridge automatically. A fresh
import analyzes and commits before opening the persistent bridge.
`--no-analyze` omits analysis; `analyze` explicitly reruns it, so it is not needed
immediately after a normal import.

`program info` reports the loaded program's format, language, image base, and function
count. If `main` is absent, use `function list` to choose a name or address.
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

An empty `find string` result does not prove the text is absent from memory.

Quote multiword arguments; shell variables, command substitutions, and wildcards
are not expanded. See [batch syntax and targeting](references/batch.md) for details.

## Results, edits, and jobs

Output defaults to human-readable on a terminal and compact JSON when piped.
`--json` and `--pretty` explicitly select JSON, including for management and
configuration commands. Use `--format ndjson` for newline-delimited JSON.
`--fields` restricts query result fields. Results go to
stdout. In JSON modes, errors on stderr have `status`, `message`, `exit_code`,
and optional `detail` fields.

Progress goes to stderr in text mode; JSON modes and `--quiet` suppress it.
Explicit verbosity still enables diagnostic logs.

Edits are saved automatically before success is returned, including analysis,
scripts, and each operation in a batch.
After a save failure, keep the bridge running and retry `program save` with the
same project/program; it saves in place without repeating the edit.
Failed or cancelled operations can retain partial changes; do not assume rollback.

`batch` exits nonzero if any command fails; its report remains on stdout.
`--on-error continue` (default) runs subsequent commands after ordinary errors;
use `--on-error stop` for dependent edits. Save failures and timeouts always stop
the batch. Do not replay successful edits.
See [batch results](references/batch.md#result-structure) for per-command results
and error details.

A socket timeout does not cancel the job. Inspect `job list` for active, queued,
and recent jobs, or `job get ID` for one job, before retrying a mutation.
`job get` requires an ID. `job cancel [ID]` requests cancellation, defaulting to
the active job when the ID is omitted. Queued jobs are removed immediately;
running jobs cancel cooperatively. A timeout is reported with exit 75, distinct
from a command failure.

## Read details as needed

| When                                                                       | Reference                                        |
| -------------------------------------------------------------------------- | ------------------------------------------------ |
| Check decompiler metadata, search modes, graphs, filters, or result limits | [Exploration](references/exploration.md)         |
| Refine names, comments, variables, signatures, types, symbols, or tags     | [Refinement](references/refinement.md)           |
| Inspect instructions or PCode, repair analysis boundaries, or patch code   | [Low-level analysis](references/low-level.md)    |
| Run custom Java processing and validate its artifacts                      | [Scripting](references/scripting.md)             |
| Manage projects/programs, import raw input, reanalyze, or export artifacts | [Programs and artifacts](references/programs.md) |
| Check batch quoting, target inheritance, nesting, or result structure      | [Batch](references/batch.md)                     |
