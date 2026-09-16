---
name: ghidra-cli
description: Use ghidra-cli for native-binary reverse engineering with Ghidra, including import of programs, code queries and decompilation, type and annotation edits, Java scripts, patches, and binary export.
---

# Ghidra CLI

The executable is `ghidra-cli`. Use `ghidra-cli <command> --help` for exact
arguments. Read the references below only when their details are needed.

Global `--project PROJECT --program PROGRAM` select the target. Each project
reuses a JVM bridge; program operations are serialized while `status`, `jobs`,
and `cancel` remain responsive.
Global `--project`, `--program`, `--projects-dir`, `--json`, and `--pretty` may
appear with subcommands. Command-level project/program options override globals
and configured defaults.

## Start with a program

Use `ghidra-cli doctor` for prerequisite checks; `doctor --runtime` also verifies
Ghidra startup, bridge communication, and shutdown.

For a new executable or library:

```bash
ghidra-cli import ./target.bin --project target --program target.bin
ghidra-cli summary --project target --program target.bin
```

Import creates the project as needed and starts the bridge automatically. A fresh
import analyzes and commits before opening the persistent bridge.
`--no-analyze` omits analysis; `analyze` explicitly reruns it, so it is not needed
immediately after a normal import.

`summary` reports the loaded program's format, language, image base, and function
count. If `main` is absent, use `function list` to choose a name or address.
Raw/headerless input needs explicit language and load parameters; see
[raw import](references/programs.md#raw-import).
On import, `--program NAME` sets the saved project file name; an existing
explicit name is rejected. Use the returned `program` for later commands.
If an import error reports `detail.import_status: "saved"`, do not re-import:
the error retains the program, analysis status, and recovery command arguments.

## Batch

Batch files contain one subcommand per line, without `ghidra-cli`.
Example `queries.ghidra`:

```text
decompile main --with-vars --with-params
function calls main
```

```bash
ghidra-cli batch ./queries.ghidra --project target --program target.bin --json
```

Quote multiword arguments; shell variables, command substitutions, and wildcards
are not expanded. See [batch syntax and targeting](references/batch.md) for details.

## Results, edits, and jobs

Output defaults to human-readable on a terminal and compact JSON when piped.
`--json` and `--pretty` explicitly select JSON, including for management and
configuration commands; `--fields` restricts query result fields. Results go to
stdout. In JSON modes, errors on stderr have `status`, `message`, `exit_code`,
and optional `detail` fields.

Progress goes to stderr in text mode; JSON modes and `--quiet` suppress it.
Explicit verbosity still enables diagnostic logs.

Edits are saved automatically before success is returned, including analysis,
scripts, and each operation in a batch.
After a save failure, keep the bridge running and retry `program save` with the
same project/program; it saves in place without repeating the edit.
Failed or cancelled operations can retain partial changes; do not assume rollback.

`batch` exits nonzero if any command fails, but writes its report to stdout even
on partial failure. In JSON output, read `.[0].results` for attempted results and
per-command error details; stderr contains only the batch diagnostic and summary.
`--on-error continue` (default) runs subsequent commands
after ordinary errors; use `--on-error stop` for edits that depend on earlier
commands succeeding.
Save failures and timeouts always stop the batch, with
`not_executed` counting remaining commands. Do not replay successful edits.

A socket timeout does not cancel the job. Inspect `jobs [ID]` before retrying a
mutation; `cancel [ID]` requests cancellation. Queued jobs are removed immediately;
running jobs cancel cooperatively. A timeout is reported with exit 75, distinct
from a command failure.

## Read details as needed

| When | Reference |
|---|---|
| Choose queries, follow references, inspect memory, or control result size | [Exploration](references/exploration.md) |
| Refine names, comments, variables, signatures, types, symbols, or tags | [Refinement](references/refinement.md) |
| Inspect instructions or PCode, repair analysis boundaries, or patch code | [Low-level analysis](references/low-level.md) |
| Run custom Java processing and validate its artifacts | [Scripting](references/scripting.md) |
| Manage projects/programs, import raw input, reanalyze, or export artifacts | [Programs and artifacts](references/programs.md) |
| Check batch quoting, target inheritance, nesting, or result structure | [Batch](references/batch.md) |
