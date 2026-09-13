---
name: ghidra-cli
description: Use ghidra-cli for native-binary reverse engineering with Ghidra, including import of programs, code queries and decompilation, type and annotation edits, Java scripts, patches, and binary export.
---

# Ghidra CLI

The executable is `ghidra-cli`. Read [commands.md](references/commands.md) to select an operation;
use `ghidra-cli <command> --help` for exact arguments.

Global `--project PROJECT --program PROGRAM` select the target. Each project
reuses a JVM bridge; program operations are serialized while `status`, `jobs`,
and `cancel` remain responsive.

Import creates the project as needed and starts the bridge automatically. A fresh
import analyzes and commits before opening the persistent bridge.
`--no-analyze` omits analysis; `analyze` explicitly reruns it, so it is not needed
immediately after a normal import.

## Basic commands

Use `ghidra-cli doctor` to check readiness or diagnose startup failures.

For a new executable or library:

```bash
ghidra-cli import ./target.bin --project target --program target.bin
ghidra-cli summary --project target --program target.bin
ghidra-cli decompile main --with-vars --with-params --project target --program target.bin
```

`summary` reports the loaded program's format, language, image base, and function
count. If `main` is absent, use `function list` to choose a name or address.
Raw/headerless input needs explicit language and load parameters; see
[raw import](references/commands.md#raw-import).

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

`batch` exits nonzero if any command fails; attempted results and error details
are in `detail.results`. Ordinary errors allow subsequent commands to run; save
failures and timeouts stop the batch, with `not_executed` counting remaining commands.
Do not replay successful edits.

A socket timeout does not cancel the job. Inspect `jobs [ID]` before retrying a
mutation; `cancel [ID]` requests cancellation. Queued jobs are removed immediately;
running jobs cancel cooperatively. A timeout is reported with exit 75, distinct
from a command failure.
