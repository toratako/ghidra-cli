---
name: ghidra-cli
description: Use ghidra-cli for native-binary reverse engineering with Ghidra, including import of programs, code queries and decompilation, type and annotation edits, Java scripts, patches, and binary export.
---

# Ghidra CLI

The executable is `ghidra`. This skill is the canonical reference for RE agents
using the CLI. Read [commands.md](references/commands.md) to select an operation;
use `ghidra <command> --help` for exact arguments.

Global `--project PROJECT --program PROGRAM` select the target. Each project
reuses a JVM bridge; program operations are serialized while `status`, `jobs`,
and `cancel` remain responsive.

Fresh import analyzes and commits before opening the persistent bridge.
`--no-analyze` omits analysis; `analyze` explicitly reruns it.

Output defaults to human-readable on a terminal and compact JSON when piped.
`--json` and `--pretty` explicitly select JSON; `--fields` restricts result fields.

Edits can remain in memory. `program save` flushes by restarting the bridge;
`stop` flushes and ends it. `program close` is not a substitute for saving.
A failed nested mutation can retain partial changes; do not assume rollback.

A socket timeout does not cancel the job. Inspect `jobs [ID]` before retrying a
mutation; `cancel [ID]` requests cancellation. Queued jobs are removed immediately;
running jobs cancel cooperatively. A timeout is reported with exit 75, distinct
from a command failure.
