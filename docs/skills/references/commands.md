# ghidra-cli working reference

Use this as a map of useful command families, not as a fixed analysis sequence.
Global `--project`, `--program`, `--projects-dir`, `--json`, and `--pretty` flags
may appear with subcommands.

## Project, program, and bridge state

```bash
ghidra project list
ghidra program list --project target
ghidra program info --project target --program target.bin
ghidra status --project target
ghidra jobs --project target
ghidra cancel --project target
ghidra restart --project target --program target.bin
ghidra program save --project target --program target.bin
ghidra stop --project target
```

One bridge is associated with each project. `jobs [JOB_ID]` exposes active,
queued, and recent work. `cancel [JOB_ID]` requests cooperative cancellation and
does not imply an immediate JVM kill.

Fresh imports are analyzed and committed durably before the persistent bridge is
started. Use `ghidra import ... --no-analyze` when analysis is intentionally
skipped.

Write operations are not immediately visible to another Ghidra process. Use
`program save` after important mutations when durability or GUI visibility is
required. It restarts the bridge as part of the save operation.

## Functions, code, and analysis repair

```bash
ghidra function list --fields name,address,size --limit 100 --project target
ghidra function get main --project target
ghidra decompile main --with-vars --with-params --project target
ghidra disasm 0x401000 -n 40 --project target
ghidra disasm-at 0x401234 -n 20 --project target
ghidra function calls main --project target
ghidra function x-refs main --project target
ghidra function x-refs malloc --project target   # external/import names resolve too
ghidra function rename FUN_00401000 parse_header --project target
ghidra function create 0x401234 parse_entry --project target
ghidra function set-signature parse_header \
  --signature "int parse_header(char *buf, int len)" --project target
ghidra function set-var-type parse_header --var local_10 \
  --type "Header *" --project target
ghidra function set-noreturn abort_path --project target
```

Use `disasm-at` when auto-analysis never reached a computed-jump target. If
Ghidra incorrectly disassembled through inline data, clear the bad code units and
optionally restart disassembly at the correct boundary:

```bash
ghidra clear 0x401200:0x40121f --to-data --project target
ghidra clear 0x401200:0x40121f --disasm-at 0x401210 --project target
```

Targets accept names or addresses where the command exposes a target argument.
Use `find function` when symbols are incomplete.

When result volume is unknown, count before fetching details:

```bash
ghidra function list --count --project target
ghidra function list --filter "size > 100" --fields name,address,size \
  --limit 40 --project target
```

## Search, strings, xrefs, and graphs

Names are often unknown at first. Search before guessing:

```bash
ghidra find function "*crypt*" --project target
ghidra strings list --filter "length > 12" --limit 80 --project target
ghidra find string "password" --project target
ghidra strings refs "password" --project target
ghidra find bytes "48 8b 05" --project target
ghidra find calls CreateProcessW --project target
ghidra find crypto --project target
ghidra find interesting --project target
ghidra x-ref to malloc --project target
ghidra x-ref to 0x401000 --project target
ghidra x-ref from 0x401000 --project target
ghidra graph callers parse_header --depth 3 --limit 100 --project target
ghidra graph callees main --depth 2 --limit 100 --project target
ghidra graph export dot --project target
```

For `graph callers` / `graph callees`, a plain `--limit N` is a bridge-side
traversal bound rather than only an output truncation. `--limit 0` requests an
unbounded result. If filter, sort, count, or offset is also requested, the CLI may
need a complete traversal to preserve query semantics.

Filter expressions support comparisons and composition, for example:

```bash
ghidra function list --filter "size >= 100 AND name ~ 'crypt'" --project target
ghidra symbol list --filter "name ^ 'FUN_'" --count --project target
```

## Symbols and types

```bash
ghidra symbol list --limit 100 --project target
ghidra memory map --project target
ghidra memory read 0x401000 64 --project target
ghidra type get Header --project target
ghidra type create Header --project target
ghidra type add-field Header --name magic --type uint --offset 0 --project target
ghidra type create-enum Mode --values "Unknown=0,Read=1,Write=2" --project target
ghidra type apply 0x404000 Header --project target
ghidra type apply 0x404000 Header --force --project target
ghidra type import-c --category /Recovered \
  'struct Vec3 { float x; float y; float z; }; typedef Vec3 *Vec3Ptr;' \
  --project target
```

`type import-c` uses Ghidra's C parser.
`type apply --force` clears a conflicting data unit before applying the requested type.

Types and symbol edits affect the Ghidra project. Re-decompile consumers after
material changes rather than assuming prior pseudocode still reflects them.

## PCode and analyzer control

```bash
ghidra pcode at 0x401000 --project target
ghidra pcode function parse_header --project target
ghidra pcode function parse_header --high --project target
ghidra analyzer list --project target
ghidra analyzer run --project target --program target.bin
```

The current bundled revision exposes analyzer enable/disable support internally,
but the `analyzer set` CLI parser has a known positional-boolean bug; see
[workarounds.md](workarounds.md) before trying to toggle an analyzer.

## Comments, scripts, batch work, and export

For arbitrary prose, prefer stdin or a file so shell metacharacters cannot alter
the comment before ghidra-cli sees it:

```bash
printf '%s' 'possible vtable load; verify callers' | \
  ghidra comment set 0x401000 --stdin --project target
ghidra comment set 0x401000 --text-file /reports/note.txt --project target
```

Scripts may be files or one-off Java supplied on stdin:

```bash
ghidra script run /reports/scripts/Inspect.java --project target -- --arg value
ghidra script run - --project target < /reports/scripts/Inspect.java
ghidra batch /reports/queries.ghidra --project target
ghidra program export c --project target -o /reports/target.c
ghidra graph export dot --project target | jq -r '.[0].output' \
  > /reports/calls.dot
ghidra patch bytes 0x401234 "90 90" --project target
ghidra patch export -o /reports/target.patched.bin --project target
```

A batch file contains one subcommand per line without the `ghidra` prefix.
Treat patch commands as edits to the project view until an explicit patch export
creates a standalone binary. Use `program save` if the in-project mutation must
also survive a fresh bridge or become visible in the GUI.
