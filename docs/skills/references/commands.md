# ghidra-cli command reference

Use `ghidra <command> --help` for exact flags. Global `--project`, `--program`,
`--projects-dir`, `--json`, and `--pretty` flags may appear with subcommands.
Command-level project/program options override global options and configured
defaults. [SKILL.md](../SKILL.md) describes job control and persistence.

## Project, import, program, and bridge state

```bash
ghidra project create target
ghidra project list
ghidra project info target
ghidra program list --project target
ghidra program info --project target --program target.bin
ghidra status --project target
ghidra jobs --project target
ghidra cancel --project target
ghidra restart --project target --program target.bin
ghidra program save --project target --program target.bin
ghidra stop --project target
```

`project delete NAME` stops its bridge and removes the `.gpr`/`.rep` artifacts.
Use `import --detach` to return while import continues, `--no-analyze` to omit
analysis, and `analyze --project target --program target.bin` to reanalyze.
`stats` reports program statistics; `summary` reports the loaded program's
metadata.

### Raw import

Choose raw input's ISA, endianness, and load address from target evidence;
plausible disassembly alone does not validate them.

```bash
ghidra import ./firmware.bin --project firmware \
  --language x86:LE:32:default --base-address 0x8000 \
  --block-name ROM --no-analyze
```

`--base-address`, `--block-name`, `--file-offset`, and `--length` imply
`BinaryLoader`; `--processor` aliases `--language`. Raw import does not establish
an entry point. Use `disasm-at` and `function create` at a known code address.

## Functions and code

```bash
ghidra function list --fields name,address,size --limit 100 --project target
ghidra function get main --project target
ghidra decompile main --with-vars --with-params --project target
ghidra disasm 0x401000 -n 40 --project target
ghidra disasm-at 0x401234 -n 20 --project target
ghidra function calls main --project target
ghidra function x-refs main --project target
ghidra function x-refs malloc --project target
ghidra function rename FUN_00401000 parse_header --project target
ghidra function create 0x401234 parse_entry --project target
ghidra function set-signature parse_header \
  --signature "int parse_header(char *buf, int len)" --project target
ghidra function set-var-type parse_header --var local_10 \
  --type "Header *" --project target
ghidra function set-return-type abort_path --type void --project target
ghidra function set-calling-convention parse_header --convention __cdecl --project target
ghidra function set-noreturn abort_path --project target
```

`decompile` accepts a function name or address; `--with-vars` and `--with-params`
include local-variable and parameter details. After type, name, or signature
edits, decompile the affected function again. Decompilation has no native time
limit by default; use `jobs` to inspect long work and `cancel` to request a stop.

Use `disasm-at` when auto-analysis missed a known target. If analysis ran through
inline data or chose the wrong boundary:

```bash
ghidra clear 0x401200:0x40121f --to-data --project target
ghidra clear 0x401200:0x40121f --disasm-at 0x401210 --project target
```

Query controls:

`--limit 0` returns all rows. Filtering, sorting, pagination, and counts generally
run in Rust after fetching the full dataset, so a small result limit does not
always bound the underlying work. Explicit output format selection precedes
`--pretty`, then `--json`, then TTY detection.

```bash
ghidra function list --count --project target
ghidra function list --filter "size > 100" --fields name,address,size \
  --limit 40 --project target
```

## Search, strings, xrefs, and graphs

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
ghidra graph calls --project target
ghidra graph callers parse_header --depth 3 --limit 100 --project target
ghidra graph callees main --depth 2 --limit 100 --project target
ghidra graph export dot --project target
```

String names and external/import names resolve directly. For plain `graph
callers/callees`, `--limit N` bounds traversal in the Java bridge; filter, sort,
count, or offset may require a broader traversal.

Filters also combine with `AND` (e.g. `size >= 100 AND name ~ 'crypt'`);
`name ^ 'FUN_'` selects a prefix.

## Data, symbols, and types

```bash
ghidra symbol list --limit 100 --project target
ghidra symbol create 0x404000 packet_header --project target
ghidra symbol rename packet_header message_header --project target
ghidra memory map --project target
ghidra memory read 0x401000 64 --project target
ghidra type get Header --project target
ghidra type create Header --project target
ghidra type add-field Header --name magic --type uint --offset 0 --project target
ghidra type del-field Header --name magic --project target
ghidra type create-enum Mode --values "Unknown=0,Read=1,Write=2" --project target
ghidra type typedef HeaderAlias Header --project target
ghidra type rename HeaderAlias PacketHeader --project target
ghidra type delete PacketHeader --project target
ghidra type apply 0x404000 Header --project target
ghidra type apply 0x404000 Header --force --project target
ghidra type import-c --category /Recovered \
  'struct Vec3 { float x; float y; float z; }; typedef Vec3 *Vec3Ptr;' \
  --project target
```

Ambiguous symbol rename/delete requires `--address` or `--filter`, or explicit
`--all` to affect every match. `type create` accepts a bare name and creates an
empty struct; use `add-field` or `import-c` for its definition.

`type apply --force` clears a conflicting data unit before applying the type.

## Function tags

```bash
ghidra tag list                        # All tags (name, comment, use count)
ghidra tag get <name>                  # Functions carrying a tag
ghidra tag create <name> --comment "…" # Create a tag (comment optional)
ghidra tag add <func> <tag>...         # Attach tags (auto-creates missing ones)
ghidra tag remove <func> <tag>...      # Detach tags (--all clears every tag)
ghidra tag rename <old> <new>          # Rename everywhere it is used
ghidra tag set-comment <name> "…"      # Set/clear a tag's comment
ghidra tag delete <name>               # Delete tag, detaching from all functions
ghidra function list --tag <name>      # Filter by tag (repeatable = AND)
ghidra function list --untagged        # Functions with no tags
```

Tag names are case-sensitive. `tag add`/`remove` are idempotent (already-present
and not-present tags are reported, not errors). Function rows include a sorted
`tags` array, so `--fields name,address,tags` and `--filter "tags ~ 'crypto'"`
work too.

## PCode and analyzer control

```bash
ghidra pcode at 0x401000 --project target
ghidra pcode function parse_header --project target
ghidra pcode function parse_header --high --project target
ghidra analyzer list --project target
ghidra analyzer set "ASCII Strings" false --project target
ghidra analyzer set "ASCII Strings" true --project target
ghidra analyzer run --project target --program target.bin
```

`analyzer set NAME true|false` changes the enabled option; it does not run
analysis. Use names from `analyzer list`; run analysis with `analyzer run`.

## Comments, scripts, batch work, and export

`comment get ADDRESS` and `comment list` read comments. `comment set` accepts
`--comment-type EOL` (default), `PRE`, `POST`, or `PLATE`.

Prefer stdin or a file for arbitrary comment text so shell metacharacters are not
rewritten before ghidra-cli sees them:

```bash
printf '%s' 'possible vtable load; verify callers' | \
  ghidra comment set 0x401000 --stdin --project target
ghidra comment set 0x401000 --text-file ./note.txt --project target
```

```bash
ghidra script list --project target
ghidra script run ./scripts/Inspect.java --project target -- --arg value
ghidra script run ./scripts/Inspect.java --expect ./out.csv:10 --project target
ghidra script run - --project target < ./scripts/Inspect.java
ghidra batch ./queries.ghidra --project target
ghidra program export c --project target -o ./target.c
ghidra graph export dot --project target | jq -r '.[0].output' \
  > ./calls.dot
ghidra patch bytes 0x401234 "90 90" --project target
ghidra patch nop 0x401234 --count 5 --project target
ghidra patch export -o ./target.patched.bin --project target
```

A batch file contains one subcommand per line without the `ghidra` prefix.

Script paths resolve absolutely; arguments after `--` and captured stdout are
returned with the result. Repeat `--expect PATH[:MIN_ROWS]` to reject missing,
empty, or short artifacts; `--allow-empty` permits an expected empty file.
Inline `script python`/`script java` are disabled: the bridge has no embedded
Python interpreter, and Java scripts go through Ghidra's bundle/compile path.
Use `script run PATH` or `script run -` with Java source on stdin.

`patch nop --count N` walks up to N consecutive instructions (default 1), including
variable-length instructions. A missing first instruction is an error; a later
gap ends successfully with a smaller returned `count`. Check that count. Failed
nested mutations can retain partial changes; see [persistence semantics](../SKILL.md).
The current implementation fills with `0x90` on x86 and `0x00` elsewhere; it does
not assemble ISA-specific NOPs. For other ISAs, use `patch bytes` with the intended
instruction encoding.
