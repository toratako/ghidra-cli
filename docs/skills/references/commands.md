# ghidra-cli command reference

Use `ghidra-cli <command> --help` for exact flags. Global `--project`, `--program`, `--projects-dir`, `--json`, and `--pretty` may
appear with subcommands. Command-level project/program options override globals and
configured defaults. [SKILL.md](../SKILL.md) covers job control and persistence.

## Project, import, program, and bridge state

```bash
ghidra-cli project create target
ghidra-cli project list
ghidra-cli project info target
ghidra-cli program list --project target
ghidra-cli program info --project target --program target.bin
ghidra-cli status --project target
ghidra-cli jobs --project target
ghidra-cli cancel --project target
ghidra-cli restart --project target --program target.bin
ghidra-cli program save --project target --program target.bin
ghidra-cli stop --project target
```

`project delete NAME` stops its bridge and removes the `.gpr`/`.rep` artifacts.
Import waits for completion. Use `import --no-analyze` to omit analysis and
`analyze --project target --program target.bin` to reanalyze.
`import INPUT --program NAME` saves under that project file name; omitting it
uses the input file name (Ghidra may add a suffix on collision). An explicit name
must be a single file name and must not already exist. The import response reports
the actual saved name. `program list`, `program info`, and `summary` report that
saved name and project file `path`. Other program responses and artifact manifests
also use the saved name. `executable_path` identifies the original input file;
Ghidra's internal Program name can differ and is not used as the CLI display name.
`stats` reports program statistics; `summary` reports the loaded program's
metadata.

### Raw import

Choose raw input's ISA, endianness, and load address from target evidence;
plausible disassembly alone does not validate them.

```bash
ghidra-cli import ./firmware.bin --project firmware \
  --language x86:LE:32:default --base-address 0x8000 \
  --block-name ROM --no-analyze
```

`--base-address`, `--block-name`, `--file-offset`, and `--length` imply
`BinaryLoader`; `--processor` aliases `--language`. Raw import does not establish
an entry point. Use `disasm-at` and `function create` at a known code address.

## Functions and code

```bash
ghidra-cli function list --fields name,address,size --limit 100 --project target
ghidra-cli function get main --project target
ghidra-cli decompile main --with-vars --with-params --project target
ghidra-cli disasm 0x401000 -n 40 --project target
ghidra-cli disasm-at 0x401234 -n 20 --project target
ghidra-cli function calls main --project target
ghidra-cli function x-refs main --project target
ghidra-cli function x-refs malloc --project target
ghidra-cli function rename FUN_00401000 parse_header --project target
ghidra-cli function create 0x401234 parse_entry --project target
ghidra-cli function set-signature parse_header \
  --signature "int parse_header(char *buf, int len)" --project target
ghidra-cli function edit-var parse_header --var local_10 \
  --name header --type "Header *" --project target
ghidra-cli function set-return-type abort_path --type void --project target
ghidra-cli function set-calling-convention parse_header --convention __cdecl --project target
ghidra-cli function set-noreturn abort_path --project target
```

`decompile` accepts a function name or address; `--with-vars` and `--with-params`
include local-variable and parameter details. Re-decompile after type, name, or
signature edits.
There is no native time limit by default; inspect long work with
`jobs` and request a stop with `cancel`.

Function names must identify one function; ambiguous names return candidates.
Use the function address to select the intended target. `function rename` does
not accept `--filter` or `--all`.

`function edit-var FUNCTION --var CURRENT_NAME` edits a local variable or parameter
by exact name; ambiguous names fail with candidates. Supply `--name`, `--type`,
or both. Omitted attributes are not explicitly reassigned. `before` reports the
decompiler's variable and `after` the updated database definition, including name,
type/path, and storage. A rename can leave the database type undefined so the
decompiler continues inferring it. Known name conflicts and invalid types fail
before editing; other failures can retain partial changes.

Use `disasm-at` when auto-analysis missed a known target. If analysis ran through
inline data or chose the wrong boundary:

```bash
ghidra-cli clear 0x401200:0x40121f --to-data --project target
ghidra-cli clear 0x401200:0x40121f --disasm-at 0x401210 --project target
```

Query controls:

`--limit 0` returns all rows. Filters, sorting, pagination, and counts generally
run in Rust after a full fetch; small limits may not bound underlying work.
An explicit limit overrides the default cap; `--count` and `--limit 0` bypass it.
Output precedence: explicit format, `--pretty`, `--json`, configured default,
TTY detection.

```bash
ghidra-cli function list --count --project target
ghidra-cli function list --filter "size > 100" --fields name,address,size \
  --limit 40 --project target
```

## Search, strings, xrefs, and graphs

`find calls TARGET` searches the entire selected program for calls to TARGET,
including resolved thunks and import-pointer references. Rows contain `caller`,
`caller_address`, `call_site`, `callee`, `callee_address`, `type`, and `via` (the
referenced target or pointer/thunk address). Ordinary data references are excluded.
It uses Ghidra's references, not decompiler text; unresolved register/function
pointer calls may still be absent. Names that resolve to distinct functions are
ambiguous; use an address to select one.
`function calls TARGET` lists outgoing calls inside TARGET. Use `graph callers`
or `graph callees` to traverse relationships at a chosen depth.

```bash
ghidra-cli find function "*crypt*" --project target
ghidra-cli strings list --filter "length > 12" --limit 80 --project target
ghidra-cli find string "password" --project target
ghidra-cli strings refs "password" --project target
ghidra-cli find bytes "48 8b 05" --project target
ghidra-cli find calls CreateProcessW --project target
ghidra-cli find crypto --project target
ghidra-cli find interesting --project target
ghidra-cli x-ref to malloc --project target
ghidra-cli x-ref to 0x401000 --project target
ghidra-cli x-ref from 0x401000 --project target
ghidra-cli graph calls --project target
ghidra-cli graph callers parse_header --depth 3 --limit 100 --project target
ghidra-cli graph callees main --depth 2 --limit 100 --project target
ghidra-cli graph export dot --project target
```

String names and external/import names resolve directly. For plain `graph
callers/callees`, `--limit N` bounds traversal in the Java bridge; filter, sort,
count, or offset may require a broader traversal.

Filters also combine with `AND` (e.g. `size >= 100 AND name ~ 'crypt'`);
`name ^ 'FUN_'` selects a prefix.

## Data, symbols, and types

```bash
ghidra-cli symbol list --limit 100 --project target
ghidra-cli symbol create 0x404000 packet_header --project target
ghidra-cli symbol rename packet_header message_header --project target
ghidra-cli memory map --project target
ghidra-cli memory read 0x401000 64 --project target
ghidra-cli type get Header --project target
ghidra-cli type create Header --project target
ghidra-cli type add-field Header --name magic --type uint --offset 0 --project target
ghidra-cli type del-field Header --name magic --project target
ghidra-cli type create-enum Mode --values "Unknown=0,Read=1,Write=2" --project target
ghidra-cli type typedef HeaderAlias Header --project target
ghidra-cli type rename HeaderAlias PacketHeader --project target
ghidra-cli type delete PacketHeader --project target
ghidra-cli type apply 0x404000 Header --project target
ghidra-cli type apply 0x404000 Header --force --project target
ghidra-cli type import-c --category /Recovered \
  'struct Vec3 { float x; float y; float z; }; typedef Vec3 *Vec3Ptr;' \
  --project target
```

`type import-c` accepts exactly one input: inline C code, `--file PATH`, or
`--stdin`. Files are UTF-8 and resolve from the CLI working directory. These
inputs use the same C declaration parser; file input does not add preprocessing
or include-path support.

```bash
ghidra-cli type import-c --file recovered_types.h --category /Recovered
ghidra-cli type import-c --stdin --category /Recovered < recovered_types.h
```

Ambiguous symbol rename/delete requires `--address` or `--filter`, or explicit
`--all` to affect every match. `type create` accepts a bare name and creates an
empty struct; use `set-field`, `add-field`, or `import-c` for its definition.

`memory write` and `memory search` are unsupported and return errors. Use
`patch bytes ADDRESS "HEX BYTES"` and `find bytes "HEX BYTES"` instead.

`type apply --force` clears a conflicting data unit before applying the type.
Type applicability, size, memory range, and field-layout checks precede
destructive edits. Later execution failures can still retain partial changes.

Type expressions accept pointers and fixed-length arrays, such as `byte[16]`,
`Hook *[8]`, and `byte[2][3]`. Array counts are positive decimal integers; sizes
use the selected program's data organization. Ambiguous short names fail with
full paths in `detail.candidates`. Use `/Recovered/Hook` or
`/Recovered/Hook *[8]` to select a category explicitly; an incorrect full path
does not fall back to another category.

Fallback aliases `uint8_t`/`u8`, `uint16_t`/`u16`, `uint32_t`/`u32`, and
`uint64_t`/`u64` have fixed widths of 1, 2, 4, and 8 bytes. Signed equivalents
use `intN_t`/`sN`. Existing types with the requested name take precedence;
ordinary C spellings such as `unsigned int` use the target ABI.

### Growing recovered structures

```bash
ghidra-cli type set-field Manager --offset 0x1c --name hook --type 'Hook *'
ghidra-cli type set-field Manager --offset 0x1c --comment 'Called during shutdown'
ghidra-cli type set-field Manager --offset 0x1c --comment ''
ghidra-cli type clear-field Manager --offset 0x1c
```

`set-field` selects a field by its exact starting byte offset. Supply one or more
of `--name`, `--type`, and `--comment`; omitted attributes keep their current
values. In undefined space, `--type` is required and `--name` is optional.
An empty comment clears it; an empty name is rejected. Offsets accept decimal
and `0x` hexadecimal, including on `add-field`.

Shrinking a field leaves undefined bytes. Growing consumes undefined space or
extends the structure, but cannot overwrite another defined field. Interior
offsets and name collisions fail with the existing field in `detail.field`;
overlaps list `detail.conflicts`. `add-field --offset` uses the same placement
checks; omitting its offset appends as before.

`clear-field` replaces the field with undefined bytes and preserves structure
size and later offsets. Clearing existing padding succeeds with `changed: false`;
an offset outside the structure fails. `del-field --name NAME` still removes
bytes and shifts later fields.

Layout changes require packing to be disabled. Packed structures allow
name/comment edits, but reject type changes and clearing defined fields.
Bit-fields and zero-length fields cannot be edited with these offset commands.

`set-field` and `clear-field` report `changed`, the structure's full `path`,
`offset`, `size_before`, `size_after`, and `before`/`after` field definitions.
`type get` includes `packing_enabled` and each field's `type_path` and `comment`.
An unnamed field has `name: null`; `display_name` gives its generated name.

## Function tags

```bash
ghidra-cli tag list                        # All tags (name, comment, use count)
ghidra-cli tag get <name>                  # Functions carrying a tag
ghidra-cli tag create <name> --comment "…" # Create a tag (comment optional)
ghidra-cli tag add <func> <tag>...         # Attach tags (auto-creates missing ones)
ghidra-cli tag remove <func> <tag>...      # Detach tags (--all clears every tag)
ghidra-cli tag rename <old> <new>          # Rename everywhere it is used
ghidra-cli tag set-comment <name> "…"      # Set/clear a tag's comment
ghidra-cli tag delete <name>               # Delete tag, detaching from all functions
ghidra-cli function list --tag <name>      # Filter by tag (repeatable = AND)
ghidra-cli function list --untagged        # Functions with no tags
```

Tag names are case-sensitive; `add`/`remove` report already-present/absent tags
without error. Function rows have a sorted `tags` array, supporting
`--fields name,address,tags` and `--filter "tags ~ 'crypto'"`.

## PCode and analyzer control

```bash
ghidra-cli pcode at 0x401000 --project target
ghidra-cli pcode function parse_header --project target
ghidra-cli pcode function parse_header --high --project target
ghidra-cli analyzer list --project target
ghidra-cli analyzer set "ASCII Strings" false --project target
ghidra-cli analyzer set "ASCII Strings" true --project target
ghidra-cli analyzer run --project target --program target.bin
```

`analyzer set` only changes the enabled option. Choose names from `analyzer list`
and execute with `analyzer run`.

## Comments, scripts, batch work, and export

`comment get ADDRESS` and `comment list` read comments. `comment set` accepts
`--comment-type EOL` (default), `PRE`, `POST`, or `PLATE`.

Use stdin or a file to preserve comment text containing shell metacharacters:

```bash
printf '%s' 'possible vtable load; verify callers' | \
  ghidra-cli comment set 0x401000 --stdin --project target
ghidra-cli comment set 0x401000 --text-file ./note.txt --project target
```

```bash
ghidra-cli script list --project target
ghidra-cli script run ./scripts/Inspect.java --project target -- --arg value
ghidra-cli script run ./scripts/Inspect.java --expect ./out.csv:10 --project target
ghidra-cli script run - --project target < ./scripts/Inspect.java
ghidra-cli batch ./queries.ghidra --project target
ghidra-cli batch ./edits.ghidra --on-error stop --project target
ghidra-cli program export c --project target -o ./target.c
ghidra-cli graph export dot --project target | jq -r '.[0].output' \
  > ./calls.dot
ghidra-cli patch bytes 0x401234 "90 90" --project target
ghidra-cli patch nop 0x401234 --count 5 --project target
ghidra-cli patch export -o ./target.patched.bin --project target
```

A batch file has one subcommand per line, without `ghidra-cli`. Quote multiword
arguments, for example
`function set-signature main --signature "int main(int argc, char **argv)"`.
Backslashes escape the next character outside quotes; single quotes preserve
literal text. Inside double quotes, backslashes escape `"`, `\`, `$`, and backticks.
Variables, command substitutions, and wildcards are never expanded. Empty lines
and lines starting with `#` are ignored; malformed quoting fails that line and
follows the selected `--on-error` policy.
Per-line `--project`/`--program` override the batch project/current selection;
omitted targets inherit the batch project/current selection even when standalone
query environment defaults exist. Program switches persist for subsequent lines
in that project. Filters, fields,
sorting, limits, and counts apply within each result.
Import inputs and program/patch export destinations resolve relative to the CLI's
working directory, including when reusing a bridge started elsewhere.

Script paths resolve absolutely; results include arguments after `--` and captured
stdout. Artifact hash/read failures return errors. Repeat `--expect PATH[:MIN_ROWS]` to reject missing/empty/short artifacts;
`--allow-empty` permits expected empty files. Inline `script python`/`script java`
are disabled: there is no embedded Python, and Java needs Ghidra's bundle/compile
path. Use `script run PATH` or `script run -` with Java source on stdin.

`program export gzf -o PATH` saves the program before packing, stages the archive
beside its destination, and atomically replaces the destination only after a
successful export. Failure or cancellation before publication preserves an
existing destination; a filesystem without atomic replacement support returns
an error.

`patch nop --count N` walks up to N consecutive instructions (default 1), including
variable-length instructions. A missing first instruction is an error; a later
gap ends successfully with a smaller returned `count`. Check that count. Failed
nested mutations can retain partial changes; see [persistence semantics](../SKILL.md).
`patch nop` supports x86 (`0x90`) and rejects other processors before editing.
For other ISAs, use `patch bytes` with the intended instruction encoding.
