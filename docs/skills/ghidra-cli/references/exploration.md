# Exploration

## Functions and decompilation

```bash
ghidra-cli function list --fields name,address,size --limit 100 --project target
ghidra-cli function get main --project target
ghidra-cli decompile main --with-vars --with-params --project target
ghidra-cli decompile main --format c --project target
ghidra-cli function calls main --project target
ghidra-cli function x-refs main --project target
ghidra-cli function x-refs malloc --project target
```

`decompile` accepts a function name or address; `--with-vars` and `--with-params`
include local-variable and parameter details. Function names must identify one
function; ambiguous names return candidates. Use an address to select the
intended function.

Explicit `--format c` prints the decompiled code without JSON escaping. Use JSON
when you need the accompanying variable/parameter metadata. `--format asm` renders
instruction rows; rows without the required code fields fall back to JSON. Neither
option changes the default TTY/non-TTY behavior.

There is no native decompilation time limit by default; inspect long work with
`jobs` and request a stop with `cancel`. See [job control](../SKILL.md#results-edits-and-jobs).

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
ghidra-cli find instruction "mov" --start 0x401000 --end 0x401100 --project target
ghidra-cli find calls CreateProcessW --project target
ghidra-cli find crypto --project target
ghidra-cli find interesting --project target
ghidra-cli x-ref to malloc --project target
ghidra-cli x-ref to 0x401000 --project target
ghidra-cli x-ref from 0x401000 --project target
ghidra-cli graph calls --project target
ghidra-cli graph callers parse_header --depth 3 --limit 100 --project target
ghidra-cli graph callees main --depth 2 --limit 100 --project target
```

String names and external/import names resolve directly. For plain `graph
callers/callees`, `--limit N` bounds traversal in the Java bridge; filter, sort,
count, or offset may require a broader traversal. See [exports](programs.md#export)
to write a graph as DOT.
For instruction-text matching and disassembly ranges, see
[low-level analysis](low-level.md#disassembly-and-analysis-boundaries).

## Symbols and memory

```bash
ghidra-cli symbol list --limit 100 --project target
ghidra-cli memory map --project target
ghidra-cli memory read 0x401000 64 --project target
```

`memory write` and `memory search` are unsupported and return errors. Use
`patch bytes ADDRESS "HEX BYTES"` and `find bytes "HEX BYTES"` instead.
See [patching](low-level.md#patching) for edit behavior.

## Query controls

`--limit 0` returns all rows. Filters, sorting, pagination, and counts generally
run in Rust after a full fetch; small limits may not bound underlying work.
The default cap also applies with no query options or with only `--fields`.
An explicit limit overrides it; `--count` ignores the default but honors an
explicit offset/limit, returning the selected page's count. Byte, string, and
interesting-function searches have no additional fixed result cap.
Output precedence: explicit format, `--pretty`, `--json`, configured default,
TTY detection.

```bash
ghidra-cli function list --count --project target
ghidra-cli function list --filter "size > 100" --fields name,address,size \
  --limit 40 --project target
```

Filters also combine with `AND` (e.g. `size >= 100 AND name ~ 'crypt'`);
`name ^ 'FUN_'` selects a prefix. For tag filters, see
[function tags](refinement.md#function-tags).
