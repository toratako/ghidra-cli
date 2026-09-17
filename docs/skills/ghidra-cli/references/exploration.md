# Exploration

## Functions and decompilation

```bash
ghidra-cli function list --fields name,address,size --limit 100 --project target
ghidra-cli function get main --project target
ghidra-cli decompile main --with-vars --with-params --project target
ghidra-cli decompile main --format c --project target
ghidra-cli function calls main --project target
ghidra-cli x-ref to main --project target
ghidra-cli x-ref to malloc --project target
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
`job list` and request a stop with `job cancel`. See [job control](../SKILL.md#results-edits-and-jobs).

## Search, strings, xrefs, and graphs

`find calls TARGET` searches the entire selected program for calls to TARGET,
including resolved thunks and import-pointer references. Rows contain `caller`,
`caller_address`, `call_site`, `callee`, `callee_address`, `type`, and `via` (the
referenced target or pointer/thunk address). Ordinary data references are excluded.
It uses Ghidra's references, not decompiler text; unresolved register/function
pointer calls may still be absent. Names that resolve to distinct functions are
ambiguous; use an address to select one.
`function calls TARGET` lists outgoing calls inside TARGET. Use `graph callers`
or `graph callees` to traverse relationships at a chosen depth. `graph callers`
uses the same thunk/import-pointer resolution and call-site checks as `find calls`;
passing a function pointer as a parameter does not make the enclosing function a caller.

```bash
ghidra-cli function list --filter "name~crypt" --project target
ghidra-cli strings list --filter "length > 12" --limit 80 --project target
ghidra-cli find string "password" --project target
ghidra-cli find text "Password" --project target
ghidra-cli find text "Password" --encoding utf-16le --project target
ghidra-cli find text "日本" --encoding shift_jis --project target
ghidra-cli strings refs "password" --project target
ghidra-cli find bytes "48 8b 05" --project target
ghidra-cli find instruction "mov" --start 0x401000 --end 0x401100 --project target
ghidra-cli find calls CreateProcessW --project target
ghidra-cli x-ref to malloc --project target
ghidra-cli x-ref to 0x401000 --project target
ghidra-cli x-ref from 0x401000 --project target
ghidra-cli graph calls --project target
ghidra-cli graph callers parse_header --depth 3 --limit 100 --project target
ghidra-cli graph callees main --depth 2 --limit 100 --project target
```

`find string` searches only defined string values, using case-insensitive literal
substring matching. It no longer falls back to raw memory when nothing matches;
an empty result does not establish that the text is absent from the binary.

`find text TEXT` searches the program's loaded memory regardless of string
definitions. It encodes the non-empty literal TEXT using `--encoding` (default
`utf-8`) and matches those exact bytes, including overlapping occurrences.
Matching is case-sensitive; no regular expressions or character normalization
are applied. Encodings use Java charset names and aliases, including `ascii`,
`utf-8`, `utf-16le`, `utf-16be`, `shift_jis`, and `windows-31j` (CP932).
Unknown encodings and text that cannot be represented in the encoding are errors.
No NUL terminator is added. Use `utf-16le` or `utf-16be` for UTF-16 without a BOM;
Java's `utf-16` encoding includes a BOM in the search bytes.
Rows contain `address` (the match start), `byte_length`, and the canonical
`encoding` name. Search does not create string definitions or infer surrounding
string boundaries. `find bytes HEX` remains available for exact byte patterns.

String names and external/import names resolve directly. For plain `graph
callers/callees`, `--limit N` bounds traversal in the Java bridge; filter, sort,
count, or offset may require a broader traversal.
For instruction-text matching and disassembly ranges, see
[low-level analysis](low-level.md#disassembly-and-analysis-boundaries).

## Symbols and memory

```bash
ghidra-cli symbol list --limit 100 --project target
ghidra-cli memory map --project target
ghidra-cli memory read 0x401000 64 --project target
```

Use `memory write ADDRESS "HEX BYTES"` to edit bytes and
`find bytes "HEX BYTES"` to search them.
See [patching](low-level.md#patching) for edit behavior.

## Query controls

Use `function list`, `strings list`, and `memory map` for their respective lists,
and `program imports` / `program exports` for external symbols and entry points.
These commands share filtering, field selection, sorting, pagination, and counts.

`--limit 0` returns all rows. Filters, sorting, pagination, and counts generally
run in Rust after a full fetch; small limits may not bound underlying work.
The default cap also applies with no query options or with only `--fields`.
An explicit limit overrides it; `--count` ignores the default but honors an
explicit offset/limit, returning the selected page's count. Byte, text, and string
searches have no additional fixed result cap.
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
