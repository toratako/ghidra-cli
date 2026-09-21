# Exploration

## Functions and decompilation

```bash
ghidra-cli function list --fields name,address,size --limit 100 --project target
ghidra-cli function get main --project target
ghidra-cli decompile main --with-vars --with-params --project target
ghidra-cli decompile dispatch --with-jump-tables --project target
ghidra-cli decompile main --format c --project target
ghidra-cli graph callees main --project target
ghidra-cli xref to main --project target
ghidra-cli xref to malloc --project target
```

Use `--with-vars` and `--with-params` for decompiler variable and parameter
metadata; parameters are in declaration order. Ambiguous function names return
candidates; use an address to select one.

`--format c` prints decompiled code without JSON escaping. Use JSON when you
need the accompanying variable/parameter metadata.

In `warnings`, `source: c_comment` may include user-written notes;
`source: decompiler` identifies an API diagnostic. `entry_memory` describes only
the entry block, not every body range.

`basic_block_count` counts optimized decompiler blocks. Jump tables contain
only recovered destinations; an empty result does not rule out an indirect branch.

Decompilation has no native time limit by default; use
[job control](../SKILL.md#results-edits-and-jobs) to inspect or cancel long work.

## Search, strings, xrefs, and graphs

Call queries resolve thunks and typed pointers using Ghidra's references;
unresolved indirect calls may be absent. Passing a function pointer as data
does not make a function a caller.
`via` is the referenced address before thunk/pointer resolution. `destination`
is the resolved landing address; `callee_address` is the function entry when
defined. Use `graph callers ADDRESS` to investigate a destination before
defining a function there.

```bash
ghidra-cli function list --filter "name~crypt" --project target
ghidra-cli string list --filter "char_length > 12" --limit 80 --project target
ghidra-cli find string "password" --project target
ghidra-cli find text "Password" --project target
ghidra-cli find text "Password" --encoding utf-16le --project target
ghidra-cli find text "日本" --encoding shift_jis --project target
ghidra-cli string refs "password" --project target
ghidra-cli find bytes "48 8b 05" --project target
ghidra-cli find bytes --regex '\x48\x8b.{4}' --project target
ghidra-cli find instruction "mov" --start 0x401000 --end 0x401100 --project target
ghidra-cli find constant 0x9e3779b9 --project target
ghidra-cli find constant -1 --bits 32 --project target
ghidra-cli find constant --min 0x20 --max 0x7e --project target
ghidra-cli graph callers CreateProcessW --project target
ghidra-cli xref to malloc --project target
ghidra-cli xref to 0x401000 --project target
ghidra-cli xref from main --function --project target
ghidra-cli graph calls --project target
ghidra-cli graph callers parse_header --depth 3 --limit 100 --project target
ghidra-cli graph callees main --depth 2 --limit 100 --project target
```

`graph calls` applies query controls to function nodes; `--count` counts selected
nodes. Edges from selected nodes can point outside the returned node set.

`find string` and `string refs` use case-insensitive literal substring matching
on defined string values. An empty result does not establish that the text is
absent from memory. `find string ""` matches all defined string values.
For `string list` and `find string`, `char_length` counts Unicode code points,
not UTF-16 code units or displayed grapheme clusters. `byte_length` is the
Ghidra data definition's occupied byte length, including any terminators or
padding in that definition; it is not a re-encoding of `value`.

`find text TEXT` searches the program's loaded memory regardless of string
definitions. It encodes the literal TEXT using `--encoding` (default `utf-8`)
and matches exact bytes, including overlapping occurrences. Matching is
case-sensitive, without character normalization or an added NUL terminator;
matches need not align with string boundaries. Encodings use Java charset names
and aliases, such as `shift_jis` or `windows-31j` (CP932).
Use `utf-16le` or `utf-16be` for UTF-16 without a BOM; Java's `utf-16` encoding
includes a BOM in the search bytes.

`find bytes --regex PATTERN` searches loaded, initialized memory with Ghidra's
native byte regular expressions, including undefined data. It matches raw bytes
and does not enumerate every overlapping match; long matches, lookaround, and
anchors can be affected by buffer boundaries.

`find constant` searches scalar operands in existing instructions, including
immediates and displacements. It does not search address operands or data, or
combine constants built by several instructions. Use `find bytes` for encoded
data and `xref` for address references.

String names and external/import names resolve directly. For plain
`graph callers/callees`, `--limit N` bounds traversal; filter, sort, count, or
offset may require a broader traversal.
For instruction-text matching and disassembly ranges, see
[low-level analysis](low-level.md#disassembly-and-analysis-boundaries).

## Symbols and memory

```bash
ghidra-cli symbol list --limit 100 --project target
ghidra-cli memory map --project target
ghidra-cli memory info 0x401003 --project target
ghidra-cli memory read 0x401000 64 --project target
ghidra-cli memory read 0x401000 64 --source original --project target
ghidra-cli data list --filter 'type=Header' --fields name,address,type,size --project target
ghidra-cli data read packet_header --max-depth 3 --max-elements 100 --project target
```

`data read` interprets current memory using its applied type. Interior targets
select a containing component and retain its `parents`; overlapping union
members remain alternative interpretations. Pointers are not followed.

Use `memory info` to check file provenance and `memory read --source original`
to compare current memory with preserved import bytes before relocations or
patches. This requires a file mapping for the whole range; it does not reopen
the executable on disk or decode original bytes as current-memory pointers.

For byte edits, see [patching](low-level.md#patching).

## Analysis diagnostics

```bash
ghidra-cli bookmark list --filter 'type=Error' --project target
ghidra-cli bookmark get 0x401000 --project target
```

Bookmarks help locate analysis problems after `analysis run`.

## Query controls

Query order is filter, sort, offset/limit, then count or field selection.
The result cap defaults to `default_limit` (1000 unless configured), including
with no query options or only `--fields`. `--limit 0` returns all rows.
`--count` ignores the default cap but honors an explicit offset/limit, counting
the selected page. Small limits may still require scanning or fetching all matches.

```bash
ghidra-cli function list --count --project target
ghidra-cli function list --filter "size > 100" --fields name,address,size \
  --limit 40 --project target
```

Filters also combine with `AND` (e.g. `size >= 100 AND name ~ 'crypt'`);
`name ^ 'FUN_'` selects a prefix. For tag filters, see
[function tags](refinement.md#function-tags).

For address comparisons and `IN`, use hex literals (`address >= 0x401000`)
or quoted addresses (`address = 'overlay:0x1000'`). Numeric comparisons use
flat offsets; quoted equality keeps space names case-sensitive while ignoring
hex case and zero padding.
