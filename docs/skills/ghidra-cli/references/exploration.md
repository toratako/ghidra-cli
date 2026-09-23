# Exploration

## Functions and decompilation

```bash
ghidra-cli function list --fields name,address,size --limit 100 --project target
ghidra-cli function get main --project target
ghidra-cli decompile main --with-vars --with-params --project target
ghidra-cli decompile dispatch --with-jump-tables --project target
ghidra-cli decompile main --format c --project target
ghidra-cli decompile parse_packet --with-addresses --format c --project target
ghidra-cli graph callees main --project target
ghidra-cli xref to main --project target
ghidra-cli xref to malloc --project target
```

In `warnings`, `source: c_comment` may include user-written notes;
`source: decompiler` identifies an API diagnostic. `entry_memory` describes only
the entry block, not every body range.

`basic_block_count` counts optimized decompiler blocks. Jump tables contain
only recovered destinations; an empty result does not rule out an indirect branch.

`--with-addresses` maps displayed operations, not every contributing instruction:
a condition may identify the branch but omit the compare. Inspect surrounding
disassembly before choosing a patch location.

```bash
ghidra-cli graph cfg parse_header --max-nodes 2000 --max-edges 8000 --project target
```

`graph cfg` includes unreachable instructions in the function body. Blocks retain
their native boundaries; `body_intersection` shows which part belongs to the
function. Calls are separate from successor edges; `boundaries` records unresolved
transfers and body crossings. Output budgets do not limit native analysis time.

Decompilation has no native time limit by default; use
[job control](../SKILL.md#results-edits-and-jobs) to inspect or cancel long work.

```bash
ghidra-cli find function-candidates --sort=-call_count,address --limit 20 --project target
ghidra-cli disassemble 0x401800 --limit 20 --project target
ghidra-cli xref to 0x401800 --project target
ghidra-cli function create 0x401800 --project target
```

Function candidates require existing instructions outside all function bodies,
with call evidence and no incoming fallthrough (even from decoded padding).
Bounds select destinations, not callers; `call_count` counts distinct call sites.
Undisassembled code and targets reached only by unresolved indirect calls are missed.

## Search, strings, xrefs, and graphs

Call queries resolve thunks and typed pointers using Ghidra's references;
unresolved indirect calls may be absent.
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
ghidra-cli xref to 0x401000 --project target
ghidra-cli xref from main --whole-function --project target
ghidra-cli graph calls --project target
ghidra-cli graph callers parse_header --depth 3 --limit 100 --project target
ghidra-cli graph callees main --depth 2 --limit 100 --project target
```

`graph calls` applies query controls to function nodes; `--count` counts selected
nodes. Edges from selected nodes can point outside the returned node set.

`find string` and `string refs` use case-insensitive literal substring matching
on defined string values; use `find text` for undefined strings.
For `string list` and `find string`, `char_length` counts Unicode code points,
not UTF-16 code units or displayed grapheme clusters. `byte_length` is the
Ghidra data definition's occupied byte length, including any terminators or
padding in that definition; it is not a re-encoding of `value`.

`find text TEXT` searches the program's loaded memory regardless of string
definitions, matching exact encoded bytes including overlapping occurrences.
Matching is case-sensitive, without normalization or an added NUL terminator.
Encodings use Java charset names and aliases, such as `shift_jis` or `windows-31j` (CP932).
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

For plain `graph callers/callees`, `--limit N` bounds traversal;
filter, sort, count, or offset may require a broader traversal.
For instruction-text matching and disassembly ranges, see
[low-level analysis](low-level.md#disassembly-and-analysis-boundaries).

## Symbols and memory

```bash
ghidra-cli symbol list --limit 100 --project target
ghidra-cli memory block list --project target
ghidra-cli memory info 0x401003 --project target
ghidra-cli memory file-mappings --project target
ghidra-cli memory file-mappings --file-offset 0x205 --limit 0 --project target
ghidra-cli memory read 0x401000 --size 64 --project target
ghidra-cli memory read 0x401000 --size 64 --source original --project target
ghidra-cli data list --filter 'type=Header' --fields name,address,type,size --project target
ghidra-cli data list --sort=-incoming_reference_count --limit 20 --project target
ghidra-cli data read packet_header --max-depth 3 --max-elements 100 --project target
```

`incoming_reference_count` counts Ghidra's recorded references to any address
inside the object, including fields and array elements.

`data read` interprets current memory using its applied type. Interior targets
select a containing component and retain its `parents`; overlapping union
members remain alternative interpretations. Pointers are not followed.

`memory read --source original` reads preserved import bytes before relocations
or patches, requiring a file mapping for the whole range. It does not reopen
the executable or decode original bytes as current-memory pointers.

`memory file-mappings --file-offset` can match several placements of the same
input bytes, including overlays. To select one saved input, pass
`--source-at` an address mapped from it; `source_at` in the results is a reusable
anchor until the layout changes. Filenames alone do not distinguish saved inputs.
Indirect mappings are excluded and reported in `meta.unsupported_mappings`;
an empty result proves only the absence of a direct mapping.

For changing RAM/MMIO or overlays, see [memory layout](low-level.md#memory-layout);
for byte edits, see [patching](low-level.md#patching).

## Pointer and virtual-function tables

```bash
ghidra-cli memory read 0x405020 --size 64 --project target
ghidra-cli find address-tables --start 0x405000 --end 0x405fff --min-entries 3 --project target
ghidra-cli memory read-vtable 0x405020 --entries 8 --abi itanium --project target
ghidra-cli memory read-vtable 0x140005020 --entries 8 --abi msvc --project target
ghidra-cli memory read-vtable 0x405020 --entries 8 --abi itanium --encoding relative32 --project target
```

`memory read-vtable` starts at the address point (slot 0, where the object's vptr
points), which can differ from the table symbol. `relative32` reads LLVM's layout,
including its RTTI proxy. Slot count is supplied, not inferred; null and undefined
targets retain their slots. `complete` concerns slot bytes; `header.complete`
concerns ABI metadata.

`memory read` distinguishes encoded pointer targets, normalized code addresses
(e.g. Thumb), and thunk destinations.

`find address-tables` can find callback and dispatch tables. Bounds select starts,
so tables can extend past `--end`. Native boundary rules can split or miss tables;
inspect bytes before interpreting one as a VTable. Check scan completion in `.meta`.

For callers through an absolute-pointer table:

```bash
ghidra-cli find virtual-callers Widget_draw --vtable 0x405020 --entries 8 --abi itanium --project target
ghidra-cli find virtual-callers Widget_draw --vtable 0x405020 --entries 8 --abi itanium --within dispatch --project target
```

In `evidence`, `table_value` traces the selected slot's address,
`table_type` associates a recovered table type, and `slot_offset` matches only an
offset. The latter two do not establish the runtime table. Branch merges and
trace failures appear in `.meta.scan.unresolved`; narrow `--within` to investigate
failed functions. An incomplete scan or unreadable table cannot rule out callers.

## Analysis diagnostics

```bash
ghidra-cli bookmark list --filter 'type=Error' --project target
ghidra-cli bookmark get 0x401000 --project target
```

## Query controls

Query order is filter, sort, offset/limit, then count or field selection.
The list cap defaults to `default_limit` (1000 unless configured);
`--limit 0` returns all rows.
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
