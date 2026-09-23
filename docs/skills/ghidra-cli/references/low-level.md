# Low-level analysis

## Disassembly and analysis boundaries

```bash
ghidra-cli function disassemble main --limit 0 --format asm --project target
ghidra-cli disassemble 0x401000 --limit 40 --project target
ghidra-cli disassemble 0x401000 --end 0x401080 --format asm --project target
ghidra-cli find instruction "mov" --start 0x401000 --end 0x401080 --project target
ghidra-cli listing define-code 0x401234 --end 0x401280 --project target
ghidra-cli disassemble 0x401234 --end 0x401280 --limit 20 --project target
ghidra-cli function create 0x401234 parse_entry --project target
```

`disassemble` can continue beyond the starting function. `function disassemble`
restricts results to its body, including disjoint ranges. Both use the shared
[query controls](exploration.md#query-controls).

`find instruction PATTERN` matches a literal substring of Ghidra's instruction
text, case-insensitively unless `--case-sensitive` is given. Either range
bound can be omitted; a one-sided range stays in the supplied endpoint's address
space. For resolved call sites, use
[graph callers](exploration.md#search-strings-xrefs-and-graphs).

`listing define-code` follows statically known code flow rather than sweeping
every byte. `--end END` confines complete instructions and
delay-slot groups to the inclusive TARGET:END range; without it, code creation
has no explicit range bound. Existing instructions/data are not overwritten;
use `listing undefine` to replace incorrect definitions.

```bash
ghidra-cli listing undefine 0x401200 --end 0x40121f --project target
ghidra-cli listing undefine 0x401200 --end 0x40121f --disassemble-at 0x401210 --project target
```

`listing undefine --disassemble-at` can disassemble beyond the cleared range.
To bound decoding, use separate `listing undefine` and `listing define-code --end`
requests; failure of the latter does not undo the former.
Both endpoints must be in the same address space. Qualify overlay and segmented
endpoints independently, e.g. `listing undefine overlay:0x1000 --end overlay:0x1010`
or `listing undefine ram:0x1234:0x0 --end ram:0x1234:0x8`.
Word-addressed values may include a byte remainder (`word:0x1000.1`).

## Function bodies

```bash
ghidra-cli function get parse_header --project target
ghidra-cli function set-body parse_header \
  --range 0x401000 0x40107f --range 0x402000 0x40201f --project target
```

`set-body` changes body membership without creating instructions or merging functions.

Shrinking a body can delete its local labels and stack/register references, and
detach variable references in the removed region. Restoring the old ranges does
not restore those annotations. For overrides left outside the body, see
[call-site prototypes](refinement.md#one-call-sites-prototype).

## Instruction flow

```bash
ghidra-cli listing flow get 0x401234 --project target
ghidra-cli listing flow set 0x401234 --override call --project target
ghidra-cli listing flow set 0x401234 --fallthrough 0x401240 --project target
ghidra-cli listing flow clear 0x401234 --override --fallthrough --project target
```

An explicit fallthrough must name an existing instruction start in the same
address space; use `listing define-code` first if it is undefined. Flow override
and fallthrough are independent; `clear --fallthrough` restores the default
successor.

`--no-fallthrough` can remove the Listing successor while decompiled C still
continues after the call. To represent a caller returning after that call, use
`--override call-return` and inspect `decompile`. Use `function set-noreturn`
when the callee itself never returns.

Flow edits change interpretation and reference types without changing bytes or
running analysis.

## Processor context

`TMode=1` selects Thumb in an ARM language.

```bash
ghidra-cli program context list --project target
ghidra-cli program context get TMode --start 0x1000 --end 0x101f --project target
```

A context mask identifies known bits; unset bits are unknown, not zero.
`clear` removes stored values, including those established by decoding or
analysis; it does not undo the last `set`. Defaults can remain effective afterward.

Existing instructions can block context edits; rebuild the affected region:

```bash
ghidra-cli listing undefine 0x1000 --end 0x101f --project target
ghidra-cli program context set TMode --start 0x1000 --end 0x101f --value 1 --project target
ghidra-cli listing define-code 0x1000 --end 0x101f --project target
ghidra-cli disassemble 0x1000 --end 0x101f --project target
```

## PCode and analyzer control

```bash
ghidra-cli pcode at 0x401000 --project target
ghidra-cli pcode function parse_header --project target
ghidra-cli pcode function parse_header --high --project target
```

Raw PCode omits flow overrides; `--high` uses the decompiler.

High PCode IDs are scoped to one `result_id`. Value IDs distinguish assignments
sharing storage. The High CFG reflects decompiler optimization;
use `graph cfg` for instruction control flow.

For `MULTIEQUAL`, input slots correspond to incoming High CFG edge indices.
Special inputs such as `INDIRECT`'s operation reference are not ordinary value
dependencies. Incomplete output can omit uses; increase `--max-nodes` or
`--max-edges` to include them. Input slots retain their original positions.

For analyzer settings and full, range, or pending analysis, see
[import and reanalysis](programs.md#import-and-reanalysis).

## Memory layout

```bash
ghidra-cli memory block create .ram --start ram:0x20000000 --size 65536 --uninitialized --permissions rw
ghidra-cli memory block create .mmio --start ram:0x40000000 --size 4096 --uninitialized --permissions rw --volatile
ghidra-cli memory block create .bank1 --start ram:0x1000 --size 8192 --overlay bank1 --fill 0xff --permissions rx
ghidra-cli memory block create .bank1_data --start bank1:0x4000 --size 256 --uninitialized --permissions rw
ghidra-cli memory block move ram:0x20000000 ram:0x21000000
```

Block edits select the exact start returned by `memory map`. Preserve the address
space qualifier; block names need not be unique. Renaming an overlay block leaves
its address-space name intact.

Moving one block leaves the image base unchanged and does not fix embedded
pointer values. Inspect outside incoming references afterward: native move/delete
can leave them targeting the old address. Deleting a block also removes analysis
in its range and can remove a whole function whose body crosses that range.
For whole-image relocation, use `program rebase`.

## Patching

```bash
ghidra-cli memory write 0x401234 --bytes "90 90" --project target
```

`memory write` requires mapped, initialized memory. It preserves data definitions
and clears instructions overlapping changed bytes, including associated delay slots.
Use `listing define-code` to restore instruction definitions.

After changing a typed pointer, check `xref from` at its address: explicit and
analysis references are preserved, and union members' references are not updated
automatically.

String edits must preserve their occupied length. To change the length or data
layout, use `listing undefine`, write the bytes, then
[apply the intended type](refinement.md#types).

Use [binary export](programs.md#export) to write the edited binary.
