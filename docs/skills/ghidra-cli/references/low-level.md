# Low-level analysis

## Code definitions and analysis boundaries

```bash
ghidra-cli listing define-code 0x401234 --end 0x401280 --project target
ghidra-cli disassemble 0x401234 --end 0x401280 --limit 20 --project target
ghidra-cli function create 0x401234 parse_entry --project target
```

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
Separate `listing undefine` and `listing define-code --end` requests bound decoding;
failure of the latter does not undo the former.
Both endpoints must be in the same address space. Overlay and segmented endpoints
are independently qualified, e.g. `listing undefine overlay:0x1000 --end overlay:0x1010`
or `listing undefine ram:0x1234:0x0 --end ram:0x1234:0x8`.
Word-addressed values may include a byte remainder (`word:0x1000.1`).

## Missing functions

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
[call-site prototypes](calls.md#one-call-sites-prototype).

## Instruction flow

```bash
ghidra-cli listing flow get 0x401234 --project target
ghidra-cli listing flow set 0x401234 --override call --project target
ghidra-cli listing flow set 0x401234 --fallthrough 0x401240 --project target
ghidra-cli listing flow clear 0x401234 --override --fallthrough --project target
```

An explicit fallthrough must name an existing instruction start in the same
address space. Flow override and fallthrough are independent;
`clear --fallthrough` restores the default successor.

`--no-fallthrough` can remove the Listing successor while decompiled C still
continues after the call. `--override call-return` represents a caller returning
after that call; `function set-noreturn` describes a callee that never returns.

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

Existing instructions can block context edits.

```bash
ghidra-cli listing undefine 0x1000 --end 0x101f --project target
ghidra-cli program context set TMode --start 0x1000 --end 0x101f --value 1 --project target
ghidra-cli listing define-code 0x1000 --end 0x101f --project target
ghidra-cli disassemble 0x1000 --end 0x101f --project target
```

## Control-flow graphs

```bash
ghidra-cli graph cfg parse_header --max-nodes 2000 --max-edges 8000 --project target
```

`graph cfg` includes unreachable instructions in the function body. Blocks retain
their native boundaries; `body_intersection` shows which part belongs to the
function. Calls are separate from successor edges; `boundaries` records unresolved
transfers and body crossings. Output budgets do not limit native analysis time.

## PCode and analyzer control

```bash
ghidra-cli pcode at 0x401000 --project target
ghidra-cli pcode function parse_header --project target
ghidra-cli pcode function parse_header --high --project target
```

Raw PCode omits flow overrides; `--high` uses the decompiler.

High PCode IDs are scoped to one `result_id`. Value IDs distinguish assignments
sharing storage. The High CFG reflects decompiler optimization;
`graph cfg` describes instruction control flow.

For `MULTIEQUAL`, input slots correspond to incoming High CFG edge indices.
Special inputs such as `INDIRECT`'s operation reference are not ordinary value
dependencies. Incomplete output can omit uses; `--max-nodes` and `--max-edges`
control output budgets. Input slots retain their original positions.

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

Block edits select the exact space-qualified start returned by `memory block list`;
block names need not be unique. Renaming an overlay block leaves its address-space
name intact.

Moving one block leaves the image base unchanged and does not fix embedded
pointer values. Native move/delete can leave outside incoming references targeting
the old address. Deleting a block also removes analysis in its range and can remove
a whole function whose body crosses that range. For whole-image relocation, see
[rebasing](programs.md#correcting-the-image-base).

## Patching

```bash
ghidra-cli memory write 0x401234 --bytes "90 90" --project target
```

`memory write` requires mapped, initialized memory. It preserves data definitions
and clears instructions overlapping changed bytes, including associated delay slots.
`listing define-code` can restore instruction definitions.

Typed pointer edits preserve explicit and analysis references; union members'
references are not updated automatically.

String edits must preserve their occupied length. Length or layout changes can
be made with `listing undefine`, `memory write`, and
[type application](types.md#define-and-apply-types).

[Binary export](programs.md#export) writes the edited bytes.
