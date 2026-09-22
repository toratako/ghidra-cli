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

`disassemble` reads existing instructions from the selected start; `--end`
sets an inclusive end address. It can continue beyond the starting function.
Use `function disassemble` to restrict results to the entire function body,
including disjoint ranges. Both use the shared
[query controls](exploration.md#query-controls).

`find instruction PATTERN` matches a literal substring of Ghidra's instruction
text, case-insensitively unless `--case-sensitive` is given. Either range
bound can be omitted; a one-sided range stays in the supplied endpoint's address
space. For resolved call sites, use
[graph callers](exploration.md#search-strings-xrefs-and-graphs).

`--format asm` prints one instruction per line (address, bytes, mnemonic, operands).

Use `listing define-code TARGET` when auto-analysis missed a known code location.
It creates instruction definitions by following statically known code flow,
rather than sweeping every byte. `--end END` confines complete instructions and
delay-slot groups to the inclusive TARGET:END range; without it, code creation
has no explicit range bound. Endpoints must share an address space. Existing
instructions/data are not overwritten; use `listing undefine` to replace
incorrect definitions.
The command returns a change receipt; use `disassemble` afterward to read instructions.

If analysis ran through inline data or chose the wrong boundary:

```bash
ghidra-cli listing undefine 0x401200 --end 0x40121f --project target
ghidra-cli listing undefine 0x401200 --end 0x40121f --disassemble-at 0x401210 --project target
```

Plain `listing undefine START --end END` clears overlapping code units and leaves
the range undefined. Add `--disassemble-at ADDRESS` to disassemble at a new boundary after
clearing; this disassembly is not confined to the cleared range. To bound code
creation, run plain `listing undefine` followed by
`listing define-code START --end END` instead. These are separate requests:
a failed `listing define-code` does not undo `listing undefine`.
Both endpoints must be in the same address space. Qualify overlay and segmented
endpoints independently, e.g. `listing undefine overlay:0x1000 --end overlay:0x1010`
or `listing undefine ram:0x1234:0x0 --end ram:0x1234:0x8`.
Word-addressed values may include a byte remainder (`word:0x1000.1`).

For headerless input, first choose the language and load parameters using
[raw import](programs.md#raw-import).

## Function bodies

Use `function get` to inspect `body_ranges`, then replace the whole body when
analysis assigned the wrong ranges:

```bash
ghidra-cli function get parse_header --project target
ghidra-cli function set-body parse_header \
  --range 0x401000 0x40107f --range 0x402000 0x40201f --project target
```

The repeated inclusive ranges form a union; gaps remain outside the function.
Keep the entry point, include complete instructions, and resolve ownership by
other functions before extending the body. This changes body membership without
creating instructions or merging functions.

Shrinking a body can delete its local labels and stack/register references, and
detach variable references in the removed region. The receipt reports observed
losses. Restoring the old ranges does not restore those annotations. Saved
call-site overrides can survive outside the new body; inspect or clear them with
`function call-signature get/clear` using the original caller.

## Instruction flow

Correct Ghidra's interpretation without changing instruction bytes:

```bash
ghidra-cli listing flow get 0x401234 --project target
ghidra-cli listing flow set 0x401234 --override call --project target
ghidra-cli listing flow set 0x401234 --fallthrough 0x401240 --project target
ghidra-cli listing flow clear 0x401234 --override --fallthrough --project target
```

Targets must be instruction starts. An explicit fallthrough destination must
already be an instruction start in the same address space; use
`listing define-code` first if it is undefined. Flow override and fallthrough
are independent: setting one preserves the other. `--no-fallthrough` removes
the successor, while `clear --fallthrough` restores the default successor.

`--no-fallthrough` can remove the Listing successor while decompiled C still
continues after the call. To represent a caller returning after that call, use
`--override call-return` and inspect `decompile`. Use `function set-noreturn`
when the callee itself never returns.

Flow edits can change reference types and graph/decompiler output, even though
bytes stay the same. Inspect `listing flow get` and re-decompile; full analysis
remains a separate `analysis run` operation.

## Processor context

Processor context controls how Ghidra decodes an address range. For example,
`TMode=1` selects Thumb in an ARM language; it is not a runtime register edit.
Inspect the selected language's registers and the affected range first:

```bash
ghidra-cli program context list --project target
ghidra-cli program context get TMode 0x1000 --end 0x101f --project target
```

Readings distinguish `stored`, `default`, and `effective` values. A value's mask
identifies known bits; unset bits are unknown, not zero. `clear` removes recorded
values in the range, including values established by decoding or analysis. It
does not undo the last `set`, and defaults can remain effective afterward.

Context edits do not replace instructions or run analysis. Ghidra can reject a
context change across existing instructions. To correct a misdecoded region,
inspect its definitions and explicitly rebuild it:

```bash
ghidra-cli listing undefine 0x1000 --end 0x101f --project target
ghidra-cli program context set TMode 1 0x1000 --end 0x101f --project target
ghidra-cli listing define-code 0x1000 --end 0x101f --project target
ghidra-cli disassemble 0x1000 --end 0x101f --project target
```

Each command saves separately; failure later in this sequence does not restore
the definitions cleared by `listing undefine`. To remove a recorded override,
use `program context clear TMode 0x1000 --end 0x101f --project target`, then
inspect the effective value before decoding again.

## PCode and analyzer control

```bash
ghidra-cli pcode at 0x401000 --project target
ghidra-cli pcode function parse_header --project target
ghidra-cli pcode function parse_header --high --project target
ghidra-cli analysis option list --project target
ghidra-cli analysis option set "ASCII Strings" false --project target
ghidra-cli analysis option set "ASCII Strings" true --project target
ghidra-cli analysis run --project target --program target.bin
```

Raw `pcode at` and `pcode function` omit instruction flow overrides. High PCode
comes through the decompiler and can therefore differ after a flow edit.

For analyzer settings and full, range, or pending analysis, see
[import and reanalysis](programs.md#import-and-reanalysis).

## Memory layout

```bash
ghidra-cli memory block create .ram ram:0x20000000 65536 --uninitialized --permissions rw
ghidra-cli memory block create .mmio ram:0x40000000 4096 --uninitialized --permissions rw --volatile
ghidra-cli memory block create .bank1 ram:0x1000 8192 --overlay bank1 --fill 0xff --permissions rx
ghidra-cli memory block create .bank1_data bank1:0x4000 256 --uninitialized --permissions rw
ghidra-cli memory block move ram:0x20000000 ram:0x21000000
```

Uninitialized RAM/MMIO represents unknown values; `--fill` creates actual bytes.
MMIO volatility and permissions guide analysis but do not emulate device behavior.
`memory write` requires initialized memory, so choose fill when populating known
bytes after creation.

Block edits select the exact start returned by `memory map`. Preserve the address
space qualifier; block names need not be unique. Overlay names identify separate
address spaces, and renaming a block leaves its space name intact.

Moving one block leaves the image base unchanged and does not fix embedded
pointer values. Inspect outside incoming references afterward: native move/delete
can leave them targeting the old address. Deleting a block also removes analysis
in its range and can remove a whole function whose body crosses that range.
Use `memory map`, `memory info`, and xrefs to check the result before choosing
whether to run analysis. For whole-image relocation, use `program rebase`.

## Patching

```bash
ghidra-cli memory write 0x401234 "90 90" --project target
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

Use [program export binary](programs.md#export) to write the edited binary.
