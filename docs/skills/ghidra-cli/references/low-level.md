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

For analyzer settings and whole-program reanalysis, see
[import and reanalysis](programs.md#import-and-reanalysis).

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
