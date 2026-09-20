# Low-level analysis

## Disassembly and analysis boundaries

```bash
ghidra-cli function disassemble main --limit 0 --format asm --project target
ghidra-cli disassemble 0x401000 --limit 40 --project target
ghidra-cli disassemble 0x401000 --end 0x401080 --format asm --project target
ghidra-cli find instruction "mov" --start 0x401000 --end 0x401080 --project target
ghidra-cli define-code 0x401234 --end 0x401280 --project target
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

Use `define-code TARGET` when auto-analysis missed a known code location.
It creates instruction definitions by following statically known code flow,
rather than sweeping every byte. `--end END` confines complete instructions and
delay-slot groups to the inclusive TARGET:END range; without it, code creation
has no explicit range bound. Endpoints must share an address space. Existing
instructions/data are not overwritten; use `clear` to replace incorrect definitions.
The command returns a change receipt; use `disassemble` afterward to read instructions.

If analysis ran through inline data or chose the wrong boundary:

```bash
ghidra-cli clear 0x401200:0x40121f --project target
ghidra-cli clear 0x401200:0x40121f --disassemble-at 0x401210 --project target
```

Plain `clear START:END` clears overlapping code units and leaves the range
undefined. Add `--disassemble-at ADDRESS` to disassemble at a new boundary after
clearing; this disassembly is not confined to the cleared range. To bound code
creation, run plain `clear` followed by `define-code START --end END` instead.
These are separate requests: a failed `define-code` does not undo `clear`.
`clear` ranges stay within one space. `overlay:0x1000:0x1010` inherits the start
space; segmented endpoints must be fully qualified, e.g.
`ram:0x1234:0x0:ram:0x1234:0x8`. For numeric space names, use
`0x1234:0x10.0:0x1234:0x20.0` to avoid ambiguous splits.
Word-addressed values may include a byte remainder (`word:0x1000.1`).

For headerless input, first choose the language and load parameters using
[raw import](programs.md#raw-import).

## PCode and analyzer control

```bash
ghidra-cli pcode at 0x401000 --project target
ghidra-cli pcode function parse_header --project target
ghidra-cli pcode function parse_header --high --project target
ghidra-cli analyzer list --project target
ghidra-cli analyzer set "ASCII Strings" false --project target
ghidra-cli analyzer set "ASCII Strings" true --project target
ghidra-cli analyze --project target --program target.bin
```

For analyzer settings and whole-program reanalysis, see
[import and reanalysis](programs.md#import-and-reanalysis).

## Patching

```bash
ghidra-cli memory write 0x401234 "90 90" --project target
```

`memory write` requires mapped, initialized memory. It preserves data definitions
and clears instructions overlapping changed bytes, including associated delay slots.
Use `define-code` to restore instruction definitions.

After changing a typed pointer, check `xref from` at its address: explicit and
analysis references are preserved, and union members' references are not updated
automatically.

String edits must preserve their occupied length. To change the length or data
layout, use `clear`, write the bytes, then
[apply the intended type](refinement.md#types).

Use [program export binary](programs.md#export) to write the edited binary.
