# Low-level analysis

## Disassembly and analysis boundaries

```bash
ghidra-cli function disassemble main --limit 0 --format asm --project target
ghidra-cli disassemble 0x401000 --limit 40 --project target
ghidra-cli disassemble 0x401000 --end 0x401080 --format asm --project target
ghidra-cli find instruction "mov" --start 0x401000 --end 0x401080 --project target
ghidra-cli define-code --target 0x401234 --end 0x401280 --project target
ghidra-cli disassemble 0x401234 --end 0x401280 --limit 20 --project target
ghidra-cli function create 0x401234 parse_entry --project target
```

`disassemble` reads existing instructions from the selected start; `--end`
sets an inclusive end address. It can continue beyond the starting function.
Use `function disassemble` to restrict results to the entire function body,
including disjoint ranges. Both use the shared filter, sort, offset, then limit
order. `--limit N` returns at most N matching instructions; `--limit 0` is
unlimited. Omitted limits use `default_limit` (1000 in the default configuration).
There is no separate ten-instruction window or `-n`/`--instructions` option.

`find instruction PATTERN` matches a literal substring of Ghidra's instruction
text, case-insensitively unless `--case-sensitive` is given. Either range
bound can be omitted; a one-sided range stays in the supplied endpoint's address
space. Use `find calls` for resolved call destinations.

Explicit `--format asm` prints one instruction per line (address, bytes, mnemonic,
operands). The default output format is unchanged.

Use `define-code TARGET` (or `define-code --target TARGET`) when auto-analysis
missed a known code location. Choose one target form, not both. It decodes the
loaded bytes and saves instruction definitions in Ghidra without changing those
bytes or executing the program. Ghidra follows statically known code flow; this
is not a linear sweep of every byte. Without `--end`, there is no explicit range
restriction. With `--end END`, only complete instructions and delay-slot groups
inside the inclusive TARGET:END range are created; out-of-range branch targets
are not defined. Endpoints accept exact names or explicit addresses and must be
ascending in the same address space. Existing instructions/data are not overwritten;
an instruction already at TARGET produces an unchanged receipt.

The command returns only a receipt (`address`, `end`, `status`, `changed`,
`already_defined`, `ok`, `landed`), never instruction rows. Status is `defined`,
`unchanged`, or `failed`; failure to define an instruction at TARGET is an error.
Use `disassemble` afterward to read instructions. There is no `--limit`, and
`default_limit` does not affect code creation. Query flags are not accepted.
The old standalone `disassemble-at` command is removed. If analysis ran through
inline data or chose the wrong boundary:

```bash
ghidra-cli clear 0x401200:0x40121f --project target
ghidra-cli clear 0x401200:0x40121f --disassemble-at 0x401210 --project target
```

Plain `clear START:END` clears overlapping code units and leaves the range
undefined. Add `--disassemble-at ADDRESS` to disassemble at a new boundary after clearing.
This existing `clear` option is separate from `define-code`: its subsequent
disassembly is not confined to the cleared range. To bound code creation, run
plain `clear` followed by `define-code --target START --end END` instead.
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

`analyzer set` only changes the enabled option. Choose names from `analyzer list`
and execute with `analyze`. This analyzes the entire program using its current
settings, including programs that have already been analyzed.

## Patching

```bash
ghidra-cli memory write 0x401234 "90 90" --project target
```

`memory write ADDRESS HEX` accepts non-empty, complete hex byte pairs,
contiguous or quoted with spaces. Supply the intended instruction encoding for
the target ISA. The entire range must be mapped and initialized. Writing clears
existing code units in that range and restores any temporarily changed block
write permissions. Use `define-code` to restore instruction definitions when needed.
Failed nested mutations can retain partial changes; see
[persistence semantics](../SKILL.md#results-edits-and-jobs).

Use [program export binary](programs.md#export) to write the edited binary.
