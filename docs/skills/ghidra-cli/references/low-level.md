# Low-level analysis

## Disassembly and analysis boundaries

```bash
ghidra-cli function disasm main --limit 0 --format asm --project target
ghidra-cli disasm 0x401000 -n 40 --project target
ghidra-cli disasm 0x401000 --end 0x401080 --format asm --project target
ghidra-cli find instruction "mov" --start 0x401000 --end 0x401080 --project target
ghidra-cli disasm-at 0x401234 -n 20 --project target
ghidra-cli function create 0x401234 parse_entry --project target
```

`find instruction PATTERN` matches a literal substring of Ghidra's instruction
text, case-insensitively unless `--case-sensitive` is given. Either range
bound can be omitted; a one-sided range stays in the supplied endpoint's address
space. Use `find calls` for resolved call destinations.

Explicit `--format asm` prints one instruction per line (address, bytes, mnemonic,
operands). The default output format is unchanged.

Use `disasm-at` when auto-analysis missed a known target. If analysis ran through
inline data or chose the wrong boundary:

```bash
ghidra-cli clear 0x401200:0x40121f --to-data --project target
ghidra-cli clear 0x401200:0x40121f --disasm-at 0x401210 --project target
```

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
ghidra-cli analyzer run --project target --program target.bin
```

`analyzer set` only changes the enabled option. Choose names from `analyzer list`
and execute with `analyzer run`.

## Patching

```bash
ghidra-cli memory write 0x401234 "90 90" --project target
```

`memory write ADDRESS HEX` accepts non-empty, complete hex byte pairs,
contiguous or quoted with spaces. Supply the intended instruction encoding for
the target ISA. The entire range must be mapped and initialized. Writing clears
existing code units in that range and restores any temporarily changed block
write permissions. Use `disasm-at` to re-disassemble when needed.
Failed nested mutations can retain partial changes; see
[persistence semantics](../SKILL.md#results-edits-and-jobs).

Use [program export binary](programs.md#export) to write the edited binary.
