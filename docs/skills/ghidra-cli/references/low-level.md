# Low-level analysis

## Disassembly and analysis boundaries

```bash
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
ghidra-cli patch bytes 0x401234 "90 90" --project target
ghidra-cli patch nop 0x401234 --count 5 --project target
```

`patch nop --count N` walks up to N consecutive instructions (default 1), including
variable-length instructions. A missing first instruction is an error; a later
gap ends successfully with a smaller returned `count`. Check that count. Failed
nested mutations can retain partial changes; see
[persistence semantics](../SKILL.md#results-edits-and-jobs).
`patch nop` supports x86 (`0x90`) and rejects other processors before editing.
For other ISAs, use `patch bytes` with the intended instruction encoding.

Use [patch export](programs.md#export) to write the patched binary.
