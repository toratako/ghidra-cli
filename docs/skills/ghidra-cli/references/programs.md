# Programs and artifacts

## Project, program, and bridge state

```bash
ghidra-cli project list
ghidra-cli project info target
ghidra-cli program list --project target
ghidra-cli program info --project target --program target.bin
ghidra-cli bridge status --project target
ghidra-cli job list --project target
ghidra-cli job get 42 --project target
ghidra-cli job cancel --project target
ghidra-cli bridge restart --project target --program target.bin
ghidra-cli program save --project target --program target.bin
ghidra-cli bridge stop --project target
```

`project delete NAME` stops its bridge and deletes the project;
`program delete --program NAME` deletes only that program file.
`program list` includes subfolders. Use the project-file `path` from `program list`
or `program info` to distinguish same-named programs. Displayed program names
are saved file names; `executable_path` identifies the original input file.
Use `program stats` for aggregate counts.
See [job control and persistence](../SKILL.md#results-edits-and-jobs)
before retrying failed edits or stopping a bridge after a save failure.

## External symbols and entry points

`symbol externals` lists external symbols and their libraries; `symbol entry-points`
lists symbols Ghidra marks as external entry points.

```bash
ghidra-cli symbol externals --filter 'library~libc' --fields name,address --limit 0
ghidra-cli symbol entry-points --sort name --limit 0
```

## Import and reanalysis

`analyze --project target --program target.bin` analyzes the entire program
using its current options. `analyzer list` and `analyzer set` inspect or change
those options without running analysis.
`import INPUT --program NAME` saves under that project file name; omitting it
uses the input file name, including a symlink's name rather than its target's
name (Ghidra may add a suffix on collision).
See [starting with a program](../SKILL.md#start-with-a-program)
for the ordinary import workflow and recovery when an import error reports a
saved program.

### Raw import

Choose raw input's ISA, endianness, and load address from target evidence;
plausible disassembly alone does not validate them.

```bash
ghidra-cli import ./firmware.bin --project firmware \
  --language x86:LE:32:default --base-address 0x8000 \
  --block-name ROM --no-analyze
```

`--base-address`, `--block-name`, `--file-offset`, and `--length` imply
`BinaryLoader`. Use `--language` to select the ISA and `--compiler-spec` to select
the compiler specification. Raw import does not establish
an entry point. Use `define-code` and `function create` at a known code address;
see [disassembly and analysis boundaries](low-level.md#disassembly-and-analysis-boundaries).

## Export

Use `c` for decompiled C, `asm` for an instruction listing, `binary` for edited
bytes, and `gzf` for a Ghidra program archive.

```bash
ghidra-cli program export c --project target -o ./target.c
ghidra-cli program export gzf --project target -o ./target.gzf
ghidra-cli program export binary -o ./target.patched.bin --project target
```

`gzf` saves the program before packing and atomically replaces the destination
after successful export. Failure or cancellation before replacement preserves
an existing destination; filesystems without atomic replacement support return an error.

Import inputs and program export destinations resolve relative to the CLI's
working directory, including when reusing a bridge started elsewhere or executing
inside a batch.
