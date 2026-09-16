# Programs and artifacts

## Project, program, and bridge state

```bash
ghidra-cli project create target
ghidra-cli project list
ghidra-cli project info target
ghidra-cli program list --project target
ghidra-cli program info --project target --program target.bin
ghidra-cli status --project target
ghidra-cli jobs --project target
ghidra-cli cancel --project target
ghidra-cli restart --project target --program target.bin
ghidra-cli program save --project target --program target.bin
ghidra-cli stop --project target
```

`project delete NAME` stops its bridge and removes the `.gpr`/`.rep` artifacts.
`program list`, `program info`, and `summary` report the saved name and project
file `path`. Other program responses and artifact manifests also use the saved
name. `executable_path` identifies the original input file; Ghidra's internal
Program name can differ and is not used as the CLI display name.
`stats` reports program statistics; `summary` reports the loaded program's
metadata. See [job control and persistence](../SKILL.md#results-edits-and-jobs)
before retrying failed edits or stopping a bridge after a save failure.

## Import and reanalysis

Import waits for completion. Use `import --no-analyze` to omit analysis and
`analyze --project target --program target.bin` to reanalyze.
`import INPUT --program NAME` saves under that project file name; omitting it
uses the input file name (Ghidra may add a suffix on collision). An explicit name
must be a single file name and must not already exist. The import response reports
the actual saved name. See [starting with a program](../SKILL.md#start-with-a-program)
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
`BinaryLoader`; `--processor` aliases `--language`. Raw import does not establish
an entry point. Use `disasm-at` and `function create` at a known code address;
see [disassembly and analysis boundaries](low-level.md#disassembly-and-analysis-boundaries).

## Export

```bash
ghidra-cli program export c --project target -o ./target.c
ghidra-cli program export gzf --project target -o ./target.gzf
ghidra-cli graph export dot --project target | jq -r '.[0].output' \
  > ./calls.dot
ghidra-cli patch export -o ./target.patched.bin --project target
```

`program export gzf -o PATH` saves the program before packing, stages the archive
beside its destination, and atomically replaces the destination only after a
successful export. Failure or cancellation before publication preserves an
existing destination; a filesystem without atomic replacement support returns
an error.

Import inputs and program/patch export destinations resolve relative to the CLI's
working directory, including when reusing a bridge started elsewhere or executing
inside a batch.
