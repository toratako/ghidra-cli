# Programs and artifacts

## Project, program, and bridge state

```bash
ghidra-cli project list
ghidra-cli project info target
ghidra-cli program list --project target
ghidra-cli program info --project target --program target.bin
ghidra-cli program list-relocations --filter 'status=FAILURE' --project target
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

## Project snapshots

Use GAR for a project containing several Programs or project type archives;
use `program export gzf` for one Program.

```bash
ghidra-cli project archive target --output ./target-20260922.gar
ghidra-cli project restore ./target-20260922.gar target-copy --projects-dir ./restored
```

Archive waits for accepted work, saves pending edits, and leaves the bridge
stopped. Use a fresh archive filename and a new restoration target.
Archive publication requires hard-link support on the destination filesystem;
if unavailable, create the GAR on a local filesystem and copy it afterward.

GAR carries local project contents, not GUI state, CLI configuration, or external
files. Inspect `external_dependencies.links` when moving projects: link targets
are preserved, not bundled or rewritten. The scan covers project links only;
`complete: false` means link inspection was unavailable for this Ghidra version.

## External symbols and entry points

`symbol externals` lists external symbols and their libraries; `symbol entry-points`
lists symbols Ghidra marks as external entry points.

```bash
ghidra-cli symbol externals --filter 'library~libc' --fields name,address --limit 0
ghidra-cli symbol entry-points --sort name --limit 0
```

## Import and reanalysis

`analysis run` analyzes the entire program using its saved settings.
To configure the first analysis:

```bash
ghidra-cli program import ./target.bin --project target --no-analyze
ghidra-cli analysis option list --project target --filter 'name~"ASCII Strings"'
ghidra-cli analysis option get "ASCII Strings.Minimum String Length" --project target
ghidra-cli analysis option set "ASCII Strings.Minimum String Length" LEN_10 --project target
ghidra-cli analysis run --project target --program target.bin
```

For enum options, select a constant from `choices`. Analyzer enablement is a
boolean option, e.g. `analysis option set "ASCII Strings" false`.
Setting options does not run analysis.

```bash
# Revisit a known region, including analysis triggered by its references.
ghidra-cli analysis run --start 0x401000 --end 0x401fff --project target
# Process work already queued in the currently open program.
ghidra-cli analysis run --pending --project target
```

A range is an inclusive starting region, not a boundary on changes: analysis
can follow references outside it and process other queued work. Reanalysis does
not clear existing instructions; repair wrong decoding with
[context and code definitions](low-level.md#processor-context).

`--pending` uses Ghidra's live queue, not a saved history of edits. Cancelling
analysis, closing the program, and restarting the bridge discard queued work.
After any of those, or after changing analyzer settings, request a range or full
analysis to revisit the relevant code.
The `analyzed` flag in `program list` records a completed full analysis, not
whether subsequent edits have been analyzed; range/pending runs do not set it.

`program import INPUT --name NAME` saves under that project file name; omitting it
uses the input file name, including a symlink's name rather than its target's
name (Ghidra may add a suffix on collision).
See [starting with a program](../SKILL.md#start-with-a-program)
for the ordinary import workflow and recovery when an import error reports a
saved program.

### Raw import

Choose raw input's ISA, endianness, and load address from target evidence;
plausible disassembly alone does not validate them.

```bash
ghidra-cli program import ./firmware.bin --project firmware \
  --language x86:LE:32:default --base-address 0x8000 \
  --block-name ROM --no-analyze
```

`--base-address`, `--block-name`, `--file-offset`, and `--length` imply
`BinaryLoader`. Use `--language` to select the ISA and `--compiler-spec` to select
the compiler specification. `--base-address` is a BinaryLoader input, not a
general ELF/PE rebasing option. Raw import does not establish
an entry point. Use `listing define-code` and `function create` at a known code
address; see
[disassembly and analysis boundaries](low-level.md#disassembly-and-analysis-boundaries).

### Correcting import settings

`program info` reports `language_id` and `compiler_spec_id`, the exact IDs accepted
by import. Its `language` description and `compiler` metadata are not those IDs.
If the CPU, endianness, bitness, compiler specification, or loader was wrong,
import under a new name so the original remains available for comparison:

```bash
ghidra-cli program import ./firmware.bin --project firmware --name firmware-arm \
  --loader BinaryLoader --language ARM:LE:32:v8 \
  --base-address 0x80000000 --no-analyze
```

Manual annotations are not transferred to the new program. For ARM/Thumb mode
changes within the same language, use
[processor context](low-level.md#processor-context).

### Correcting the image base

When the language and layout are correct but the load position is wrong:

```bash
ghidra-cli program rebase 0x80000000 --project firmware --program firmware.bin
```

The argument is the absolute image base, which can differ from the first block's
address. Default-space blocks and associated Program addresses move together,
including MMIO. Overlays and other address spaces stay in place.

Rebase leaves pointer and immediate bytes unchanged and does not run analysis
or reapply loader relocations. Inspect affected pointers and references; if
correctness depends on the loader applying relocations again, use a separate
import with the appropriate loader settings.

## Export

Use `c` for decompiled C, `asm` for an instruction listing, `binary` for edited
bytes, and `gzf` for a Ghidra program archive.

```bash
ghidra-cli program export c --project target -o ./target.c
ghidra-cli program export gzf --project target -o ./target.gzf
ghidra-cli program export binary -o ./target.patched.bin --project target
```

C exports do not reconstruct complete data initializers.

`gzf` saves the program before packing and atomically replaces the destination
after successful export. Failure or cancellation before replacement preserves
an existing destination; filesystems without atomic replacement support return an error.

Import inputs and program export destinations resolve relative to the CLI's
working directory, including when reusing a bridge started elsewhere or executing
inside a batch.
