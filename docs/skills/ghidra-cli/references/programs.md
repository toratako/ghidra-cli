# Programs and artifacts

## Project, program, and bridge state

```bash
ghidra-cli project list
ghidra-cli project info target
ghidra-cli program list --project target
ghidra-cli program info target.bin --project target
ghidra-cli program list-relocations --filter 'status=FAILURE' --project target
ghidra-cli bridge status --project target
ghidra-cli job list --project target
ghidra-cli job get 2c7a3b91-f960-4b85-87d7-e90cf7bf0625 --project target
ghidra-cli job cancel --project target
ghidra-cli bridge restart --project target --program target.bin
ghidra-cli program save target.bin --project target
ghidra-cli bridge stop --project target
```

`project delete` stops the bridge before deletion.
`program list` includes subfolders. The project-file `path` from `program list`
or `program info` distinguishes same-named programs. Displayed program names
are saved file names.

## Project snapshots

GAR holds a project, including its Programs and type archives; GZF holds one Program.

```bash
ghidra-cli project archive target --output ./target-20260922.gar
ghidra-cli project restore ./target-20260922.gar target-copy --projects-dir ./restored
```

Archive waits for accepted work, saves pending edits, and leaves the bridge
stopped.
Archive publication requires hard-link support on the destination filesystem;
if unavailable, create the GAR on a local filesystem and copy it afterward.

GAR preserves project links without bundling or rewriting their targets.
`external_dependencies.links` scans project links only, not other external files;
`complete: false` means link inspection was unavailable for this Ghidra version.

## External symbols and entry points

```bash
ghidra-cli symbol externals --filter 'library~libc' --fields name,address --limit 0
ghidra-cli symbol entry-points --sort name --limit 0
```

## Import and reanalysis

```bash
ghidra-cli program import ./target.bin --project target --no-analyze
ghidra-cli analysis option list --project target --filter 'name~"ASCII Strings"'
ghidra-cli analysis option set "ASCII Strings" true --project target
ghidra-cli analysis option get "ASCII Strings.Minimum String Length" --project target
ghidra-cli analysis option set "ASCII Strings.Minimum String Length" LEN_10 --project target
ghidra-cli analysis run --project target --program target.bin

ghidra-cli analysis run --start 0x401000 --end 0x401fff --project target
ghidra-cli analysis run --pending --project target
```

A range is an inclusive starting region, not a boundary on changes: analysis
can follow references outside it and process other queued work. Reanalysis does
not clear existing instructions; repair wrong decoding with
[context and code definitions](low-level.md#processor-context).

`--pending` uses Ghidra's live queue, not a saved history of edits. Cancelling
analysis, closing the program, and restarting the bridge discard queued work.
Range or full analysis can revisit code after queue loss or analyzer setting changes.
The `analyzed` flag in `program list` records a completed full analysis, not
whether subsequent edits have been analyzed; range/pending runs do not set it.

Without `program import --name`, the saved name follows the input filename,
including a symlink's name rather than its target's. Ghidra may add a suffix
on collision.

### Raw import

```bash
ghidra-cli program import ./firmware.bin --project firmware \
  --language x86:LE:32:default --base-address 0x8000 \
  --block-name ROM --no-analyze
```

`--base-address`, `--block-name`, `--file-offset`, and `--length` imply
`BinaryLoader`; `--base-address` is not a general ELF/PE rebasing option.
Raw import does not establish an entry point; see
[code definitions and analysis boundaries](low-level.md#code-definitions-and-analysis-boundaries).

### Correcting import settings

`program info` reports `language_id` and `compiler_spec_id`, the exact IDs accepted
by import. Its `language` description and `compiler` metadata are not those IDs.

```bash
ghidra-cli program import ./firmware.bin --project firmware --name firmware-arm \
  --loader BinaryLoader --language ARM:LE:32:v8 \
  --base-address 0x80000000 --no-analyze
```

For ARM/Thumb mode changes within the same language, use
[processor context](low-level.md#processor-context).

### Correcting the image base

```bash
ghidra-cli program rebase firmware.bin --base 0x80000000 --project firmware
```

`--base` is the absolute image base, which can differ from the first block's
address. Default-space blocks and associated Program addresses move together,
including MMIO. Overlays and other address spaces stay in place.

Rebase leaves pointer and immediate bytes unchanged and does not run analysis
or reapply loader relocations. Re-import can reapply relocations.

## Reusing archived types

```bash
ghidra-cli type archive inspect sdk.gdt --filter 'category^"/SDK"' --project target
ghidra-cli type archive import sdk.gdt --where 'path="/SDK/Header"' --project target
ghidra-cli listing define-data 0x404000 --type /SDK/Header --project target
ghidra-cli type archive export protocol.gdt --where 'category^"/Protocol"' --project target
```

Selected roots bring their dependencies, even from other categories. Conflicting
definitions/origins or ABI layout changes reject the entire import. Changing roots
can still select the conflicting dependency reported in the dependency path.
Layout conflicts require an archive compatible with the target ABI.

Equivalent local definitions can adopt the archive's identity. Export gives local
types new archive identities and preserves existing file-archive origins.
GDT cannot retain field-specific interpretation settings such as endian overrides.

## Export

```bash
ghidra-cli program export target.bin --export-format c --project target -o ./target.c
ghidra-cli program export target.bin --export-format gzf --project target -o ./target.gzf
ghidra-cli program export target.bin --export-format binary -o ./target.patched.bin --project target
```

C exports do not reconstruct complete data initializers.

`gzf` saves the program before packing and atomically replaces the destination
after successful export. Failure or cancellation before replacement preserves
an existing destination; filesystems without atomic replacement support return an error.

Import inputs and program export destinations resolve relative to the CLI's
working directory, including when reusing a bridge started elsewhere or executing
inside a batch.
