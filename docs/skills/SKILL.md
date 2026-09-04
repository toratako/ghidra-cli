---
name: hina-ghidra
description: Analyze native binaries with the ghidra-cli revision bundled in the Hina analysis image, including durable import, decompilation, disassembly repair, functions, xrefs, strings, symbols, types, PCode, analyzer control, call graphs, scripts, and patch exploration. Use when a native executable or library needs structural or semantic reverse engineering through Ghidra.
---

# Hina Ghidra CLI

Use `/usr/local/bin/ghidra`, the bundled Rust ghidra-cli. `GHIDRA_INSTALL_DIR` and
persistent project storage under `/reports` are configured by the image;
`/samples` is read-only.

One localhost JVM bridge is kept per project and reused by later commands.
Program operations are serialized, while status, queued-job inspection, and
cooperative cancellation remain available.

A fresh `ghidra import` auto-analyzes and durably commits before the persistent
bridge opens the program. Do not immediately run `ghidra analyze` unless
reanalysis is intentional; use `--no-analyze` to skip analysis.

For raw/headerless binaries, provide the known language and load model explicitly;
do not infer ISA, endian, or base address from plausible disassembly.

```bash
ghidra doctor
ghidra import /samples/target.bin --project target --program target.bin
ghidra summary --project target --program target.bin
ghidra decompile main --with-vars --with-params --project target --program target.bin
```

Use [references/commands.md](references/commands.md) as the command catalog and
`ghidra <command> --help` for exact flags.

Mutations remain in the running bridge until flushed. Use `ghidra program save
--project NAME` when another Ghidra process must see them, or `ghidra stop
--project NAME` when ending the session.

Read [references/workarounds.md](references/workarounds.md) for limitations that
still apply to the bundled revision.
