---
name: hina-ghidra
description: Analyze native binaries with the ghidra-cli revision bundled in the Hina analysis image, including durable import, decompilation, disassembly repair, functions, xrefs, strings, symbols, types, PCode, analyzer control, call graphs, scripts, and patch exploration. Use when a native executable or library needs structural or semantic reverse engineering through Ghidra.
---

# Hina Ghidra CLI

Use `/usr/local/bin/ghidra`, the bundled Rust ghidra-cli rather than Ghidra's
desktop launcher. `GHIDRA_INSTALL_DIR` and persistent project storage under
`/reports` are configured by the image.

One localhost JVM bridge is kept per project and reused by later commands.
Program operations are serialized, while status, queued-job inspection, and
cooperative cancellation remain available.

A fresh `ghidra import` performs auto-analysis in the short-lived import process
and durably commits the analyzed program before the persistent bridge opens it.
Do not immediately run `ghidra analyze` unless reanalysis is intentional. Use
`--no-analyze` when an import-only operation is desired.

```bash
ghidra doctor
ghidra import /samples/target.bin --project target --program target.bin
ghidra summary --project target --program target.bin
ghidra decompile main --with-vars --with-params \
  --project target --program target.bin
```

Prefer the concrete command families and use cases in
[references/commands.md](references/commands.md). Use `ghidra <command> --help`
when exact flags matter.

For focused list/query operations, use filters, fields, and limits. In particular,
`graph callers` and `graph callees` enforce a simple `--limit N` inside the Java
bridge and stop recursive traversal once the cap is reached. When filter, sort,
count, or offset semantics require the complete result set, ghidra-cli may still
fetch/traverse more before applying client-side processing.

Apply useful names, types, signatures, comments, and code corrections to the
project, then re-query affected functions. Mutations remain in the running
bridge until they are flushed. Run `ghidra program save --project NAME` when a
fresh bridge or the GUI must see important edits; it deliberately stops and
restarts the bridge to make the changes durable. `ghidra stop --project NAME`
also flushes on clean shutdown and is appropriate when ending the session.

Export patched binaries and standalone artifacts to `/reports`; `/samples` is
read-only.

Read [references/workarounds.md](references/workarounds.md) for limitations that
still apply to the bundled revision. 
