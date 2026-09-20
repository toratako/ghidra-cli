# Scripting

Use Java scripts for processing that the built-in commands do not cover.

```bash
ghidra-cli script list --project target
ghidra-cli script run ./scripts/Inspect.java --project target -- --arg value
ghidra-cli script run ./scripts/Inspect.java --expect ./out.jsonl:10 --project target
ghidra-cli script run - --project target < ./scripts/Inspect.java
```

Script and `--expect` paths resolve from the CLI working directory.
Repeat `--expect PATH[:MIN_ROWS]` to reject missing/empty/short artifacts;
`--allow-empty` permits expected empty files.

Stdin source must declare exactly one top-level public class extending
`GhidraScript`. Keep supporting source files in the file script's parent
directory, which Ghidra uses as its source bundle.

Scripts follow the shared [save and failure behavior](../SKILL.md#results-edits-and-jobs).
