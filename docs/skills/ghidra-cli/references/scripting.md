# Scripting

Use Java scripts for processing that the built-in commands do not cover.

```bash
ghidra-cli script list --project target
ghidra-cli script run ./scripts/Inspect.java --project target -- --arg value
ghidra-cli script run ./scripts/Inspect.java --expect ./out.jsonl:10 --project target
ghidra-cli script run - --project target < ./scripts/Inspect.java
```

Script paths resolve absolutely; results include arguments after `--` and captured
stdout. Artifact hash/read failures return errors. Repeat `--expect PATH[:MIN_ROWS]`
to reject missing/empty/short artifacts; `--allow-empty` permits expected empty files.
Java source uses Ghidra's bundle/compile path. Use `script run PATH` or
`script run -` with Java source on stdin.

Stdin source must declare exactly one top-level public class that Ghidra can load
as a script. Package declarations are supported for both file and stdin scripts;
the public class must extend `GhidraScript`. File scripts retain their parent
directory as the source bundle, so supporting source files belong in that bundle.

Scripts follow the shared [save and failure behavior](../SKILL.md#results-edits-and-jobs).
