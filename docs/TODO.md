# ghidra-cli TODO

Open owner notes. Fixed issues are recorded in Git history and regression tests.

- `tests/project_tests.rs` still gives full import/analyze operations a 300 s timeout. A full import with analysis has been observed near that budget under load; consider raising the integration-test budget (for example to 600 s) or deriving it from the long-operation timeout policy.

- External cleanup: `docs/GHIDRA_WORKFLOW.md` in `parasolid-re` still had the historical `--limit 1000000` workaround for the old `--limit 0` bug. Remove that workaround if it is still present.

- Destructive-operation dry-run/plan output remains open. Ordinary single-Program
  edits now have request-level rollback; a dry-run must separately account for
  scripts, project/filesystem effects, and operations that retain partial results.
- add `find text --regex`
