# ghidra-cli TODO

Status: first-pass pruning candidate. Completed bug history was removed; Git history and regression tests are the canonical record for fixed issues.

- `tests/project_tests.rs` still gives full import/analyze operations a 300 s timeout. A full import with analysis has been observed near that budget under load; consider raising the integration-test budget (for example to 600 s) or deriving it from the long-operation timeout policy.

- `src/filter.pest` defines `expr = { logical_expr }` without `SOI`/`EOI`. Verify whether Pest accepts trailing garbage after an otherwise valid expression (for example `name=test garbage`); if so, anchor the grammar and add a regression test.

- External cleanup: `docs/GHIDRA_WORKFLOW.md` in `parasolid-re` still had the historical `--limit 1000000` workaround for the old `--limit 0` bug. Remove that workaround if it is still present.
