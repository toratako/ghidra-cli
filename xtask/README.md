# Developer tasks

`xtask` is a non-published workspace package. At the workspace root, `ghidra-cli`
remains the default package for `cargo build`, `cargo run`, and `cargo test`. The
[`cargo xtask` alias](../.cargo/config.toml) selects the task package.

## Commands

```bash
cargo xtask test --no-fail-fast
cargo xtask test --test comment_tests --test type_tests
cargo xtask gen-tree
cargo xtask gen-tree --check
cargo xtask fmt-java
cargo xtask fmt-java --check
```

`test` runs `cargo test` with every following argument unchanged and in order,
including `--help` and the test executable's arguments after `--`. It preserves
the caller's working directory, so relative paths such as `--manifest-path` keep
their meaning. A fresh temporary fixture directory stays alive until Cargo exits,
then is removed even if the tests fail. The task reports elapsed time and returns
Cargo's exit status. See [test commands and coverage](../tests/README.md) and
[fixture lifecycle](../tests/common/README.md#lifecycle-boundaries) for test
implementation details. Ghidra suites require a working
[Ghidra and JDK installation](../docs/runtime.md#installation).

`gen-tree` writes [the command tree](../docs/tree.md) from the same Clap definitions
as the CLI. Automatically generated `help` commands are omitted from the tree
and its node count. The task resolves the workspace root independently of the
caller's working directory and always writes `docs/tree.md` there. Regenerate it
after changing command definitions. `--check` leaves the file unchanged and fails
if it is missing or stale; it accepts CRLF line endings in Windows checkouts.

`fmt-java` formats complete `.java` files under the workspace's `src/` and `tests/`
directories with google-java-format 1.37.0 and Google's two-space indentation.
Long string literals retain their spelling for tests that modify Java source.
`--check` leaves files unchanged and fails when formatting is needed. Java fragments
(`.java.inc`), templates (`.java.in`), and inline parser test inputs keep their
intentional syntax and are excluded.

The formatter needs a full JDK 21 or newer, available through `JAVA_HOME` or
`PATH`, and `curl` on `PATH` for the first download. It downloads the official
all-deps JAR, verifies its pinned SHA-256, and caches it in
`target/google-java-format`. Ghidra is not required.

## Implementation and checks

| Source | Responsibility |
|---|---|
| [src/main.rs](src/main.rs) | Task dispatch |
| [src/test.rs](src/test.rs) | Cargo argument forwarding and run-scoped fixture lifetime |
| [src/gen_tree.rs](src/gen_tree.rs) | Command tree rendering, generation, and freshness checks |
| [src/fmt_java.rs](src/fmt_java.rs) | Pinned Java formatter download, verification, and source formatting |
| [../src/cli.rs](../src/cli.rs) | Shared CLI command definitions |

Run `cargo test -p xtask` and `cargo xtask gen-tree --check` without Ghidra.
See [repository checks](../tests/README.md#run) for formatting and lint commands.
