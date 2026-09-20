# Developer tasks

`xtask` is a non-published workspace package. At the workspace root, `ghidra-cli`
remains the default package for `cargo build`, `cargo run`, and `cargo test`. The
[`cargo xtask` alias](../.cargo/config.toml) selects the task package.

## Commands

```bash
cargo xtask test --no-fail-fast
cargo xtask test --test comment_tests --test type_tests
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

## Implementation and checks

| Source | Responsibility |
|---|---|
| [src/main.rs](src/main.rs) | Task dispatch |
| [src/test.rs](src/test.rs) | Cargo argument forwarding and run-scoped fixture lifetime |

These checks cover the task package without Ghidra:

```bash
cargo test -p xtask
cargo fmt --all -- --check
cargo clippy --workspace -- -D warnings
```
