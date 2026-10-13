# Test fixtures

Keep independent test programs, Ghidra setup scripts, state checks, and fault
probes in domain directories here. Rust suites own their execution order,
arguments, assertions, and resource lifetimes. Keep short boundary values and
syntax examples inline when their contents are the subject of the test.

Use `include_str!` when passing Java source to `script_run_source`; extracting
a fixture must not change a source-execution test into a file-execution test.
Complete Java scripts use their public class name as the filename. Shared Java
fragments use `.java.inc`; templates with explicit insertion markers use
`.java.in`. Keep both beside the scripts that use them.

Format complete `.java` fixtures with `cargo xtask fmt-java`; CI checks them with
`cargo xtask fmt-java --check`. Fragments, templates, and inline parser inputs keep
their intentional syntax. See [developer tasks](../../xtask/README.md) for formatter
setup.

Treat this tree as read-only during tests. Stage scripts that need file execution
or modification into an owned `tempfile` directory and retain its owner until
execution finishes. Generated binaries, projects, archives, and artifacts also
belong in temporary storage. See [common fixture lifecycle](../common/README.md#lifecycle-boundaries)
for run-scoped compilation, analyzed sources, and isolated project copies.

Keep fixture-specific layout assumptions and regeneration commands with the
fixture, as in [the vtable fixtures](vtable/README.md).
