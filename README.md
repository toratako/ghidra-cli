# Ghidra CLI

A Rust CLI for AI agents automating native-binary reverse engineering with
Ghidra: decompilation, queries, types, scripts, and patches. One persistent Java
bridge per project keeps analysis state in Ghidra's JVM and avoids starting it
for every command. No separate Rust daemon or Python/PyGhidra is required.

## Install

Build with a current stable Rust toolchain:

```bash
git clone https://github.com/akiselev/ghidra-cli
cd ghidra-cli
cargo install --path .
```

Install Ghidra 11+ with `ghidra setup`, or set `GHIDRA_INSTALL_DIR` to an existing
installation. A full JDK is required (`javac` and `jdk.compiler`, not a JRE);
Ghidra 12.x requires JDK 21 (older releases accept JDK 17). The CLI selects a
suitable JDK automatically; `--java-home` overrides it. `ghidra doctor` checks the
installation and compiles the embedded bridge bundle.

## Start an analysis

```bash
ghidra doctor
ghidra import ./binary --project analysis --program binary
ghidra --project analysis --program binary function list --limit 20
ghidra --project analysis --program binary decompile main
# Flush edits before another process reads the project.
ghidra program save --project analysis --program binary
ghidra stop --project analysis
```

Fresh import analyzes and commits the program before opening the persistent
bridge; use `--no-analyze` to skip analysis. Program operations are serialized;
`status`, `jobs`, and `cancel` remain responsive during long jobs.

Output defaults to human-readable on a terminal and compact JSON when piped.
Use `--json` or `--pretty` explicitly in automation.

## Documentation

- [Command catalog](docs/commands.md) and `ghidra <command> --help`.
- [Configuration, timeouts, and recovery](docs/usage.md).
- [Documentation map](docs/README.md), including the private Hina skill mirror.
- [Contributor constraints](AGENTS.md) and [tests](tests/README.md).
- [Release history](CHANGELOG.md).

Licensed under [GPL-3.0](LICENSE).
