# Ghidra CLI

A Rust CLI for AI agents automating native-binary reverse engineering with
Ghidra: decompilation, queries, types, scripts, and patches. One persistent Java
bridge per project keeps analysis state in Ghidra's JVM between commands.

## Install

Requires a stable Rust toolchain and a full JDK compatible with your Ghidra
version (JDK 21 for Ghidra 12.x).

```bash
git clone https://github.com/toratako/ghidra-cli
cd ghidra-cli
cargo install --path .
ghidra setup
ghidra doctor
```

For an existing Ghidra installation, set `GHIDRA_INSTALL_DIR` instead of running
`ghidra setup`. Doctor exits with code 1 if a readiness check fails.

## Usage

- [ghidra-cli skill](docs/skills/SKILL.md): commands and operational semantics for RE agents.
- [Configuration and recovery](docs/runtime.md): JDK selection, environment variables, and troubleshooting.

For development, see [AGENTS.md](AGENTS.md), [tests](tests/README.md), and the
[documentation map](docs/README.md). [Release history](CHANGELOG.md) records past changes.

Licensed under [GPL-3.0](LICENSE).
