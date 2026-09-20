# Ghidra CLI

> ⚠️ This project is under very active development and all types of backward compatibility are not being considered. ⚠️
> Check this repository and frequently update executable and skills for the better experience!

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
ghidra-cli setup
ghidra-cli doctor
```

For an existing Ghidra installation, set `GHIDRA_INSTALL_DIR` instead of running
`ghidra-cli setup`.

## Usage

- [ghidra-cli skill](docs/skills/ghidra-cli/SKILL.md): commands and operational semantics for RE agents.
- [Configuration and recovery](docs/runtime.md): JDK selection, environment variables, and troubleshooting.

Development: [AGENTS.md](AGENTS.md), [tests](tests/README.md),
[documentation map](docs/README.md), and [release history](CHANGELOG.md).

Licensed under [GPL-3.0](LICENSE).
