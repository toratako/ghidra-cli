# Ghidra CLI

> ⚠️ This project is under very active development and all types of backward compatibility are not being considered. ⚠️
>
> Check this repository and frequently update executable and skills for the better experience!

A Rust CLI for AI agents automating native-binary reverse engineering with
Ghidra: decompilation, queries, types, scripts, and patches. One persistent Java
bridge per project keeps analysis state in Ghidra's JVM between commands.

## Install

Install [Ghidra](https://github.com/NationalSecurityAgency/ghidra/releases) and a
compatible full JDK (JDK 21 for Ghidra 12.x) separately. Building the CLI requires
a stable Rust toolchain. See [runtime installation](docs/runtime.md#installation)
for platform-specific requirements.

```bash
git clone https://github.com/toratako/ghidra-cli
cd ghidra-cli
cargo install --path .
ghidra-cli doctor
```

Ghidra is detected from PATH and known installation locations. If it is not
found, set `GHIDRA_INSTALL_DIR` or run
`ghidra-cli config set ghidra_install_dir /path/to/ghidra`, then rerun `doctor`.
To use a standalone `ghidra.jar` built by Ghidra's official `buildGhidraJar`, set
`GHIDRA_JAR` or run `ghidra-cli config set ghidra_jar /path/to/ghidra.jar`.
See [standalone JAR setup](docs/runtime.md#standalone-ghidra-jar) for build requirements.
Use `ghidra-cli doctor --runtime` to also verify bridge startup.

## Usage

- [ghidra-cli skill](docs/skills/ghidra-cli/SKILL.md): commands and operational semantics for RE agents.
- [Configuration and recovery](docs/runtime.md): JDK selection, environment variables, and troubleshooting.

Development: [AGENTS.md](AGENTS.md), [tests](tests/README.md),
[documentation map](docs/README.md), and [release history](CHANGELOG.md).

Licensed under [GPL-3.0](LICENSE).
