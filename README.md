# Ghidra CLI

> ⚠️ This project is under very active development and all types of backward compatibility are not being considered. ⚠️
>
> Check this repository and frequently update executable and skills for the better experience!

A Rust CLI for AI agents automating native-binary reverse engineering with
Ghidra: decompilation, queries, types, scripts, and patches. One persistent Java
bridge per project keeps analysis state in Ghidra's JVM between commands.

See [ghidra-cli command tree](docs/tree.md)!

## Install

Install [Ghidra](https://github.com/NationalSecurityAgency/ghidra/releases) and a compatible full JDK (JDK 21 for Ghidra 12.x) separately.  
Building the CLI requires a stable Rust toolchain.  
See [runtime installation](docs/runtime.md#installation) for platform-specific requirements.

```bash
git clone https://github.com/toratako/ghidra-cli.git
cd ghidra-cli
cargo install --path .
ghidra-cli doctor
```

or download a prebuilt binary from [releases](https://github.com/toratako/ghidra-cli/releases).  
Windows/Linux/macOS binaries are available.

Ghidra is detected from PATH and known installation locations.  
If it is not found, set `GHIDRA_INSTALL_DIR` or  
run `ghidra-cli config set ghidra_install_dir /path/to/ghidra`, then rerun `doctor`.

To use a standalone `ghidra.jar` built by Ghidra's official `buildGhidraJar`, set
`GHIDRA_JAR` or run `ghidra-cli config set ghidra_jar /path/to/ghidra.jar`.  
See [standalone JAR setup](docs/runtime.md#standalone-ghidra-jar) for build requirements.
Use `ghidra-cli doctor --runtime` to also verify bridge startup.

### Skills

There is already an optimized [ghidra-cli skill](docs/skills/ghidra-cli/SKILL.md) for strong agents.  
This skill is thin and does not include RE workflow, just usage and examples of the CLI commands.

Install [ghidra-cli skill](docs/skills/ghidra-cli/) (If you download from [releases](https://github.com/toratako/ghidra-cli/releases), use `ghidra-cli-<version>-skill.zip`) to your agents:  
[Claude Code](https://code.claude.com/docs/en/skills#where-skills-live), [Codex](https://learn.chatgpt.com/docs/build-skills#where-codex-loads-local-skills), [Cursor](https://prod.cursor.com/docs/skills#skill-directories), [Gemini CLI](https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/using-agent-skills.md#discovery-tiers), [OpenCode](https://opencode.ai/docs/skills#place-files)

## Usage

- [ghidra-cli skill](docs/skills/ghidra-cli/SKILL.md): commands and operational semantics for RE agents.
- [Configuration and recovery](docs/runtime.md): JDK selection, environment variables, and troubleshooting.

Development: [AGENTS.md](AGENTS.md), [tests](tests/README.md),
[documentation map](docs/README.md), and [release history](CHANGELOG.md).

## Uninstall

```bash
cargo uninstall ghidra-cli
rm -rf ~/.config/ghidra-cli/
rm -rf ~/.local/share/ghidra-cli/
```

## License

Licensed under [GPL-3.0](LICENSE).  
This project is based on [akiselev/ghidra-cli](https://github.com/akiselev/ghidra-cli). Thanks a lot!
