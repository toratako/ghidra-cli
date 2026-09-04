# Bundled ghidra-cli limitations

These limitations apply to the current Hina-bundled revision. Remove or rewrite
a workaround only after verifying its case against the bundled binary.

## Analyzer enable/disable CLI parser

`ghidra analyzer set` currently declares its `enabled` value as a positional
Rust `bool`. With the current clap configuration, even `ghidra analyzer set
--help` trips a debug assertion instead of producing a usable command parser.

Do not rely on `analyzer set` from an agent workflow until the CLI argument is
fixed (for example by parsing an explicit value such as `true|false` or by using
separate enable/disable flags/subcommands). `analyzer list` and `analyzer run`
remain usable.

## PE resources

The bundled revision has no resource list or export command. Use `wrestool` to
identify and extract the exact reported type, name, and language, then use Ghidra
to inspect consumers and control flow.

```bash
wrestool --list /samples/target.exe
wrestool --extract --raw --type=10 --name=101 \
  --output=/reports/target-rcdata-101.bin /samples/target.exe
```

Type 10 is `RCDATA`; the identifiers above are illustrative.
