# Bundled ghidra-cli limitations

These apply to the current Hina-bundled revision.

## Analyzer enable/disable

`ghidra analyzer set` has a broken positional-`bool` clap definition; even
`--help` can panic. Use `analyzer list` and `analyzer run`, but do not rely on
`analyzer set` until fixed.

## PE resources

ghidra-cli has no PE resource list/export command. Use `wrestool` to identify
and extract the exact resource, then inspect consumers in Ghidra.

```bash
wrestool --list /samples/target.exe
wrestool --extract --raw --type=10 --name=101 \
  --output=/reports/target-rcdata-101.bin /samples/target.exe
```

Type/name identifiers above are illustrative.
