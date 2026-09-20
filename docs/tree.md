# ghidra-cli command tree

Generated from `src/cli.rs` and `src/cli/*.rs` using Clap's `CommandFactory`.
Automatically generated `help` commands, arguments, and options are omitted.
Command aliases are not supported.
For command details, run `ghidra-cli <command> --help`.

Regenerate from the repository root with `cargo xtask gen-tree`.
Run `cargo xtask gen-tree --check` to verify that this document is current.

```text
ghidra-cli
├── project
│   ├── list
│   ├── delete
│   └── info
├── program
│   ├── list
│   ├── open
│   ├── close
│   ├── delete
│   ├── info
│   ├── stats
│   ├── imports
│   ├── exports
│   ├── export
│   └── save
├── function
│   ├── list
│   ├── get
│   ├── disassemble
│   ├── rename
│   ├── create
│   ├── delete
│   ├── set-signature
│   ├── set-return-type
│   ├── set-calling-convention
│   ├── edit-var
│   └── set-noreturn
├── string
│   ├── list
│   └── refs
├── symbol
│   ├── list
│   ├── get
│   ├── create
│   ├── delete
│   └── rename
├── memory
│   ├── map
│   ├── read
│   └── write
├── xref
│   ├── to
│   └── from
├── type
│   ├── list
│   ├── get
│   ├── create
│   │   ├── struct
│   │   ├── enum
│   │   └── typedef
│   ├── apply
│   ├── import-c
│   ├── delete
│   ├── rename
│   ├── add-field
│   ├── set-field
│   ├── clear-field
│   └── del-field
├── tag
│   ├── list
│   ├── get
│   ├── create
│   ├── delete
│   ├── rename
│   ├── set-comment
│   ├── add
│   └── remove
├── pcode
│   ├── at
│   └── function
├── analyzer
│   ├── list
│   └── set
├── comment
│   ├── list
│   ├── get
│   ├── set
│   └── delete
├── find
│   ├── string
│   ├── text
│   ├── bytes
│   └── instruction
├── graph
│   ├── calls
│   ├── callers
│   └── callees
├── decompile
├── disassemble
├── define-code
├── clear
├── script
│   ├── run
│   └── list
├── batch
├── config
│   ├── list
│   ├── get
│   ├── set
│   └── reset
├── doctor
├── import
├── analyze
├── bridge
│   ├── start
│   ├── stop
│   ├── restart
│   ├── status
│   └── ping
├── job
│   ├── list
│   ├── get
│   └── cancel
└── setup
```

114 command nodes (excluding the root), 0 aliases.
