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
│   ├── list-relocations
│   ├── context
│   │   ├── list
│   │   ├── get
│   │   ├── set
│   │   └── clear
│   ├── rebase
│   ├── import
│   ├── export
│   └── save
├── function
│   ├── list
│   ├── get
│   ├── list-calling-conventions
│   ├── disassemble
│   ├── rename
│   ├── create
│   ├── delete
│   ├── set-signature
│   ├── set-return-type
│   ├── set-calling-convention
│   ├── set-stack-purge
│   ├── edit-var
│   └── set-noreturn
├── string
│   ├── list
│   └── refs
├── symbol
│   ├── list
│   ├── get
│   ├── externals
│   ├── entry-points
│   ├── create-label
│   ├── delete
│   ├── rename
│   ├── set-namespace
│   └── set-primary
├── equate
│   ├── list
│   ├── get
│   ├── create
│   ├── attach
│   ├── detach
│   └── delete
├── namespace
│   ├── list
│   ├── get
│   └── create
├── memory
│   ├── map
│   ├── file-mappings
│   ├── info
│   ├── read
│   └── write
├── data
│   ├── list
│   └── read
├── listing
│   ├── define-code
│   └── undefine
├── xref
│   ├── to
│   ├── from
│   ├── create
│   │   └── memory
│   ├── delete
│   └── set-primary
├── type
│   ├── list
│   ├── get
│   ├── create
│   │   ├── struct
│   │   ├── union
│   │   ├── enum
│   │   └── typedef
│   ├── apply
│   ├── import-c
│   ├── delete
│   ├── rename
│   ├── field
│   │   ├── append
│   │   ├── set
│   │   ├── clear
│   │   └── delete
│   └── enum
│       └── member
│           └── delete
├── tag
│   ├── list
│   ├── get
│   ├── create
│   ├── delete
│   ├── rename
│   ├── set-comment
│   ├── attach
│   └── detach
├── pcode
│   ├── at
│   └── function
├── analysis
│   ├── run
│   └── option
│       ├── list
│       ├── get
│       └── set
├── comment
│   ├── list
│   ├── get
│   ├── set
│   └── delete
├── bookmark
│   ├── list
│   ├── get
│   ├── set
│   └── delete
├── find
│   ├── string
│   ├── text
│   ├── bytes
│   ├── instruction
│   └── constant
├── graph
│   ├── calls
│   ├── callers
│   └── callees
├── decompile
├── disassemble
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

159 command nodes (excluding the root), 0 aliases.
