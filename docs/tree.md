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
│   ├── set-body
│   ├── call-signature
│   │   ├── get
│   │   ├── set
│   │   └── clear
│   ├── var
│   │   ├── list
│   │   ├── get
│   │   └── set
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
│   ├── block
│   │   ├── create
│   │   ├── rename
│   │   ├── set-permissions
│   │   ├── set-volatile
│   │   ├── move
│   │   └── delete
│   ├── info
│   ├── read
│   └── write
├── data
│   ├── list
│   └── read
├── listing
│   ├── define-code
│   ├── undefine
│   └── flow
│       ├── get
│       ├── set
│       └── clear
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
│   ├── clone
│   ├── resize
│   ├── move
│   ├── category
│   │   ├── list
│   │   ├── create
│   │   └── delete
│   ├── field
│   │   ├── append
│   │   ├── create-bitfield
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

186 command nodes (excluding the root), 0 aliases.
