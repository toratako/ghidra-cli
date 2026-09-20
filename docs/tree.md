# ghidra-cli command tree

Generated from `src/cli.rs` and `src/cli/*.rs` using Clap's `CommandFactory`.
Includes all subcommands and automatically generated `help` commands.
Command aliases are not supported; arguments and options are omitted.

Regenerate from the repository root with `cargo xtask gen-tree`.
Run `cargo xtask gen-tree --check` to verify that this document is current.

```text
ghidra-cli
├── project
│   ├── list
│   ├── delete
│   ├── info
│   └── help
│       ├── list
│       ├── delete
│       ├── info
│       └── help
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
│   ├── save
│   └── help
│       ├── list
│       ├── open
│       ├── close
│       ├── delete
│       ├── info
│       ├── stats
│       ├── imports
│       ├── exports
│       ├── export
│       ├── save
│       └── help
├── function
│   ├── list
│   ├── get
│   ├── disassemble
│   ├── calls
│   ├── rename
│   ├── create
│   ├── delete
│   ├── set-signature
│   ├── set-return-type
│   ├── set-calling-convention
│   ├── edit-var
│   ├── set-noreturn
│   └── help
│       ├── list
│       ├── get
│       ├── disassemble
│       ├── calls
│       ├── rename
│       ├── create
│       ├── delete
│       ├── set-signature
│       ├── set-return-type
│       ├── set-calling-convention
│       ├── edit-var
│       ├── set-noreturn
│       └── help
├── string
│   ├── list
│   ├── refs
│   └── help
│       ├── list
│       ├── refs
│       └── help
├── symbol
│   ├── list
│   ├── get
│   ├── create
│   ├── delete
│   ├── rename
│   └── help
│       ├── list
│       ├── get
│       ├── create
│       ├── delete
│       ├── rename
│       └── help
├── memory
│   ├── map
│   ├── read
│   ├── write
│   └── help
│       ├── map
│       ├── read
│       ├── write
│       └── help
├── xref
│   ├── to
│   ├── from
│   └── help
│       ├── to
│       ├── from
│       └── help
├── type
│   ├── list
│   ├── get
│   ├── create
│   │   ├── struct
│   │   ├── enum
│   │   ├── typedef
│   │   └── help
│   │       ├── struct
│   │       ├── enum
│   │       ├── typedef
│   │       └── help
│   ├── apply
│   ├── import-c
│   ├── delete
│   ├── rename
│   ├── add-field
│   ├── set-field
│   ├── clear-field
│   ├── del-field
│   └── help
│       ├── list
│       ├── get
│       ├── create
│       │   ├── struct
│       │   ├── enum
│       │   └── typedef
│       ├── apply
│       ├── import-c
│       ├── delete
│       ├── rename
│       ├── add-field
│       ├── set-field
│       ├── clear-field
│       ├── del-field
│       └── help
├── tag
│   ├── list
│   ├── get
│   ├── create
│   ├── delete
│   ├── rename
│   ├── set-comment
│   ├── add
│   ├── remove
│   └── help
│       ├── list
│       ├── get
│       ├── create
│       ├── delete
│       ├── rename
│       ├── set-comment
│       ├── add
│       ├── remove
│       └── help
├── pcode
│   ├── at
│   ├── function
│   └── help
│       ├── at
│       ├── function
│       └── help
├── analyzer
│   ├── list
│   ├── set
│   └── help
│       ├── list
│       ├── set
│       └── help
├── comment
│   ├── list
│   ├── get
│   ├── set
│   ├── delete
│   └── help
│       ├── list
│       ├── get
│       ├── set
│       ├── delete
│       └── help
├── find
│   ├── string
│   ├── text
│   ├── bytes
│   ├── instruction
│   ├── calls
│   └── help
│       ├── string
│       ├── text
│       ├── bytes
│       ├── instruction
│       ├── calls
│       └── help
├── graph
│   ├── calls
│   ├── callers
│   ├── callees
│   └── help
│       ├── calls
│       ├── callers
│       ├── callees
│       └── help
├── decompile
├── disassemble
├── define-code
├── clear
├── script
│   ├── run
│   ├── list
│   └── help
│       ├── run
│       ├── list
│       └── help
├── batch
├── config
│   ├── list
│   ├── get
│   ├── set
│   ├── reset
│   └── help
│       ├── list
│       ├── get
│       ├── set
│       ├── reset
│       └── help
├── doctor
├── import
├── analyze
├── bridge
│   ├── start
│   ├── stop
│   ├── restart
│   ├── status
│   ├── ping
│   └── help
│       ├── start
│       ├── stop
│       ├── restart
│       ├── status
│       ├── ping
│       └── help
├── job
│   ├── list
│   ├── get
│   ├── cancel
│   └── help
│       ├── list
│       ├── get
│       ├── cancel
│       └── help
├── setup
└── help
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
    │   ├── calls
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
    │   ├── instruction
    │   └── calls
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
    ├── setup
    └── help
```

364 command nodes (excluding the root), 0 aliases.
