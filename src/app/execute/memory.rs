use crate::cli::{MemoryBlockCommands, MemoryCommands};
use crate::ipc::client::{BridgeClient, MemoryBlockCreateRequest};
use serde_json::{json, Value};

pub(super) fn validate(command: &MemoryCommands) -> anyhow::Result<()> {
    let addresses: Vec<&str> = match command {
        MemoryCommands::ReadVtable(args) => {
            args.validate().map_err(anyhow::Error::msg)?;
            vec![]
        }
        MemoryCommands::FileMappings(args) => args.source_at.iter().map(String::as_str).collect(),
        MemoryCommands::Block(command) => match command {
            MemoryBlockCommands::List(_) => vec![],
            MemoryBlockCommands::Create(args) => vec![&args.start],
            MemoryBlockCommands::Set(args) => vec![&args.block_start],
            MemoryBlockCommands::Move(args) => vec![&args.block_start, &args.start],
            MemoryBlockCommands::Delete(args) => vec![&args.block_start],
        },
        _ => vec![],
    };
    for address in addresses {
        anyhow::ensure!(
            crate::address::ExplicitAddress::parse(address).is_some(),
            "Invalid address '{address}': use an explicit 0x-prefixed address"
        );
    }
    Ok(())
}

pub(super) fn execute(client: &BridgeClient, command: &MemoryCommands) -> anyhow::Result<Value> {
    match command {
        MemoryCommands::FileMappings(args) => {
            client.memory_file_mappings(args.file_offset.as_deref(), args.source_at.as_deref())
        }
        MemoryCommands::Block(command) => match command {
            MemoryBlockCommands::List(_) => client.memory_block_list(),
            MemoryBlockCommands::Create(args) => {
                client.memory_block_create(MemoryBlockCreateRequest {
                    name: &args.name,
                    start: &args.start,
                    size: args.size,
                    uninitialized: args.uninitialized,
                    fill: args.fill,
                    permissions: &args.permissions,
                    volatile: args.volatile,
                    overlay: args.overlay.as_deref(),
                })
            }
            MemoryBlockCommands::Set(args) => client.memory_block_set(
                &args.block_start,
                args.name.as_deref(),
                args.permissions.as_deref(),
                args.volatile,
            ),
            MemoryBlockCommands::Move(args) => {
                client.memory_block_move(&args.block_start, &args.start)
            }
            MemoryBlockCommands::Delete(args) => client.memory_block_delete(&args.block_start),
        },
        MemoryCommands::Info(args) => client.memory_info(&args.target),
        MemoryCommands::Write(args) => client.memory_write(&args.address, &args.hex),
        MemoryCommands::Read(args) => client.send_command(
            "read_memory",
            Some(json!({
                "address": args.address,
                "size": args.size,
                "source": args.source,
            })),
        ),
        MemoryCommands::ReadVtable(args) => client.send_command(
            "vtable_read",
            Some(json!({
                "target": args.target,
                "entries": args.entries,
                "abi": args.abi,
                "encoding": args.encoding,
            })),
        ),
    }
}
