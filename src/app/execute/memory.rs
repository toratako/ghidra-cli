use crate::cli::MemoryCommands;
use crate::ipc::client::BridgeClient;
use serde_json::{json, Value};

pub(super) fn validate(command: &MemoryCommands) -> anyhow::Result<()> {
    let addresses: Vec<&str> = match command {
        MemoryCommands::FileMappings(args) => args.source_at.iter().map(String::as_str).collect(),
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
        MemoryCommands::Map(_) => client.memory_map(),
        MemoryCommands::FileMappings(args) => {
            client.memory_file_mappings(args.file_offset.as_deref(), args.source_at.as_deref())
        }
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
    }
}
