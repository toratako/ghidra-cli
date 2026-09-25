use super::{batch_arguments, RecordedBridge};
use serde_json::Value;

#[path = "types/archives.rs"]
mod archives;
#[path = "types/commands.rs"]
mod commands;
#[path = "types/edits.rs"]
mod edits;
#[path = "types/uses.rs"]
mod uses;

pub(super) use archives::{gdt_candidates_fixture, gdt_transfer_fixture};
pub(super) use uses::{category_list_fixture, field_uses_fixture, uses_fixture};

fn run_envelope(bridge: &RecordedBridge, args: &[&str], batch: bool) -> Value {
    let output = if batch {
        std::fs::write(bridge.root.path().join("batch.txt"), batch_arguments(args)).unwrap();
        bridge
            .command()
            .args(["batch", "batch.txt"])
            .output()
            .unwrap()
    } else {
        bridge.command().args(args).output().unwrap()
    };
    assert!(
        output.status.success(),
        "{args:?}, batch={batch}: {output:?}"
    );
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    if batch {
        assert_eq!(result["data"]["failed"], 0);
        result["data"]["results"][0]["result"].clone()
    } else {
        result
    }
}
