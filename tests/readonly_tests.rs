//! Read-query integration tests sharing one bridge and suite-owned project.

#[path = "support/json.rs"]
mod json_output;

use serial_test::serial;
use std::sync::OnceLock;

#[macro_use]
mod common;
use common::{ensure_test_project, ghidra, test_project, DaemonTestHarness};

#[path = "readonly/batch.rs"]
mod batch;
#[path = "readonly/bookmarks.rs"]
mod bookmarks;
#[path = "readonly/byte_regex.rs"]
mod byte_regex;
#[path = "readonly/calls.rs"]
mod calls;
#[path = "readonly/cfg.rs"]
mod cfg;
#[path = "readonly/constants.rs"]
mod constants;
#[path = "readonly/decompile.rs"]
mod decompile;
#[path = "readonly/decompile_addresses.rs"]
mod decompile_addresses;
#[path = "readonly/decompile_cli.rs"]
mod decompile_cli;
#[path = "readonly/decompile_details.rs"]
mod decompile_details;
#[path = "readonly/disassembly.rs"]
mod disassembly;
#[path = "readonly/function_details.rs"]
mod function_details;
#[path = "readonly/functions.rs"]
mod functions;
#[path = "readonly/high_pcode.rs"]
mod high_pcode;
#[path = "readonly/memory_info.rs"]
mod memory_info;
#[path = "readonly/program.rs"]
mod program;
#[path = "readonly/program_metadata.rs"]
mod program_metadata;
#[path = "readonly/query.rs"]
mod query;
#[path = "readonly/relationships.rs"]
mod relationships;
#[path = "readonly/search.rs"]
mod search;
#[path = "readonly/search_limits.rs"]
mod search_limits;
#[path = "readonly/strings.rs"]
mod strings;
#[path = "readonly/structure_inference.rs"]
mod structure_inference;

const TEST_PROGRAM: &str = common::FIXTURE_PROGRAM;

static HARNESS: OnceLock<DaemonTestHarness> = OnceLock::new();

fn harness() -> &'static DaemonTestHarness {
    HARNESS.get_or_init(|| {
        ensure_test_project(test_project(), TEST_PROGRAM);
        DaemonTestHarness::new(test_project(), TEST_PROGRAM).expect("Failed to start daemon")
    })
}
