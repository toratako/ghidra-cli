//! Archive paths and guarded root selection are resolved in the invoking client.

use crate::app::output::describe_selector_error;
use crate::cli::{TypeArchiveListArgs, TypeGdtArgs};
use crate::filter::Filter;
use crate::ipc::client::BridgeClient;
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

pub(super) fn parse_selection(args: &TypeGdtArgs) -> Result<Option<Filter>> {
    anyhow::ensure!(
        args.all != args.where_expr.is_some(),
        "Specify exactly one of --where or --all"
    );
    args.where_expr
        .as_deref()
        .map(|expression| Filter::parse(expression).map_err(describe_selector_error))
        .transpose()
}

pub(super) fn list(client: &BridgeClient, args: &TypeArchiveListArgs) -> Result<Value> {
    let file = input_path(&args.file)?;
    // Query processing stays client-side so filters, sorting and counts always
    // see the full archive, independently of the configured display limit.
    client.send_command(
        "type_archive_list",
        Some(json!({"file": wire_path(&file)?})),
    )
}

pub(super) fn transfer(client: &BridgeClient, args: &TypeGdtArgs, import: bool) -> Result<Value> {
    let filter = parse_selection(args)?;
    let file = if import {
        input_path(&args.file)?
    } else {
        output_path(&args.file)?
    };
    let file = wire_path(&file)?;
    let mut request = json!({"file": file});
    if let Some(filter) = filter {
        let candidates = client.send_command(
            "type_gdt_candidates",
            Some(if import {
                json!({"file": file})
            } else {
                json!({})
            }),
        )?;
        let rows = candidates["types"]
            .as_array()
            .context("Bridge did not return GDT selection candidates")?;
        let source = candidates["source"]
            .as_object()
            .context("Bridge did not return GDT selection source guard")?;
        let mut paths = Vec::new();
        for row in rows {
            if filter.evaluate(row).map_err(describe_selector_error)? {
                paths.push(
                    row["path"]
                        .as_str()
                        .context("Bridge did not return a selected type path")?,
                );
            }
        }
        anyhow::ensure!(
            !paths.is_empty(),
            "No types match --where '{}'",
            args.where_expr.as_deref().unwrap_or_default()
        );
        request["paths"] = json!(paths);
        request["source"] = json!(source);
    } else {
        request["all"] = json!(true);
    }
    client.send_command(
        if import {
            "type_import_gdt"
        } else {
            "type_export_gdt"
        },
        Some(request),
    )
}

fn wire_path(file: &Path) -> Result<&str> {
    file.to_str().with_context(|| {
        format!(
            "Archive path cannot be represented as UTF-8: {}",
            file.display()
        )
    })
}

fn validate_extension(file: &Path) -> Result<()> {
    anyhow::ensure!(
        file.extension().is_some_and(|extension| extension == "gdt"),
        "Archive must be a .gdt file: {}",
        file.display()
    );
    Ok(())
}

fn input_path(file: &Path) -> Result<PathBuf> {
    validate_extension(file)?;
    let file = dunce::canonicalize(file)
        .with_context(|| format!("Cannot resolve archive: {}", file.display()))?;
    let metadata = std::fs::metadata(&file)
        .with_context(|| format!("Cannot inspect archive: {}", file.display()))?;
    anyhow::ensure!(
        metadata.is_file(),
        "Archive is not a regular file: {}",
        file.display()
    );
    std::fs::File::open(&file)
        .with_context(|| format!("Cannot read archive: {}", file.display()))?;
    Ok(file)
}

fn output_path(file: &Path) -> Result<PathBuf> {
    validate_extension(file)?;
    let file = std::path::absolute(file)?;
    let name = file
        .file_name()
        .context("Archive output must have a file name")?;
    let parent = file
        .parent()
        .context("Archive output must have a parent directory")?;
    // Canonicalize the parent through the filesystem: lexical removal of '..'
    // after a symlink can select a different destination.
    let parent = dunce::canonicalize(parent).with_context(|| {
        format!(
            "Cannot resolve archive output directory: {}",
            parent.display()
        )
    })?;
    anyhow::ensure!(
        parent.is_dir(),
        "Archive output parent is not a directory: {}",
        parent.display()
    );
    let file = parent.join(name);
    match std::fs::symlink_metadata(&file) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(file),
        Err(error) => {
            Err(error).with_context(|| format!("Cannot inspect archive output: {}", file.display()))
        }
        Ok(_) => anyhow::bail!("Archive output already exists: {}", file.display()),
    }
}
