//! Validation and loader argument construction shared by preflight and execution.

use crate::cli::ImportArgs;
use crate::ghidra::bridge;

pub(in crate::app) fn validate_options(args: &ImportArgs) -> anyhow::Result<()> {
    build_oneshot_import_options(args).map(|_| ())
}

pub(super) fn build_oneshot_import_options(
    args: &ImportArgs,
) -> anyhow::Result<(bridge::OneShotImportOptions, bool)> {
    if let Some(name) = &args.name {
        anyhow::ensure!(
            !name.trim().is_empty() && name != "." && name != ".." && !name.contains(['/', '\\']),
            "--name must be a single non-empty file name"
        );
    }
    anyhow::ensure!(
        args.compiler_spec.is_none() || args.language.is_some(),
        "--compiler-spec requires --language"
    );
    let binary_loader_fields = args.base_address.is_some()
        || args.block_name.is_some()
        || args.file_offset.is_some()
        || args.length.is_some();

    if binary_loader_fields
        && args.loader.as_deref().is_some_and(|loader| {
            !matches!(
                loader,
                "BinaryLoader" | "ghidra.app.util.opinion.BinaryLoader"
            )
        })
    {
        anyhow::bail!(
            "--base-address/--block-name/--file-offset/--length are BinaryLoader options"
        );
    }

    let loader = args
        .loader
        .clone()
        .or_else(|| binary_loader_fields.then(|| "BinaryLoader".to_string()));

    let mut loader_options: Vec<(String, String)> = Vec::new();
    if let Some(value) = &args.base_address {
        loader_options.push(("baseAddr".to_string(), value.clone()));
    }
    if let Some(value) = &args.block_name {
        loader_options.push(("blockName".to_string(), value.clone()));
    }
    for (flag, name, value) in [
        ("--file-offset", "fileOffset", &args.file_offset),
        ("--length", "length", &args.length),
    ] {
        if let Some(value) = value {
            let count = crate::cli::numeric::ranged::<i64>(value, 0, i64::MAX as i128)
                .map_err(|reason| anyhow::anyhow!("Invalid {flag} '{value}': {reason}"))?;
            // BinaryLoader uses HexLong options, whose native parser treats
            // even unprefixed digits as hexadecimal.
            loader_options.push((name.to_string(), format!("0x{count:x}")));
        }
    }

    anyhow::ensure!(
        args.loader_options.len().is_multiple_of(2),
        "--loader-option requires NAME VALUE"
    );
    for [name, value] in args.loader_options.as_chunks::<2>().0 {
        if name.is_empty()
            || !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            anyhow::bail!(
                "Invalid loader option name '{}': use only letters, digits, '-' or '_'",
                name
            );
        }
        if value.is_empty() {
            anyhow::bail!(
                "Invalid --loader-option '{}': value must not be empty",
                name
            );
        }
        loader_options.push((name.to_string(), value.to_string()));
    }

    for (name, value) in &loader_options {
        if name.eq_ignore_ascii_case("baseAddr") {
            anyhow::ensure!(
                crate::address::ExplicitAddress::parse(value).is_some(),
                "Invalid base address '{}': use a 0x-prefixed address",
                value
            );
        }
    }

    let explicit_loader_control = loader.is_some()
        || args.language.is_some()
        || args.compiler_spec.is_some()
        || !loader_options.is_empty();

    Ok((
        bridge::OneShotImportOptions {
            analyze: !args.no_analyze,
            program: args.name.clone(),
            loader,
            language: args.language.clone(),
            compiler_spec: args.compiler_spec.clone(),
            loader_options,
        },
        explicit_loader_control,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_loader_counts_are_normalized_without_reinterpreting_extra_arguments() {
        use clap::Parser;
        let cli = crate::cli::Cli::try_parse_from([
            "ghidra-cli",
            "program",
            "import",
            "sample.bin",
            "--file-offset",
            "010",
            "--length",
            "0x40",
            "--loader-option",
            "blockName",
            "010",
        ])
        .unwrap();
        let crate::cli::Commands::Program(crate::cli::ProgramCommands::Import(args)) = cli.command
        else {
            panic!("expected program import");
        };
        let (options, explicit) = build_oneshot_import_options(&args).unwrap();
        assert!(explicit);
        assert_eq!(options.loader.as_deref(), Some("BinaryLoader"));
        assert_eq!(
            options.loader_options,
            [
                ("fileOffset".to_string(), "0xa".to_string()),
                ("length".to_string(), "0x40".to_string()),
                ("blockName".to_string(), "010".to_string()),
            ]
        );
    }
}
