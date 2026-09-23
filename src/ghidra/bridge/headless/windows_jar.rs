//! The Windows Java launcher converts native argv to the active ANSI code page.
//! Use ASCII entry-point operands and decode headless arguments inside Java.

use super::sources;
use anyhow::{Context, Result};
use std::ffi::OsString;
use std::fmt::Write as _;
use std::io::{Cursor, Write as _};
use std::path::Path;
use std::process::Command;

#[cfg(windows)]
pub(super) fn configure(command: &mut Command, jar: &Path, arguments: &[OsString]) -> Result<()> {
    configure_in(
        command,
        jar,
        arguments,
        &sources::root_path()?.join("jar-launchers"),
    )
}

fn configure_in(
    command: &mut Command,
    jar: &Path,
    arguments: &[OsString],
    root: &Path,
) -> Result<()> {
    let arguments: Vec<_> = arguments
        .iter()
        .map(|value| {
            value
                .to_str()
                .context("Ghidra launch argument is not valid Unicode")
        })
        .collect::<Result<_>>()?;
    let jar = std::path::absolute(jar)?;
    let path = jar
        .to_str()
        .context("Ghidra JAR path is not valid Unicode")?;
    #[cfg(windows)]
    let path = path.replace('\\', "/");
    #[cfg(windows)]
    let path = path.as_str();
    let classpath = classpath_jar(&file_url(path))?;
    // The system classloader may keep the classpath JAR open until JVM exit.
    // Publish immutable cached resources, as for the bridge source bundle.
    let directory = sources::install_files(
        root,
        &[
            ("classpath.jar", &classpath),
            (
                "GhidraCliJarLauncher.java",
                sources::JAR_LAUNCHER.as_bytes(),
            ),
        ],
    )?;
    command
        .current_dir(directory)
        .args(["-cp", "classpath.jar", "GhidraCliJarLauncher.java"])
        .env(
            "GHIDRA_CLI_JAR_ARGUMENTS",
            serde_json::to_string(&arguments)?,
        );
    Ok(())
}

fn file_url(path: &str) -> String {
    // dunce retains verbatim prefixes for UNC and long disk paths. Java file
    // URLs use the ordinary drive/UNC spelling, without Win32's device prefix.
    let unc;
    let path = if let Some(server_path) = path.strip_prefix("//?/UNC/") {
        unc = format!("//{server_path}");
        unc.as_str()
    } else {
        path.strip_prefix("//?/").unwrap_or(path)
    };
    // Absolute drive paths need an extra slash. Slash-prefixed paths include
    // UNC paths: file:////server/share is Java's empty-authority UNC form.
    let mut url = if path.starts_with('/') {
        "file://"
    } else {
        "file:///"
    }
    .to_owned();
    for byte in path.bytes() {
        if byte.is_ascii_alphanumeric() || b"/-._~:".contains(&byte) {
            url.push(char::from(byte));
        } else {
            write!(&mut url, "%{byte:02X}").unwrap();
        }
    }
    url
}

fn classpath_jar(url: &str) -> Result<Vec<u8>> {
    let mut manifest = String::from("Manifest-Version: 1.0\r\n");
    // URLs contain only ASCII. Fold the manifest within its 72-byte line limit.
    for (index, chunk) in format!("Class-Path: {url}")
        .as_bytes()
        .chunks(70)
        .enumerate()
    {
        if index != 0 {
            manifest.push(' ');
        }
        manifest.push_str(std::str::from_utf8(chunk)?);
        manifest.push_str("\r\n");
    }
    manifest.push_str("\r\n");
    let mut archive = zip::ZipWriter::new(Cursor::new(Vec::new()));
    archive.start_file(
        "META-INF/MANIFEST.MF",
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored),
    )?;
    archive.write_all(manifest.as_bytes())?;
    Ok(archive.finish()?.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn manifest_preserves_drive_and_unc_paths_as_folded_file_urls() {
        for (path, prefix) in [
            ("C:/runtime's #日本語/ghidra.jar", "file:///C:/"),
            ("//server/share's #日本語/ghidra.jar", "file:////server/"),
            ("//?/C:/runtime's #日本語/ghidra.jar", "file:///C:/"),
            (
                "//?/UNC/server/share's #日本語/ghidra.jar",
                "file:////server/",
            ),
        ] {
            let url = file_url(path);
            assert!(url.starts_with(prefix));
            assert!(url.contains("%27s%20%23%E6%97%A5%E6%9C%AC%E8%AA%9E/"));
            let mut archive =
                zip::ZipArchive::new(Cursor::new(classpath_jar(&url).unwrap())).unwrap();
            let mut manifest = String::new();
            archive
                .by_name("META-INF/MANIFEST.MF")
                .unwrap()
                .read_to_string(&mut manifest)
                .unwrap();
            assert!(manifest.lines().all(|line| line.len() <= 72));
            assert!(manifest
                .replace("\r\n ", "")
                .contains(&format!("Class-Path: {url}\r\n\r\n")));
        }
    }

    #[test]
    fn native_arguments_are_ascii_and_payload_retains_unicode_and_empty_values() {
        let root = tempfile::tempdir().unwrap();
        let jar = root.path().join("ghidra 日本語.jar");
        let arguments: Vec<OsString> = ["project 日本語", "quote'\"\\\n\t", ""]
            .into_iter()
            .map(Into::into)
            .collect();
        let mut command = Command::new("java");
        configure_in(&mut command, &jar, &arguments, root.path()).unwrap();
        assert!(command
            .get_args()
            .all(|value| value.to_str().unwrap().is_ascii()));
        let encoded = command
            .get_envs()
            .find(|(key, _)| *key == "GHIDRA_CLI_JAR_ARGUMENTS")
            .unwrap()
            .1
            .unwrap();
        let decoded: Vec<String> = serde_json::from_str(encoded.to_str().unwrap()).unwrap();
        assert_eq!(
            decoded.iter().map(OsString::from).collect::<Vec<_>>(),
            arguments
        );
        let directory = command.get_current_dir().unwrap().to_owned();
        assert!(directory.join("classpath.jar").is_file());
        assert_eq!(
            std::fs::read_to_string(directory.join("GhidraCliJarLauncher.java")).unwrap(),
            sources::JAR_LAUNCHER
        );
        let mut second = Command::new("java");
        configure_in(&mut second, &jar, &[], root.path()).unwrap();
        assert_eq!(second.get_current_dir(), Some(directory.as_path()));
    }
}
