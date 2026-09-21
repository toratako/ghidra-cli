use super::*;

#[test]
fn release_numbers_resolve_to_official_build_tags() {
    for (version, expected) in [
        (
            "11.0",
            "https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/tags/Ghidra_11.0_build",
        ),
        (
            "11.0.1",
            "https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/tags/Ghidra_11.0.1_build",
        ),
    ] {
        assert_eq!(release_api_url(Some(version)), expected);
    }
}

#[test]
fn omitted_release_number_resolves_to_latest() {
    assert_eq!(
        release_api_url(None),
        "https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest"
    );
}

fn fixture_archive(path: &Path, valid: bool) -> Result<()> {
    let mut archive = zip::ZipWriter::new(File::create(path)?);
    let name = if valid {
        if cfg!(windows) {
            "ghidra_test/support/analyzeHeadless.bat"
        } else {
            "ghidra_test/support/analyzeHeadless"
        }
    } else {
        "ghidra_test/incomplete"
    };
    archive.start_file(name, zip::write::SimpleFileOptions::default())?;
    archive.write_all(b"launcher")?;
    if valid {
        for (name, content) in [
            (
                "Ghidra/application.properties",
                "application.version=12.1.3\n",
            ),
            ("Ghidra/Framework/Utility/lib/Utility.jar", "runtime"),
            ("support/LaunchSupport.jar", "launcher runtime"),
        ] {
            archive.start_file(
                format!("ghidra_test/{name}"),
                zip::write::SimpleFileOptions::default(),
            )?;
            archive.write_all(content.as_bytes())?;
        }
    }
    archive.finish()?;
    Ok(())
}

#[test]
fn publication_rejects_invalid_archive_and_preserves_existing_tree() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let target = temp.path().join("install");
    let old = target.join("ghidra_test");
    std::fs::create_dir_all(&old)?;
    std::fs::write(old.join("keep"), "existing data")?;
    let archive = temp.path().join("bad.zip");
    fixture_archive(&archive, false)?;
    assert!(publish_archive(&archive, &target, true).is_err());
    assert_eq!(std::fs::read_to_string(old.join("keep"))?, "existing data");
    assert_eq!(std::fs::read_dir(&target)?.count(), 1);
    // A valid replacement still cannot overwrite an incomplete destination.
    fixture_archive(&archive, true)?;
    assert!(publish_archive(&archive, &target, true).is_err());
    assert_eq!(std::fs::read_to_string(old.join("keep"))?, "existing data");
    assert!(!old.join("support").exists());
    Ok(())
}

#[test]
fn concurrent_publication_reuses_existing_installation() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let archive = temp.path().join("valid.zip");
    fixture_archive(&archive, true)?;
    let target = temp.path().join("install");
    let workers: Vec<_> = (0..4)
        .map(|_| {
            let archive = archive.clone();
            let target = target.clone();
            std::thread::spawn(move || publish_archive(&archive, &target, true).unwrap())
        })
        .collect();
    let paths: Vec<_> = workers.into_iter().map(|w| w.join().unwrap()).collect();
    assert!(paths.iter().all(|p| p == &paths[0]));
    std::fs::write(paths[0].join("keep"), "existing data")?;
    assert_eq!(publish_archive(&archive, &target, true)?, paths[0]);
    assert_eq!(
        std::fs::read_to_string(paths[0].join("keep"))?,
        "existing data"
    );
    Ok(())
}

#[test]
fn relative_install_directory_returns_absolute_path() -> Result<()> {
    let temp = tempfile::tempdir_in(".")?;
    let relative = temp
        .path()
        .strip_prefix(std::env::current_dir()?)
        .unwrap_or(temp.path());
    assert!(relative.is_relative());
    let archive = relative.join("valid.zip");
    fixture_archive(&archive, true)?;
    let installed = publish_archive(&archive, &relative.join("install"), true)?;
    assert!(installed.is_absolute());
    assert_eq!(
        installed,
        dunce::canonicalize(relative.join("install/ghidra_test"))?
    );
    Ok(())
}

#[test]
fn test_extract_zip_preserves_root_and_contents() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let zip_path = temp.path().join("ghidra.zip");
    let mut archive = zip::ZipWriter::new(File::create(&zip_path)?);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(0o755);
    archive.start_file("ghidra_test/support/analyzeHeadless", options)?;
    archive.write_all(b"#!/bin/sh\n")?;
    archive.finish()?;

    let target = temp.path().join("install");
    let root = extract_zip(&zip_path, &target, true)?;
    assert_eq!(root, target.join("ghidra_test"));
    let script = root.join("support/analyzeHeadless");
    assert_eq!(std::fs::read(&script)?, b"#!/bin/sh\n");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(script)?.permissions().mode() & 0o777,
            0o755
        );
    }
    Ok(())
}

#[test]
fn test_extract_zip_preserves_language_freshness() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let zip_path = temp.path().join("ghidra.zip");
    let mut archive = zip::ZipWriter::new(File::create(&zip_path)?);
    let source_time = zip::DateTime::from_date_and_time(2026, 1, 2, 3, 4, 0)?;
    let compiled_time = zip::DateTime::from_date_and_time(2026, 1, 2, 3, 5, 0)?;
    let options = zip::write::SimpleFileOptions::default();
    // Archive order is independent of build order. The compiled language
    // can precede a source it includes, as x86-64.sla precedes x86.slaspec.
    archive.start_file(
        "ghidra_test/languages/x86-64.sla",
        options.last_modified_time(compiled_time),
    )?;
    archive.write_all(b"compiled language")?;
    archive.start_file(
        "ghidra_test/languages/x86.slaspec",
        options.last_modified_time(source_time),
    )?;
    archive.write_all(b"language source")?;
    archive.finish()?;

    let root = extract_zip(&zip_path, &temp.path().join("install"), true)?;
    let compiled = root.join("languages/x86-64.sla");
    let source = root.join("languages/x86.slaspec");
    let compiled_modified = compiled.metadata()?.modified()?;
    let source_modified = source.metadata()?.modified()?;
    assert!(compiled_modified > source_modified);
    let expected = chrono::NaiveDate::from_ymd_opt(2026, 1, 2)
        .unwrap()
        .and_hms_opt(3, 5, 0)
        .unwrap()
        .and_utc();
    assert_eq!(compiled_modified, std::time::SystemTime::from(expected));
    assert_eq!(std::fs::read(compiled)?, b"compiled language");
    assert_eq!(std::fs::read(source)?, b"language source");
    Ok(())
}

#[test]
fn test_ghidra_min_java_defaults() {
    // Unknown install dir falls back to the documented default floor.
    let min = crate::ghidra::java::ghidra_min_java(std::path::Path::new("/nonexistent"));
    assert_eq!(min, crate::ghidra::java::DEFAULT_MIN_JAVA);
}
