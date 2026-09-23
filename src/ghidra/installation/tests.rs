use super::*;

fn standalone_jar(path: &Path, manifest: &str, properties: &str, omit: Option<&str>) -> PathBuf {
    use std::io::Write;
    let file = fs::File::create(path).unwrap();
    let mut archive = zip::ZipWriter::new(file);
    for (name, text) in [
        ("META-INF/MANIFEST.MF", manifest),
        ("_Root/Ghidra/application.properties", properties),
        ("ghidra/JarRun.class", "class"),
        ("ghidra/GhidraJarApplicationLayout.class", "class"),
        ("ghidra/app/util/headless/AnalyzeHeadless.class", "class"),
        ("_Root/Ghidra/MODULE_LIST", "Ghidra/Features/Base\n"),
    ] {
        if omit == Some(name) {
            continue;
        }
        archive
            .start_file(name, zip::write::SimpleFileOptions::default())
            .unwrap();
        archive.write_all(text.as_bytes()).unwrap();
    }
    archive.finish().unwrap();
    dunce::canonicalize(path).unwrap()
}

fn jar(path: &Path) -> PathBuf {
    standalone_jar(
        path,
        "Manifest-Version: 1.0\r\nMain-Class: ghidra.JarRun\r\n\r\n",
        "application.version=12.1.4\napplication.java.min=21\n",
        None,
    )
}

#[test]
fn jar_metadata_uses_official_layout_and_manifest_continuations() {
    let temp = tempfile::tempdir().unwrap();
    let path = standalone_jar(
        &temp.path().join("ghidra space's.jar"),
        "Manifest-Version: 1.0\r\nmain-class: ghidra.\r\n JarRun\r\n\r\nName: ignored\r\nMain-Class: unrelated\r\n",
        "application.version = 12.1.4\napplication.java.min = 25\n",
        None,
    );
    let selected = inspect(&path, InstallationKind::Jar).unwrap();
    assert_eq!(selected.path, path);
    assert_eq!(selected.kind, InstallationKind::Jar);
    assert_eq!(selected.version, "12.1.4");
    assert_eq!(selected.min_java, 25);
    assert_eq!(selected.launcher(), None);
    assert_eq!(serde_json::to_value(selected).unwrap()["kind"], "jar");
}

#[test]
fn jar_selection_rejects_plus_in_canonical_path_only() {
    let temp = tempfile::tempdir().unwrap();
    let directory = distribution(&temp.path().join("jar+path"), Platform::native(), "12.1");
    let archive = jar(&directory.join("ghidra.jar"));
    let alias = temp.path().join("alias.jar");
    link_file(&archive, &alias);
    for path in [&archive, &alias] {
        let error = resolve_inputs(Inputs {
            configured_jar: Some(path.clone()),
            ..inputs()
        })
        .unwrap_err();
        assert_eq!(status(&error), "invalid");
        assert!(error
            .to_string()
            .contains("move the JAR to a path without '+'"));
    }
    // Directory distributions do not use Ghidra's JAR URL decoding.
    assert!(inspect(&directory, InstallationKind::Directory).is_ok());
    let safe_archive = jar(&temp.path().join("safe.jar"));
    let plus_alias = temp.path().join("safe+alias.jar");
    link_file(&safe_archive, &plus_alias);
    assert_eq!(
        inspect(&plus_alias, InstallationKind::Jar).unwrap().path,
        safe_archive
    );
}

#[test]
fn metadata_requires_version_and_preserves_java_requirement_fallback() {
    let temp = tempfile::tempdir().unwrap();
    let directory = distribution(&temp.path().join("directory"), Platform::native(), "12.1");
    for properties in [
        "application.version=12.1.4\n",
        "application.version=12.1.4\napplication.java.min=invalid\n",
        "application.java.min=21\n",
    ] {
        fs::write(directory.join("Ghidra/application.properties"), properties).unwrap();
        let archive = standalone_jar(
            &temp.path().join("ghidra.jar"),
            "Main-Class: ghidra.JarRun\n\n",
            properties,
            None,
        );
        for (path, kind) in [
            (&directory, InstallationKind::Directory),
            (&archive, InstallationKind::Jar),
        ] {
            let selected = inspect(path, kind);
            if properties.starts_with("application.version=") {
                assert_eq!(selected.unwrap().min_java, DEFAULT_MIN_JAVA);
            } else {
                assert!(selected
                    .unwrap_err()
                    .to_string()
                    .contains("Missing application.version"));
            }
        }
    }
}

#[test]
fn jar_selection_replaces_the_entire_lower_priority_layer() {
    let temp = tempfile::tempdir().unwrap();
    let directory = distribution(
        &temp.path().join("distribution"),
        Platform::native(),
        "12.1",
    );
    let archive = jar(&temp.path().join("ghidra.jar"));
    let selected = resolve_inputs(Inputs {
        environment_jar: Some(archive.clone().into_os_string()),
        configured: Some(directory.clone()),
        configured_jar: Some(temp.path().join("missing.jar")),
        ..inputs()
    })
    .unwrap();
    assert_eq!(selected.path, archive);
    assert_eq!(selected.source, "GHIDRA_JAR");
    let selected = resolve_inputs(Inputs {
        environment: Some(directory.clone().into_os_string()),
        configured_jar: Some(archive.clone()),
        ..inputs()
    })
    .unwrap();
    assert_eq!(selected.path, directory);
    let selected = resolve_inputs(Inputs {
        configured_jar: Some(archive.clone()),
        path: directory.join("support").into_os_string(),
        ..inputs()
    })
    .unwrap();
    assert_eq!(selected.path, archive);
    assert_eq!(selected.source, "config ghidra_jar");
}

#[test]
fn conflicting_effective_selections_fail_before_path_validation() {
    for environment in [true, false] {
        let mut options = inputs();
        if environment {
            options.environment = Some("missing-directory".into());
            options.environment_jar = Some("missing.jar".into());
        } else {
            options.configured = Some("missing-directory".into());
            options.configured_jar = Some("missing.jar".into());
        }
        let error = resolve_inputs(options).unwrap_err();
        assert_eq!(status(&error), "invalid");
        assert!(error.to_string().contains("both select Ghidra"));
    }
}

#[test]
fn invalid_jar_selection_never_falls_back() {
    let temp = tempfile::tempdir().unwrap();
    let directory = distribution(
        &temp.path().join("distribution"),
        Platform::native(),
        "12.1",
    );
    let invalid = temp.path().join("invalid.jar");
    fs::write(&invalid, "not a jar").unwrap();
    for environment in [true, false] {
        for path in [
            PathBuf::new(),
            temp.path().join("missing.jar"),
            invalid.clone(),
            directory.clone(),
        ] {
            let mut options = inputs();
            options.path = directory.join("support").into_os_string();
            if environment {
                options.environment_jar = Some(path.into_os_string());
                options.configured = Some(directory.clone());
            } else {
                options.configured_jar = Some(path);
            }
            assert_eq!(status(&resolve_inputs(options).unwrap_err()), "invalid");
        }
    }
}

#[test]
fn jar_validation_rejects_missing_entrypoints_and_inapplicable_manifests() {
    let temp = tempfile::tempdir().unwrap();
    for (manifest, omit, expected) in [
        ("Main-Class: unrelated\n\n", None, "Main-Class"),
        (
            "Manifest-Version: 1.0\n\nName: section\nMain-Class: ghidra.JarRun\n",
            None,
            "Main-Class",
        ),
        (
            "Main-Class: ghidra.JarRun\n\n",
            Some("ghidra/app/util/headless/AnalyzeHeadless.class"),
            "AnalyzeHeadless.class",
        ),
        (
            "Main-Class: ghidra.JarRun\n\n",
            Some("_Root/Ghidra/application.properties"),
            "application.properties",
        ),
    ] {
        let path = standalone_jar(
            &temp.path().join("ghidra.jar"),
            manifest,
            "application.version=12.1.4\n",
            omit,
        );
        assert!(inspect(&path, InstallationKind::Jar)
            .unwrap_err()
            .to_string()
            .contains(expected));
    }
}

#[test]
fn jars_are_not_automatically_discovered() {
    let temp = tempfile::tempdir().unwrap();
    jar(&temp.path().join("ghidra.jar"));
    let options = Inputs {
        path: temp.path().as_os_str().to_owned(),
        ..inputs()
    };
    assert_eq!(status(&resolve_inputs(options).unwrap_err()), "not_found");
    let directory = distribution(temp.path(), Platform::native(), "12.1");
    let selected = resolve_inputs(Inputs {
        roots: vec![SearchRoot::exact(directory.clone(), "package")],
        ..inputs()
    })
    .unwrap();
    assert_eq!(selected.kind, InstallationKind::Directory);
    assert_eq!(selected.path, directory);
    assert_eq!(selected.min_java, DEFAULT_MIN_JAVA);
    assert!(selected.launcher().unwrap().is_file());
}

fn distribution(path: &Path, platform: Platform, version: &str) -> PathBuf {
    for (name, content) in [
        (
            format!("support/{}", platform.launcher()),
            "launcher".to_owned(),
        ),
        (
            "Ghidra/application.properties".into(),
            format!("application.version={version}\napplication.release.name=DEV\n"),
        ),
        (
            "Ghidra/Framework/Utility/lib/Utility.jar".into(),
            "runtime".into(),
        ),
        (
            "support/LaunchSupport.jar".into(),
            "launcher runtime".into(),
        ),
    ] {
        let file = path.join(name);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(file, content).unwrap();
    }
    dunce::canonicalize(path).unwrap()
}

fn inputs() -> Inputs {
    Inputs {
        platform: Platform::native(),
        environment: None,
        environment_jar: None,
        configured: None,
        configured_jar: None,
        path: OsString::new(),
        roots: Vec::new(),
    }
}

fn status(error: &GhidraError) -> &str {
    match error {
        GhidraError::Installation(e) => e.status,
        _ => panic!("unexpected error: {error}"),
    }
}

fn link_file(target: &Path, link: &Path) {
    #[cfg(unix)]
    std::os::unix::fs::symlink(target, link).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(target, link).unwrap();
}

#[test]
fn explicit_selection_precedes_path_and_packages() {
    let temp = tempfile::tempdir().unwrap();
    let platform = Platform::native();
    let environment = distribution(&temp.path().join("environment"), platform, "11.4");
    let config = distribution(&temp.path().join("config"), platform, "12.1");
    let path = distribution(&temp.path().join("path"), platform, "12.2");
    let package = distribution(&temp.path().join("package"), platform, "13.0");
    let options = || Inputs {
        environment: None,
        environment_jar: None,
        configured: Some(config.clone()),
        configured_jar: None,
        path: path.join("support").into_os_string(),
        roots: vec![SearchRoot::exact(&package, "package")],
        platform,
    };
    let mut first = options();
    first.environment = Some(environment.clone().into_os_string());
    let selected = resolve_inputs(first).unwrap();
    assert_eq!(selected.path, environment);
    assert_eq!(selected.source, "GHIDRA_INSTALL_DIR");
    assert_eq!(resolve_inputs(options()).unwrap().path, config);
    let mut without_config = options();
    without_config.configured = None;
    assert_eq!(resolve_inputs(without_config).unwrap().path, path);
}

#[test]
fn invalid_explicit_paths_never_fall_back_and_retain_io_details() {
    let temp = tempfile::tempdir().unwrap();
    let good = distribution(&temp.path().join("good"), Platform::native(), "12.1");
    for configured in [false, true] {
        for path in [PathBuf::new(), temp.path().join("missing")] {
            let mut options = inputs();
            options.path = good.join("support").into_os_string();
            if configured {
                options.configured = Some(path.clone());
            } else {
                options.environment = Some(path.clone().into_os_string());
                options.configured = Some(good.clone());
            }
            let error = resolve_inputs(options).unwrap_err();
            assert_eq!(status(&error), "invalid");
            let detail = crate::error::diagnostic_detail(&error.into());
            assert_eq!(
                detail["installation"]["checked"][0]["path"],
                serde_json::json!(path)
            );
            if !path.as_os_str().is_empty() {
                assert_eq!(detail["io_kind"], "not_found");
                assert_eq!(detail["stage"], "installation.inspect");
            }
        }
    }
}

#[test]
fn path_order_skips_broken_candidates_and_keeps_selected_version() {
    let temp = tempfile::tempdir().unwrap();
    let platform = Platform::native();
    let bad = temp.path().join("broken/support");
    fs::create_dir_all(&bad).unwrap();
    fs::write(bad.join(platform.launcher()), "incomplete").unwrap();
    let old = distribution(&temp.path().join("old"), platform, "11.4");
    let new = distribution(&temp.path().join("new"), platform, "12.1");
    let mut options = inputs();
    options.path = std::env::join_paths([
        PathBuf::new(),
        PathBuf::from("relative"),
        bad,
        old.join("support"),
        new.join("support"),
    ])
    .unwrap();
    let selected = resolve_inputs(options).unwrap();
    assert_eq!(selected.path, old);
    assert_eq!(selected.version, "11.4");
    assert!(selected.source.starts_with("PATH "));
}

#[test]
fn package_candidates_are_validated_and_reported_without_version_selection() {
    let temp = tempfile::tempdir().unwrap();
    let platform = Platform::native();
    let old = distribution(&temp.path().join("old"), platform, "11.9");
    let new = distribution(&temp.path().join("new"), platform, "12.1");
    let mut options = inputs();
    options.roots = vec![
        SearchRoot::exact(temp.path().join("broken"), "broken"),
        SearchRoot::exact(&old, "first"),
        SearchRoot::exact(&new, "second"),
    ];
    let error = resolve_inputs(options).unwrap_err();
    assert_eq!(status(&error), "ambiguous");
    let GhidraError::Installation(e) = error else {
        unreachable!()
    };
    assert_eq!(e.candidates.len(), 2);
    assert_eq!(e.checked.len(), 1);
    let message = e.to_string();
    assert!(message.contains("11.9") && message.contains("12.1") && message.contains("config set"));
}

#[test]
fn path_links_deduplicate_and_conflicts_in_one_directory_are_ambiguous() {
    let temp = tempfile::tempdir().unwrap();
    let platform = Platform::native();
    let first = distribution(&temp.path().join("first"), platform, "12.1");
    let second = distribution(&temp.path().join("second"), platform, "11.4");
    let bin = temp.path().join("bin");
    fs::create_dir(&bin).unwrap();
    let names = platform.commands();
    link_file(
        &first.join("support").join(platform.launcher()),
        &bin.join(names[0]),
    );
    link_file(
        &first.join("support").join(platform.launcher()),
        &bin.join(names[1]),
    );
    let options = || Inputs {
        path: bin.clone().into_os_string(),
        ..inputs()
    };
    assert_eq!(resolve_inputs(options()).unwrap().path, first);
    fs::remove_file(bin.join(names[1])).unwrap();
    link_file(
        &second.join("support").join(platform.launcher()),
        &bin.join(names[1]),
    );
    assert_eq!(status(&resolve_inputs(options()).unwrap_err()), "ambiguous");
}

#[cfg(unix)]
#[test]
fn homebrew_wrapper_is_resolved_without_running_it() {
    let temp = tempfile::tempdir().unwrap();
    let keg = temp.path().join("custom brew/Cellar/ghidra/12.1");
    let root = distribution(&keg.join("libexec"), Platform::native(), "12.1");
    fs::create_dir_all(keg.join("bin")).unwrap();
    fs::write(keg.join("bin/ghidraRun"), "#!/bin/sh\nexit 99\n").unwrap();
    let bin = temp.path().join("bin");
    fs::create_dir(&bin).unwrap();
    link_file(&keg.join("bin/ghidraRun"), &bin.join("ghidraRun"));
    assert_eq!(
        resolve_inputs(Inputs {
            path: bin.into_os_string(),
            ..inputs()
        })
        .unwrap()
        .path,
        root
    );
}

#[cfg(unix)]
#[test]
fn nix_headless_symlink_and_broken_symlink_are_handled() {
    let temp = tempfile::tempdir().unwrap();
    let root = distribution(
        &temp.path().join("store/hash-ghidra/lib/ghidra"),
        Platform::native(),
        "12.1",
    );
    let bin = temp.path().join("profile/bin");
    fs::create_dir_all(&bin).unwrap();
    link_file(&temp.path().join("missing"), &bin.join("ghidra"));
    link_file(
        &root.join("support/analyzeHeadless"),
        &bin.join("ghidra-analyzeHeadless"),
    );
    assert_eq!(
        resolve_inputs(Inputs {
            path: bin.into_os_string(),
            ..inputs()
        })
        .unwrap()
        .path,
        root
    );
}

#[test]
fn platform_package_layouts_work_in_relocated_filesystem() {
    let temp = tempfile::tempdir().unwrap();
    for platform in [Platform::Linux, Platform::Mac, Platform::Windows] {
        // Relocate production roots without consulting the actual filesystem.
        // Exercise each source independently so another installed package cannot
        // make a broken layout test pass.
        for (n, mut root) in package_roots(
            platform,
            Some(temp.path().join("custom brew")),
            Some(temp.path().join("home")),
        )
        .into_iter()
        .enumerate()
        {
            root.path = temp
                .path()
                .join(format!("layout-{n}-{}", platform.launcher()));
            let installed = if let Some(prefix) = root.child_prefix {
                root.path.join(format!("{prefix}12.1"))
            } else {
                root.path.clone()
            };
            let expected = distribution(&installed, platform, "12.1");
            assert_eq!(
                resolve_inputs(Inputs {
                    platform,
                    roots: vec![root],
                    ..inputs()
                })
                .unwrap()
                .path,
                expected
            );
            fs::remove_dir_all(
                temp.path()
                    .join(format!("layout-{n}-{}", platform.launcher())),
            )
            .unwrap();
        }
    }
}

#[test]
fn macports_versions_are_ambiguous_and_not_recursively_searched() {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path().join("share/java");
    let mut root = package_roots(Platform::Mac, None, None).remove(0);
    root.path = base.clone();
    distribution(&base.join("nested/ghidra-12.1"), Platform::Mac, "12.1");
    let error = resolve_inputs(Inputs {
        platform: Platform::Mac,
        roots: vec![root],
        ..inputs()
    })
    .unwrap_err();
    assert_eq!(status(&error), "not_found");
    distribution(&base.join("ghidra-11.4"), Platform::Mac, "11.4");
    distribution(&base.join("ghidra-12.1"), Platform::Mac, "12.1");
    let mut root = package_roots(Platform::Mac, None, None).remove(0);
    root.path = base;
    assert_eq!(
        status(
            &resolve_inputs(Inputs {
                platform: Platform::Mac,
                roots: vec![root],
                ..inputs()
            })
            .unwrap_err()
        ),
        "ambiguous"
    );
}

#[test]
fn incomplete_distributions_and_non_files_fail_shared_validation() {
    let temp = tempfile::tempdir().unwrap();
    let platform = Platform::native();
    for missing in [
        "Ghidra/application.properties",
        "Ghidra/Framework/Utility/lib/Utility.jar",
        "support/LaunchSupport.jar",
    ] {
        let path = distribution(&temp.path().join("root"), platform, "12.1");
        fs::remove_file(path.join(missing)).unwrap();
        assert!(inspect(&path, InstallationKind::Directory)
            .unwrap_err()
            .to_string()
            .contains(missing.rsplit('/').next().unwrap()));
    }
    let path = distribution(&temp.path().join("root"), platform, "12.1");
    let launcher = path.join("support").join(platform.launcher());
    fs::remove_file(&launcher).unwrap();
    fs::create_dir(&launcher).unwrap();
    assert!(inspect(&path, InstallationKind::Directory)
        .unwrap_err()
        .to_string()
        .contains("Expected an installation file"));
}

#[test]
fn duplicate_roots_and_dot_aliases_do_not_create_ambiguity() {
    let temp = tempfile::tempdir().unwrap();
    let root = distribution(
        &temp.path().join("Ghidra space's"),
        Platform::native(),
        "12.1",
    );
    let roots = vec![
        SearchRoot::exact(&root, "first"),
        SearchRoot::exact(root.join("."), "alias"),
    ];
    assert_eq!(
        resolve_inputs(Inputs { roots, ..inputs() }).unwrap().path,
        root
    );
}

#[cfg(unix)]
#[test]
fn explicit_os_paths_preserve_backslashes() {
    let temp = tempfile::tempdir().unwrap();
    let root = distribution(
        &temp.path().join(r"Ghidra \ path"),
        Platform::native(),
        "12.1",
    );
    let selected = resolve_inputs(Inputs {
        environment: Some(root.clone().into_os_string()),
        ..inputs()
    })
    .unwrap();
    assert_eq!(selected.path, root);
}

// APFS rejects invalid UTF-8 filenames, so creating this fixture requires Linux.
#[cfg(target_os = "linux")]
#[test]
fn explicit_os_paths_preserve_non_utf8() {
    use std::os::unix::ffi::OsStringExt;
    let temp = tempfile::tempdir().unwrap();
    let root = distribution(
        &temp
            .path()
            .join(OsString::from_vec(b"Ghidra \xff".to_vec())),
        Platform::native(),
        "12.1",
    );
    let selected = resolve_inputs(Inputs {
        environment: Some(root.clone().into_os_string()),
        ..inputs()
    })
    .unwrap();
    assert_eq!(selected.path, root);
    let error = resolve_inputs(Inputs {
        environment: Some(root.join("missing").into_os_string()),
        ..inputs()
    })
    .unwrap_err();
    assert_eq!(
        crate::error::diagnostic_detail(&error.into())["installation"]["status"],
        "invalid"
    );
}

#[cfg(unix)]
#[test]
fn non_utf8_paths_serialize_without_filesystem_access() {
    use std::os::unix::ffi::OsStringExt;
    let installation = Installation {
        path: OsString::from_vec(b"Ghidra \xff".to_vec()).into(),
        kind: InstallationKind::Directory,
        min_java: DEFAULT_MIN_JAVA,
        version: "12.1".into(),
        source: "GHIDRA_INSTALL_DIR".into(),
    };
    let checked = CheckedPath {
        path: installation.path.clone(),
        source: installation.source.clone(),
        message: "Invalid installation".into(),
    };
    for value in [
        serde_json::to_value(&installation).unwrap(),
        serde_json::to_value(&checked).unwrap(),
    ] {
        assert_eq!(value["path"], "Ghidra \u{fffd}");
    }
}

#[test]
fn failed_detection_distinguishes_absent_and_incomplete_installations() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("installation");
    let options = || Inputs {
        roots: vec![SearchRoot::exact(&root, "package")],
        ..inputs()
    };
    assert_eq!(status(&resolve_inputs(options()).unwrap_err()), "not_found");
    fs::create_dir(&root).unwrap();
    assert_eq!(status(&resolve_inputs(options()).unwrap_err()), "invalid");
}

#[test]
fn relative_path_entries_cannot_select_a_distribution() {
    let temp = tempfile::tempdir_in(".").unwrap();
    distribution(temp.path(), Platform::native(), "12.1");
    let relative = Path::new(temp.path().file_name().unwrap()).join("support");
    let options = Inputs {
        path: relative.into_os_string(),
        ..inputs()
    };
    assert_eq!(status(&resolve_inputs(options).unwrap_err()), "not_found");
}

#[cfg(unix)]
#[test]
fn custom_homebrew_prefix_uses_opt_link_and_deduplicates_aliases() {
    let temp = tempfile::tempdir().unwrap();
    let prefix = temp.path().join("brew prefix");
    let keg = prefix.join("Cellar/ghidra/12.1");
    let installed = distribution(&keg.join("libexec"), Platform::native(), "12.1");
    distribution(
        &prefix.join("Cellar/ghidra/11.4/libexec"),
        Platform::native(),
        "11.4",
    );
    fs::create_dir_all(prefix.join("opt")).unwrap();
    std::os::unix::fs::symlink(&keg, prefix.join("opt/ghidra")).unwrap();
    let mut roots: Vec<_> = package_roots(Platform::native(), Some(prefix), None)
        .into_iter()
        .filter(|r| r.path.starts_with(temp.path()))
        .collect();
    roots.push(SearchRoot::exact(&installed, "same keg"));
    assert_eq!(
        resolve_inputs(Inputs { roots, ..inputs() }).unwrap().path,
        installed
    );
}

#[cfg(windows)]
#[test]
fn windows_case_aliases_do_not_create_distinct_candidates() {
    let temp = tempfile::tempdir().unwrap();
    let installed = distribution(
        &temp.path().join("Ghidra space's"),
        Platform::Windows,
        "12.1",
    );
    let alias = PathBuf::from(installed.to_str().unwrap().to_uppercase());
    let roots = vec![
        SearchRoot::exact(&installed, "original"),
        SearchRoot::exact(alias, "case alias"),
    ];
    assert_eq!(
        resolve_inputs(Inputs { roots, ..inputs() }).unwrap().path,
        installed
    );
}
