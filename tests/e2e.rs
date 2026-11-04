//! Version output checks that do not require Ghidra.

#[test]
fn version_flags_report_package_version() {
    for flag in ["--version", "-V"] {
        assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
            .arg(flag)
            .assert()
            .success()
            .stdout(concat!("ghidra-cli ", env!("CARGO_PKG_VERSION"), "\n"));
    }
}
