//! Per-executable prerequisite checks that retain failures and their diagnostics.

use std::sync::OnceLock;

/// Cache the actual diagnostic output, including failures, rather than poisoning
/// a Once after a panic. Every dependent test still fails with the same reason.
#[derive(Default)]
pub struct DoctorCheck(OnceLock<std::result::Result<std::process::Output, String>>);

impl DoctorCheck {
    pub fn require_with(
        &self,
        check: impl FnOnce() -> std::result::Result<std::process::Output, String>,
    ) {
        match self.0.get_or_init(check) {
            Ok(output) => assert_doctor_ready(output),
            Err(error) => panic!("Failed to run ghidra-cli doctor: {error}"),
        }
    }
}

/// The parent test process keeps its Ghidra/JDK configuration fixed. Tests that
/// change child environments or test doctor itself must invoke doctor directly.
pub fn require_ghidra() {
    static CHECK: DoctorCheck = DoctorCheck(OnceLock::new());
    CHECK.require_with(|| {
        let started = std::time::Instant::now();
        let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
            .arg("doctor")
            .output()
            .map_err(|error| error.to_string());
        eprintln!(
            "[test setup] doctor: {:.2}s",
            started.elapsed().as_secs_f64()
        );
        output
    });
}

#[macro_export]
macro_rules! require_ghidra {
    () => {
        $crate::common::require_ghidra();
    };
}

pub fn assert_doctor_ready(doctor: &std::process::Output) {
    let stdout = String::from_utf8_lossy(&doctor.stdout);
    let stderr = String::from_utf8_lossy(&doctor.stderr);
    assert!(
        doctor.status.success()
            && (stdout.contains("Headless launcher: OK (analyzeHeadless)")
                || stdout.contains("Headless launcher: OK (ghidra.JarRun)"))
            && stdout.contains("Checking bridge script compiles... OK"),
        "Ghidra not properly installed — tests MUST fail without Ghidra.\nStatus: {}\nstdout: {}\nstderr: {}",
        doctor.status, stdout, stderr
    );
}
