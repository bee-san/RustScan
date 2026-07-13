//! Integration test: verify that suppress_output() actually silences
//! stdout produced by the library's output macros (`warning!`, `detail!`,
//! `output!`).  The test builds and runs the `stdout_check` example as a
//! subprocess so we can capture real stdout rather than just checking the
//! internal AtomicBool flag.

use std::path::PathBuf;
use std::process::Command;

/// Locate the compiled `stdout_check` example binary.
fn example_binary() -> PathBuf {
    // Cargo sets CARGO_BIN_EXE_<name> for bin targets; examples may
    // also be available under this key depending on the Cargo version.
    if let Ok(p) = std::env::var("CARGO_BIN_EXE_stdout_check") {
        let path = PathBuf::from(p);
        if path.exists() {
            return path;
        }
    }

    let manifest =
        std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| env!("CARGO_MANIFEST_DIR").into());
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    PathBuf::from(manifest)
        .join("target")
        .join(profile)
        .join("examples")
        .join("stdout_check")
}

/// Build the example if it hasn't been built yet.
fn ensure_example_built() {
    let status = Command::new("cargo")
        .args(["build", "--example", "stdout_check"])
        .status()
        .expect("failed to run cargo build --example stdout_check");
    assert!(
        status.success(),
        "cargo build --example stdout_check failed"
    );
}

#[test]
fn suppress_output_actually_silences_macro_output() {
    ensure_example_built();

    let bin = example_binary();
    assert!(
        bin.exists(),
        "example binary not found at {}; run `cargo build --example stdout_check`",
        bin.display()
    );

    let output = Command::new(&bin)
        .output()
        .expect("failed to spawn stdout_check example");

    assert!(
        output.status.success(),
        "example exited with {}: stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Pre-suppression markers must be present.
    assert!(
        stdout.contains("PRE_SUPPRESS_WARNING"),
        "PRE_SUPPRESS_WARNING missing from stdout:\n{}",
        stdout
    );
    assert!(
        stdout.contains("PRE_SUPPRESS_DETAIL"),
        "PRE_SUPPRESS_DETAIL missing from stdout:\n{}",
        stdout
    );
    assert!(
        stdout.contains("PRE_SUPPRESS_OUTPUT"),
        "PRE_SUPPRESS_OUTPUT missing from stdout:\n{}",
        stdout
    );

    // Post-suppression markers must be absent.
    assert!(
        !stdout.contains("POST_SUPPRESS_WARNING"),
        "POST_SUPPRESS_WARNING leaked into stdout:\n{}",
        stdout
    );
    assert!(
        !stdout.contains("POST_SUPPRESS_DETAIL"),
        "POST_SUPPRESS_DETAIL leaked into stdout:\n{}",
        stdout
    );
    assert!(
        !stdout.contains("POST_SUPPRESS_OUTPUT"),
        "POST_SUPPRESS_OUTPUT leaked into stdout:\n{}",
        stdout
    );
}
