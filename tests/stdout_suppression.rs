//! Integration test: verify that suppress_output() actually silences
//! stdout produced by the library's output macros (`warning!`, `detail!`,
//! `output!`).  The test builds and runs the `stdout_check` example as a
//! subprocess so we can capture real stdout rather than just checking the
//! internal AtomicBool flag.

use std::path::PathBuf;
use std::process::Command;

/// Locate a compiled example binary by name.
fn example_binary(name: &str) -> PathBuf {
    let env_key = format!("CARGO_BIN_EXE_{name}");
    if let Ok(p) = std::env::var(&env_key) {
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
        .join(format!("{}{}", name, std::env::consts::EXE_SUFFIX))
}

/// Build an example by name if it hasn't been built yet.
fn ensure_example_built(name: &str) {
    let status = Command::new("cargo")
        .args(["build", "--example", name])
        .status()
        .expect("failed to run cargo build");
    assert!(status.success(), "cargo build --example {} failed", name);
}

#[test]
fn suppress_output_actually_silences_macro_output() {
    ensure_example_built("stdout_check");

    let bin = example_binary("stdout_check");
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

/// Fresh-process test: verify the library is silent by default.
/// The `default_silent` example does NOT call `enable_output()`,
/// so all macro output should be suppressed by the initialiser.
#[test]
fn default_silent_output_is_suppressed() {
    ensure_example_built("default_silent");

    let bin = example_binary("default_silent");
    assert!(
        bin.exists(),
        "example binary not found at {}; run `cargo build --example default_silent`",
        bin.display()
    );

    let output = Command::new(&bin)
        .output()
        .expect("failed to spawn default_silent example");

    assert!(
        output.status.success(),
        "example exited with {}: stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Default-silent markers must NOT appear — library is silent by default.
    assert!(
        !stdout.contains("DEFAULT_SILENT_WARNING"),
        "DEFAULT_SILENT_WARNING leaked into stdout (library should be silent by default):\n{}",
        stdout
    );
    assert!(
        !stdout.contains("DEFAULT_SILENT_DETAIL"),
        "DEFAULT_SILENT_DETAIL leaked into stdout:\n{}",
        stdout
    );
    assert!(
        !stdout.contains("DEFAULT_SILENT_OUTPUT"),
        "DEFAULT_SILENT_OUTPUT leaked into stdout:\n{}",
        stdout
    );
}
