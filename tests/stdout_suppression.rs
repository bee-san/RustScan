//! Integration test: verify that suppress_output() actually silences
//! stdout produced by the library's output macros (`warning!`, `detail!`,
//! `output!`).  The test builds and runs the `stdout_check` example as a
//! subprocess so we can capture real stdout rather than just checking the
//! internal AtomicBool flag.

use std::path::PathBuf;
use std::process::Command;

/// Build an example and return the path to the compiled binary.
///
/// Uses `cargo build --message-format=json` so that the profile matches
/// the test binary (`cfg!(debug_assertions)`) and the returned path
/// respects `CARGO_TARGET_DIR` and workspace layouts.
fn build_example(name: &str) -> PathBuf {
    let mut args: Vec<&str> = vec!["build", "--example", name, "--message-format=json"];
    if !cfg!(debug_assertions) {
        args.push("--release");
    }

    let output = Command::new("cargo")
        .args(&args)
        .output()
        .expect("failed to run cargo build");

    assert!(
        output.status.success(),
        "cargo build --example {} failed\nstderr:\n{}",
        name,
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let value: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };

        if value.get("reason").and_then(|v| v.as_str()) != Some("compiler-artifact") {
            continue;
        }

        if value
            .get("target")
            .and_then(|v| v.get("name"))
            .and_then(|v| v.as_str())
            != Some(name)
        {
            continue;
        }

        if let Some(executable) = value.get("executable").and_then(|v| v.as_str()) {
            let path = PathBuf::from(executable);
            assert!(
                path.exists(),
                "cargo-reported binary does not exist: {}",
                path.display()
            );
            return path;
        }
    }

    panic!(
        "could not find executable for example '{}' in cargo build output",
        name
    );
}

#[test]
fn suppress_output_actually_silences_macro_output() {
    let bin = build_example("stdout_check");

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
    let bin = build_example("default_silent");

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
