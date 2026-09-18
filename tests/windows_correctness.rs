#![cfg(windows)]

//! Native Windows integration tests for RustScan CLI correctness.
//!
//! These tests intentionally execute the compiled `rustscan.exe` rather than
//! calling internal functions. They verify the complete path through Clap
//! parsing, configuration merging, platform validation, and scanner startup.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

fn rustscan_executable() -> &'static str {
    env!("CARGO_BIN_EXE_rustscan")
}

fn unique_temp_path(name: &str) -> PathBuf {
    let counter = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);

    std::env::temp_dir().join(format!(
        "rustscan-windows-correctness-{}-{counter}-{name}",
        std::process::id()
    ))
}

fn nonexistent_config_path() -> PathBuf {
    let path = unique_temp_path("missing-config.toml");

    // The path should normally already be absent. Removing it here makes
    // the invariant explicit if a stale file from an interrupted run exists.
    let _ = fs::remove_file(&path);

    path
}

fn run_rustscan(args: &[&str], enable_debug_logging: bool) -> Output {
    let mut command = Command::new(rustscan_executable());
    command.args(args);

    if enable_debug_logging {
        command.env("RUST_LOG", "debug");
    }

    command
        .output()
        .expect("failed to execute the compiled rustscan binary")
}

fn combined_output(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn windows_help_hides_ulimit_and_keeps_batch_size_visible() {
    let output = run_rustscan(&["--help"], false);

    assert!(
        output.status.success(),
        "`rustscan --help` failed:\n{}",
        combined_output(&output)
    );

    let text = combined_output(&output);

    assert!(
        text.contains("--batch-size"),
        "Windows help should advertise --batch-size:\n{}",
        text
    );
    assert!(
        !text.contains("--ulimit"),
        "Windows help should not advertise Unix-only --ulimit:\n{}",
        text
    );
}

#[test]
fn windows_rejects_ulimit_from_command_line() {
    let config_path = nonexistent_config_path();
    let config_path = config_path.to_string_lossy().into_owned();

    let output = run_rustscan(
        &[
            "--no-config",
            "--config-path",
            &config_path,
            "--addresses",
            "127.0.0.1",
            "--ulimit",
            "5000",
            "--scripts",
            "none",
            "--greppable",
        ],
        false,
    );

    assert_eq!(
        output.status.code(),
        Some(2),
        "Windows --ulimit should exit with code 2:\n{}",
        combined_output(&output)
    );

    let text = combined_output(&output);

    assert!(
        text.contains("--ulimit is only supported on Unix-like operating systems"),
        "expected explicit Windows platform-validation error:\n{}",
        text
    );
    assert!(
        text.contains("--batch-size"),
        "error should direct Windows users to --batch-size:\n{}",
        text
    );
}

#[test]
fn windows_rejects_ulimit_from_config_after_merge() {
    let config_path = unique_temp_path("ulimit-config.toml");

    fs::write(&config_path, "ulimit = 5000\n")
        .expect("failed to create temporary RustScan configuration");

    let config_path_string = config_path.to_string_lossy().into_owned();

    let output = run_rustscan(
        &[
            "--config-path",
            &config_path_string,
            "--addresses",
            "127.0.0.1",
            "--scripts",
            "none",
            "--greppable",
        ],
        false,
    );

    let _ = fs::remove_file(&config_path);

    assert_eq!(
        output.status.code(),
        Some(2),
        "Windows ulimit supplied by config should exit with code 2:\n{}",
        combined_output(&output)
    );

    let text = combined_output(&output);

    assert!(
        text.contains("--ulimit is only supported on Unix-like operating systems"),
        "ulimit merged from config should be rejected on Windows:\n{}",
        text
    );
}

#[test]
fn windows_explicit_batch_size_reaches_scanner_startup() {
    let config_path = nonexistent_config_path();
    let config_path = config_path.to_string_lossy().into_owned();

    // Scan a single localhost port to keep the test deterministic and fast
    // while still exercising the real Scanner construction path.
    let output = run_rustscan(
        &[
            "--no-config",
            "--config-path",
            &config_path,
            "--addresses",
            "127.0.0.1",
            "--ports",
            "1",
            "--batch-size",
            "17",
            "--timeout",
            "50",
            "--tries",
            "1",
            "--scripts",
            "none",
            "--greppable",
        ],
        true,
    );

    assert!(
        output.status.success(),
        "RustScan failed while exercising explicit Windows batch size:\n{}",
        combined_output(&output)
    );

    let text = combined_output(&output);

    assert!(
        text.contains("Effective batch size: 17"),
        "the requested Windows batch size did not reach scanner startup:\n{}",
        text
    );
}
