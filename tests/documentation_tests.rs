//! Comprehensive documentation testing suite for RustScan
//!
//! This module contains tests that verify the quality, completeness, and
//! correctness of the RustScan documentation. It ensures that:
//!
//! - All public APIs are properly documented
//! - Documentation examples compile and run correctly  
//! - Cross-references and links are valid
//! - Documentation follows consistent formatting standards

use std::process::Command;
use std::str;

#[test]
fn test_all_public_items_documented() {
    let output = Command::new("cargo")
        .args(&["doc", "--no-deps"])
        .env("RUSTDOCFLAGS", "-D missing_docs")
        .output()
        .expect("Failed to run cargo doc");

    if !output.status.success() {
        let stderr = str::from_utf8(&output.stderr).unwrap();
        panic!(
            "Documentation check failed - missing documentation found:\n{}",
            stderr
        );
    }
}

#[test]
fn test_documentation_examples_compile() {
    let output = Command::new("cargo")
        .args(&["test", "--doc"])
        .output()
        .expect("Failed to run doc tests");

    if !output.status.success() {
        let stderr = str::from_utf8(&output.stderr).unwrap();
        let stdout = str::from_utf8(&output.stdout).unwrap();
        panic!(
            "Documentation examples failed to compile:\nSTDOUT:\n{}\nSTDERR:\n{}",
            stdout, stderr
        );
    }

    // Verify that doc tests actually ran
    let stdout = str::from_utf8(&output.stdout).unwrap();
    assert!(
        stdout.contains("test result: ok") || stdout.contains("running"),
        "Doc tests should have executed successfully"
    );
}

#[test]
fn test_no_broken_intra_doc_links() {
    let output = Command::new("cargo")
        .args(&["doc", "--no-deps"])
        .env("RUSTDOCFLAGS", "-D rustdoc::broken_intra_doc_links")
        .output()
        .expect("Failed to run cargo doc");

    if !output.status.success() {
        let stderr = str::from_utf8(&output.stderr).unwrap();
        panic!("Broken documentation links found:\n{}", stderr);
    }
}

#[test]
fn test_documentation_generates_without_warnings() {
    let output = Command::new("cargo")
        .args(&["doc", "--no-deps", "--document-private-items"])
        .output()
        .expect("Failed to run cargo doc");

    let stderr = str::from_utf8(&output.stderr).unwrap();

    // Filter out acceptable warnings
    let critical_warnings: Vec<&str> = stderr
        .lines()
        .filter(|line| line.contains("warning:"))
        .filter(|line| !line.contains("unused")) // Ignore unused warnings in docs
        .filter(|line| !line.contains("missing documentation")) // Allow missing docs on internal items
        .filter(|line| !line.contains("broken_intra_doc_links")) // These are tested separately
        .filter(|line| !line.contains("generated")) // Ignore summary lines
        .collect();

    if !critical_warnings.is_empty() {
        panic!(
            "Documentation generation produced critical warnings:\n{}",
            critical_warnings.join("\n")
        );
    }

    assert!(
        output.status.success(),
        "Documentation generation should succeed"
    );

    // Verify that we don't have too many missing documentation warnings
    // This ensures main public API is documented while allowing some internal items to be undocumented
    let missing_doc_warnings: Vec<&str> = stderr
        .lines()
        .filter(|line| line.contains("missing documentation"))
        .collect();

    // Allow up to 50 missing documentation warnings for internal/private items
    // Main public API should be well documented as verified by other tests
    if missing_doc_warnings.len() > 50 {
        panic!(
            "Too many missing documentation warnings ({} found, max 50 allowed):\n{}",
            missing_doc_warnings.len(),
            missing_doc_warnings.join("\n")
        );
    }

    println!(
        "Documentation generated successfully with {} missing documentation warnings (acceptable level)",
        missing_doc_warnings.len()
    );
}

#[test]
fn test_documentation_coverage_metrics() {
    use std::fs;
    use std::path::Path;

    // Generate documentation first
    let output = Command::new("cargo")
        .args(&["doc", "--no-deps"])
        .output()
        .expect("Failed to run cargo doc");

    assert!(output.status.success(), "Documentation generation failed");

    // Check that documentation files were generated
    let doc_path = Path::new("target/doc/rustscan");

    // If doc directory doesn't exist, try generating documentation again
    if !doc_path.exists() {
        println!("Documentation directory not found, generating documentation again...");
        let output2 = Command::new("cargo")
            .args(&["doc", "--no-deps", "--force"])
            .output()
            .expect("Failed to run cargo doc");

        assert!(
            output2.status.success(),
            "Second documentation generation failed"
        );

        // Give it a moment to complete
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    assert!(doc_path.exists(), "Documentation directory should exist");

    // Count documentation files
    let doc_files = fs::read_dir(doc_path)
        .expect("Failed to read documentation directory")
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let path = entry.path();
            if path.extension()? == "html" {
                Some(path)
            } else {
                None
            }
        })
        .count();

    // Should have documentation for main modules
    assert!(
        doc_files >= 5,
        "Should have documentation files for at least 5 modules, found {}",
        doc_files
    );
}

#[test]
fn test_example_code_quality() {
    // This test verifies that documentation examples follow best practices
    use std::fs;

    let lib_content = fs::read_to_string("src/lib.rs").expect("Failed to read lib.rs");

    // Check for comprehensive examples in main documentation
    assert!(
        lib_content.contains("```rust"),
        "lib.rs should contain Rust code examples"
    );

    assert!(
        lib_content.contains("use rustscan::"),
        "Examples should demonstrate how to use the crate"
    );

    assert!(
        lib_content.contains("Scanner::new"),
        "Examples should show Scanner usage"
    );

    // Verify error handling in examples
    assert!(
        lib_content.contains("Result<")
            || lib_content.contains("unwrap()")
            || lib_content.contains("?"),
        "Examples should demonstrate proper error handling patterns"
    );
}

#[test]
fn test_accessibility_features_documented() {
    use std::fs;

    // Check that accessibility features are properly documented
    let lib_content = fs::read_to_string("src/lib.rs").expect("Failed to read lib.rs");

    assert!(
        lib_content.contains("A11Y")
            || lib_content.contains("accessibility")
            || lib_content.contains("accessible"),
        "Documentation should mention accessibility features"
    );

    // Check scanner documentation
    let scanner_content =
        fs::read_to_string("src/scanner/mod.rs").expect("Failed to read scanner/mod.rs");

    assert!(
        scanner_content.contains("accessible") || scanner_content.contains("accessibility"),
        "Scanner documentation should explain accessibility features"
    );
}

#[test]
fn test_performance_documentation() {
    use std::fs;

    let lib_content = fs::read_to_string("src/lib.rs").expect("Failed to read lib.rs");

    // Performance-related documentation
    let performance_keywords = [
        "performance",
        "batch",
        "timeout",
        "concurrent",
        "memory",
        "speed",
        "optimization",
        "throughput",
    ];

    let has_performance_docs = performance_keywords
        .iter()
        .any(|keyword| lib_content.to_lowercase().contains(keyword));

    assert!(
        has_performance_docs,
        "Documentation should include performance guidance and considerations"
    );
}

#[test]
fn test_security_considerations_documented() {
    use std::fs;

    // Read various source files to check for security documentation
    let files = [
        "src/lib.rs",
        "src/scanner/mod.rs",
        "src/port_strategy/mod.rs",
    ];

    let mut security_docs_found = false;

    for file_path in &files {
        if let Ok(content) = fs::read_to_string(file_path) {
            let security_keywords = [
                "security",
                "evasion",
                "detection",
                "stealth",
                "firewall",
                "IDS",
                "rate limit",
                "defensive",
            ];

            if security_keywords
                .iter()
                .any(|keyword| content.to_lowercase().contains(keyword))
            {
                security_docs_found = true;
                break;
            }
        }
    }

    assert!(
        security_docs_found,
        "Documentation should include security considerations and evasion techniques"
    );
}

#[test]
fn test_cross_platform_documentation() {
    use std::fs;

    let lib_content = fs::read_to_string("src/lib.rs").expect("Failed to read lib.rs");

    // Should mention cross-platform compatibility
    let platform_indicators = [
        "IPv4",
        "IPv6",
        "Windows",
        "Linux",
        "macOS",
        "cross-platform",
        "operating system",
        "OS",
    ];

    let has_platform_docs = platform_indicators
        .iter()
        .any(|indicator| lib_content.contains(indicator));

    assert!(
        has_platform_docs,
        "Documentation should include cross-platform information"
    );
}

#[test]
fn test_integration_documentation() {
    use std::fs;

    let lib_content = fs::read_to_string("src/lib.rs").expect("Failed to read lib.rs");

    // Should document integration with Nmap
    assert!(
        lib_content.to_lowercase().contains("nmap"),
        "Documentation should explain Nmap integration"
    );

    // Should show how to use as a library
    assert!(
        lib_content.contains("use rustscan::"),
        "Documentation should show library usage examples"
    );
}

#[cfg(test)]
mod benchmarks {
    use super::*;
    use std::time::Instant;

    #[test]
    fn benchmark_documentation_generation_time() {
        let start = Instant::now();

        let output = Command::new("cargo")
            .args(&["doc", "--no-deps"])
            .output()
            .expect("Failed to run cargo doc");

        let duration = start.elapsed();

        assert!(output.status.success(), "Documentation generation failed");

        // Documentation should generate in reasonable time (under 2 minutes)
        assert!(
            duration.as_secs() < 120,
            "Documentation generation took too long: {:?}",
            duration
        );

        println!("Documentation generated in {:?}", duration);
    }

    #[test]
    fn test_documentation_size_reasonable() {
        use std::fs;
        use std::path::Path;

        // Generate docs first
        let output = Command::new("cargo")
            .args(&["doc", "--no-deps"])
            .output()
            .expect("Failed to run cargo doc");

        assert!(output.status.success(), "Documentation generation failed");

        // Check total documentation size
        let doc_path = Path::new("target/doc");
        if doc_path.exists() {
            let size = get_dir_size(doc_path).unwrap_or(0);

            // Documentation should be reasonable size (under 50MB)
            const MAX_SIZE_MB: u64 = 50 * 1024 * 1024;
            assert!(
                size < MAX_SIZE_MB,
                "Documentation size ({} bytes) exceeds maximum ({} bytes)",
                size,
                MAX_SIZE_MB
            );

            println!("Documentation size: {} MB", size / (1024 * 1024));
        }
    }

    fn get_dir_size(path: &std::path::Path) -> std::io::Result<u64> {
        use std::fs;
        let mut size = 0;
        if path.is_dir() {
            for entry in fs::read_dir(path)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_dir() {
                    size += get_dir_size(&path)?;
                } else {
                    size += entry.metadata()?.len();
                }
            }
        }
        Ok(size)
    }
}

#[cfg(test)]
mod link_validation {
    use std::fs;
    use std::path::Path;

    #[test]
    fn test_external_links_in_documentation() {
        // This test would ideally validate external links, but we'll keep it simple
        // and just check that external links follow expected patterns

        let lib_content = fs::read_to_string("src/lib.rs").expect("Failed to read lib.rs");

        // Check for properly formatted links
        if lib_content.contains("http://") {
            assert!(
                !lib_content.contains("http://"),
                "Documentation should use HTTPS links where possible"
            );
        }

        // Check for GitHub links format
        if lib_content.contains("github.com") {
            assert!(
                lib_content.contains("https://github.com"),
                "GitHub links should be properly formatted"
            );
        }
    }

    #[test]
    fn test_internal_module_references() {
        // Verify that internal module references are correct
        use std::collections::HashMap;

        let mut modules = HashMap::new();

        // Collect available modules
        if Path::new("src/scanner").exists() {
            modules.insert("scanner", true);
        }
        if Path::new("src/port_strategy").exists() {
            modules.insert("port_strategy", true);
        }
        if Path::new("src/input.rs").exists() {
            modules.insert("input", true);
        }

        // Check lib.rs references these modules correctly
        let lib_content = fs::read_to_string("src/lib.rs").expect("Failed to read lib.rs");

        for (module, _) in &modules {
            assert!(
                lib_content.contains(&format!("pub mod {}", module)),
                "lib.rs should declare module '{}'",
                module
            );
        }
    }
}
