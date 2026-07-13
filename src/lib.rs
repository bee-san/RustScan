//! This crate exposes the internal functionality of the
//! [RustScan](https://rustscan.github.io/RustScan) port scanner.
//!
//! ## Example: perform a scan against localhost
//!
//! The core scanning behaviour is managed by
//! [`Scanner`](crate::scanner::Scanner) which in turn requires a
//! [`PortStrategy`](crate::port_strategy::PortStrategy):
//!
//! ```rust
//! use async_std::task::block_on;
//! use std::{net::IpAddr, time::Duration};
//!
//! use rustscan::input::{PortRange, ScanOrder};
//! use rustscan::port_strategy::PortStrategy;
//! use rustscan::scanner::Scanner;
//!
//! fn main() {
//!     let addrs = vec!["127.0.0.1".parse::<IpAddr>().unwrap()];
//!     let range = PortRange {
//!         start: 1,
//!         end: 1_000,
//!     };
//!     let strategy = PortStrategy::pick(&Some(range), None, ScanOrder::Random); // can be serial, random or manual https://github.com/RustScan/RustScan/blob/master/src/port_strategy/mod.rs
//!     let scanner = Scanner::new(
//!         &addrs, // the addresses to scan
//!         10, // batch_size is how many ports at a time should be scanned
//!         Duration::from_millis(100), //T imeout is the time RustScan should wait before declaring a port closed. As datatype Duration.
//!         1, // Tries, how many retries should RustScan do?
//!         true, // greppable is whether or not RustScan should print things, or wait until the end to print only the ip
//!         strategy, // the port strategy used
//!         true, // accessible, should the output be A11Y compliant?
//!         vec![9000], // What ports should RustScan exclude?
//!         false, // is this a UDP scan?
//!     );
//!
//!     let scan_result = block_on(scanner.run());
//!
//!     println!("{:?}", scan_result);
//! }
//! ```
#![allow(clippy::needless_doctest_main)]

use std::sync::atomic::{AtomicBool, Ordering};

/// When `true`, all stdout output from the library is suppressed.
/// Defaults to `true` so that library consumers get silent output.
/// The CLI entry point (`main.rs`) calls [`enable_output()`] at startup
/// to restore normal terminal printing.
#[doc(hidden)]
pub static SUPPRESS_STDOUT: AtomicBool = AtomicBool::new(true);

/// Suppress all stdout output from the library.
///
/// Output is suppressed by default. Call this only after calling
/// [`enable_output()`] if you need to re-silence output mid-session.
/// Has no effect on `log` crate logging (controlled by `RUST_LOG`).
///
/// ```ignore
/// rustscan::enable_output();
/// // ... print something ...
/// rustscan::suppress_output();
/// // ... output is silent again
/// ```
pub fn suppress_output() {
    SUPPRESS_STDOUT.store(true, Ordering::Relaxed);
}

/// Enable stdout output from the library.
///
/// Output is suppressed by default. The CLI calls this at startup;
/// library consumers should call this only if they want terminal output.
///
/// ```ignore
/// rustscan::enable_output();
/// // ... output will now print to stdout
/// ```
pub fn enable_output() {
    SUPPRESS_STDOUT.store(false, Ordering::Relaxed);
}

pub mod tui;

pub mod input;

pub mod scanner;

pub mod port_strategy;

pub mod benchmark;

pub mod scripts;

pub mod address;

pub mod generated;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    /// Sequential test covering all toggle behaviours on the shared
    /// `SUPPRESS_STDOUT` static.  Individual `#[test]` functions would
    /// race under parallel test execution; a single test runs them in
    /// the order shown and is safe with any `--test-threads` setting.
    ///
    /// The actual stdout-suppression effect is verified by the
    /// integration tests in tests/stdout_suppression.rs, which spawn
    /// subprocesses and therefore have no shared state.
    #[test]
    fn toggle_flag_behavior() {
        // --- suppress_output sets the flag ---
        SUPPRESS_STDOUT.store(false, Ordering::Relaxed);
        suppress_output();
        assert!(SUPPRESS_STDOUT.load(Ordering::Relaxed));

        // --- suppress_output is idempotent ---
        SUPPRESS_STDOUT.store(false, Ordering::Relaxed);
        suppress_output();
        suppress_output();
        assert!(SUPPRESS_STDOUT.load(Ordering::Relaxed));

        // --- enable_output clears the flag ---
        SUPPRESS_STDOUT.store(true, Ordering::Relaxed);
        enable_output();
        assert!(!SUPPRESS_STDOUT.load(Ordering::Relaxed));
    }
}
