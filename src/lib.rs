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
//! use std::{net::IpAddr, time::Duration};
//!
//! use rustscan::input::{PortRange, ScanOrder};
//! use rustscan::port_strategy::PortStrategy;
//! use rustscan::scanner::Scanner;
//! #[tokio::main]
//! async fn main() {
//!     let addrs = vec!["127.0.0.1".parse::<IpAddr>().unwrap()];
//!     let range = PortRange {
//!         start: 1,
//!         end: 1_000,
//!     };
//!     let strategy = PortStrategy::pick(&Some(range), None, ScanOrder::Random);
//!     let scanner = Scanner::new(
//!         &addrs,
//!         10,
//!         Duration::from_millis(100),
//!         1,
//!         true,
//!         strategy,
//!         true,
//!         vec![9000],
//!         false,
//!     );
//!
//!     let scan_result = scanner.run().await;
//!
//!     println!("{:?}", scan_result);
//! }
//! ```
#![allow(clippy::needless_doctest_main)]

pub mod tui;

pub mod input;

pub mod scanner;

pub mod port_strategy;

pub mod benchmark;

pub mod scripts;

pub mod address;

pub mod udp_packets;
