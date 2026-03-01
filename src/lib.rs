//! This crate exposes the internal functionality of the
//! [RustScan](https://rustscan.github.io/RustScan) port scanner.
//!
//! RustScan is a modern, high-performance port scanner built in Rust that can scan
//! all 65,535 ports in seconds. It is designed to complement Nmap by providing rapid
//! initial port discovery, with the results then fed to Nmap for detailed analysis.
//!
//! ## Key Features
//!
//! - **Ultra-fast scanning**: Can scan all 65k ports in 3-8 seconds
//! - **Nmap integration**: Automatically pipes results to Nmap for detailed analysis
//! - **Scripting engine**: Supports Python, Lua, and Shell scripts
//! - **IPv6 support**: Full support for IPv6 addresses and networks
//! - **UDP scanning**: Comprehensive UDP port scanning capabilities
//! - **Accessibility**: Built with A11Y compliance in mind
//! - **Adaptive learning**: Improves performance over time based on usage patterns
//!
//! ## Architecture Overview
//!
//! The core scanning behaviour is managed by
//! [`Scanner`](crate::scanner::Scanner) which in turn requires a
//! [`PortStrategy`](crate::port_strategy::PortStrategy). The scanning process
//! follows this flow:
//!
//! 1. **Input Processing**: IP addresses and port ranges are parsed and validated
//! 2. **Port Strategy**: Determines the order and method of port scanning
//! 3. **Socket Scanning**: Concurrent socket connections test port availability
//! 4. **Result Processing**: Open ports are collected and optionally passed to Nmap
//! 5. **Script Execution**: Optional scripts are executed based on discovered services
//!
//! ## Basic Usage Example
//!
//! The following example demonstrates a basic scan against localhost:
//!
//! ```rust
//! use async_std::task::block_on;
//! use std::{net::IpAddr, time::Duration};
//!
//! use rustscan::input::{PortRange, ScanOrder};
//! use rustscan::port_strategy::PortStrategy;
//! use rustscan::scanner::Scanner;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Define target addresses - supports IPv4, IPv6, and hostnames
//!     let addrs = vec!["127.0.0.1".parse::<IpAddr>().unwrap()];
//!     
//!     // Configure port range - scan ports 1-1000
//!     let range = PortRange {
//!         start: 1,
//!         end: 1_000,
//!     };
//!     
//!     // Choose scanning strategy (Random, Serial, or Manual)
//!     let strategy = PortStrategy::pick(&Some(range), None, ScanOrder::Random);
//!     
//!     // Create scanner with optimized settings
//!     let scanner = Scanner::new(
//!         &addrs,                           // Target IP addresses
//!         10,                               // Batch size (concurrent connections)
//!         Duration::from_millis(100),       // Connection timeout
//!         1,                                // Number of retries per port
//!         true,                             // Greppable output (quiet mode)
//!         strategy,                         // Port scanning strategy
//!         true,                             // Accessibility mode (A11Y compliant)
//!         vec![9000],                       // Ports to exclude from scan
//!         false,                            // TCP scan (set true for UDP)
//!     );
//!
//!     // Execute the scan asynchronously
//!     let scan_result = block_on(scanner.run());
//!
//!     // Process results - scan_result contains Vec<SocketAddr> of open ports
//!     println!("Discovered {} open ports:", scan_result.len());
//!     for socket in &scan_result {
//!         println!("  {}", socket);
//!     }
//!     
//!     Ok(())
//! }
//! ```
//!
//! ## Advanced Usage Examples
//!
//! ### High-Performance Scanning
//!
//! ```rust
//! use rustscan::input::{PortRange, ScanOrder};
//! use rustscan::port_strategy::PortStrategy;
//! use rustscan::scanner::Scanner;
//! use std::{net::IpAddr, time::Duration};
//! use async_std::task::block_on;
//!
//! // Scan all ports with maximum performance
//! let addrs = vec!["192.168.1.1".parse::<IpAddr>().unwrap()];
//! let range = PortRange { start: 1, end: 65535 };
//! let strategy = PortStrategy::pick(&Some(range), None, ScanOrder::Random);
//!
//! // High-performance configuration
//! let scanner = Scanner::new(
//!     &addrs,
//!     5000,                        // Large batch size for speed
//!     Duration::from_millis(50),   // Short timeout for speed
//!     1,                           // Single attempt
//!     false,                       // Show progress output
//!     strategy,
//!     false,                       // Standard output
//!     vec![],                      // No excluded ports
//!     false,
//! );
//!
//! let results = block_on(scanner.run());
//! println!("Found {} open ports in high-speed scan", results.len());
//! ```
//!
//! ### UDP Scanning
//!
//! ```rust
//! # use rustscan::input::{PortRange, ScanOrder};
//! # use rustscan::port_strategy::PortStrategy;
//! # use rustscan::scanner::Scanner;
//! # use std::{net::IpAddr, time::Duration};
//! # use async_std::task::block_on;
//! // UDP port scanning example
//! let addrs = vec!["8.8.8.8".parse::<IpAddr>().unwrap()];
//! let range = PortRange { start: 53, end: 161 }; // Common UDP ports
//! let strategy = PortStrategy::pick(&Some(range), None, ScanOrder::Serial);
//!
//! let udp_scanner = Scanner::new(
//!     &addrs,
//!     100,                         // Smaller batch for UDP
//!     Duration::from_secs(2),      // Longer timeout for UDP
//!     3,                           // More retries for UDP
//!     false,
//!     strategy,
//!     true,
//!     vec![],
//!     true,                        // Enable UDP mode
//! );
//!
//! let udp_results = block_on(udp_scanner.run());
//! println!("UDP scan found {} open ports", udp_results.len());
//! ```
//!
//! ## Performance Tuning
//!
//! - **Batch Size**: Adjust based on system limits (ulimit) and network conditions
//! - **Timeout**: Balance between speed and accuracy
//! - **Retries**: More retries for unreliable networks, fewer for speed
//! - **Port Strategy**: Random for evasion, Serial for systematic scanning
//!
//! ## Error Handling
//!
//! RustScan handles various error conditions gracefully:
//!
//! - Network timeouts and connection failures
//! - System resource limits (file descriptors)
//! - Invalid IP addresses and port ranges
//! - DNS resolution failures
//!
//! ## Integration with Nmap
//!
//! RustScan is designed to work seamlessly with Nmap:
//!
//! 1. RustScan quickly identifies open ports
//! 2. Results are formatted for Nmap consumption
//! 3. Nmap performs detailed service detection and OS fingerprinting
//! 4. Scripts can be executed based on discovered services
#![allow(clippy::needless_doctest_main)]
#![warn(missing_docs)]
// Note: rustdoc::missing_doc_code_examples lint is unstable
#![doc(html_root_url = "https://docs.rs/rustscan/2.4.1")]
#![doc(html_logo_url = "https://github.com/RustScan/RustScan/raw/master/pictures/rustscan.png")]

pub mod tui;

pub mod input;

pub mod scanner;

pub mod port_strategy;

pub mod benchmark;

pub mod scripts;

pub mod address;

/// Generated configuration and payload data for RustScan.
///
/// This module contains automatically generated configuration data and
/// service-specific payloads used for UDP port scanning. The data is
/// generated from external sources and embedded into the binary for
/// optimal performance.
pub mod generated;
