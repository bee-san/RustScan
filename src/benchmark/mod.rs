//! Provides functionality to capture timing information for scans.
//!
//! # Usage
//!
//! ```rust
//! // Initiate Benchmark vector
//! # use rustscan::benchmark::{Benchmark, NamedTimer};
//! # use log::info;
//! let mut bm = Benchmark::init();
//! // Start named timer with name
//! let mut example_bench = NamedTimer::start("Example Bench");
//! // Stop named timer
//! example_bench.end();
//! // Add named timer to Benchmarks
//! bm.push(example_bench);
//! // Print Benchmark Summary
//! info!("{}", bm.summary());
//! ```
use std::time::Instant;

/// A Benchmark struct to hold NamedTimers with name, start and end Instants,
#[derive(Debug)]
pub struct Benchmark {
    named_timers: Vec<NamedTimer>,
}

impl Benchmark {
    pub fn init() -> Self {
        Self {
            named_timers: Vec::new(),
        }
    }
    pub fn push(&mut self, timer: NamedTimer) {
        self.named_timers.push(timer);
    }

    /// Summary of the benchmarks will destruct the vector,
    /// formats every element the same way and return
    /// a single String with all the available information
    /// for easy printing
    pub fn summary(&self) -> String {
        let mut summary = String::from("\nRustScan Benchmark Summary");

        for timer in &self.named_timers {
            if let (Some(start), Some(end)) = (timer.start, timer.end) {
                let runtime_secs = end.saturating_duration_since(start).as_secs_f32();
                summary.push_str(&format!("\n{0: <10} | {1: <10}s", timer.name, runtime_secs));
            }
        }
        summary
    }
}

/// The purpose of NamedTimer is to hold a name,
/// start Instant and end Instant for a specific timer.
/// The given name will be presented in the benchmark summary,
/// start and end Instants will be used for calculating runtime.
#[derive(Debug)]
pub struct NamedTimer {
    name: &'static str,
    start: Option<Instant>,
    end: Option<Instant>,
}

impl NamedTimer {
    pub fn start(name: &'static str) -> Self {
        Self {
            name,
            start: Some(Instant::now()),
            end: None,
        }
    }
    pub fn end(&mut self) {
        self.end = Some(Instant::now());
    }
}

#[test]
fn benchmark() {
    let mut benchmarks = Benchmark::init();
    let mut test_timer = NamedTimer::start("test");
    std::thread::sleep(std::time::Duration::from_millis(100));
    test_timer.end();
    benchmarks.push(test_timer);
    benchmarks.push(NamedTimer::start("only_start"));
    assert!(benchmarks
        .summary()
        .contains("\nRustScan Benchmark Summary\ntest       | 0."));
    assert!(!benchmarks.summary().contains("only_start"));
}
