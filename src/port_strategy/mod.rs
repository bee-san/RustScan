//! Port scanning strategies and configuration management.
//!
//! This module provides different strategies for determining the order and method
//! of port scanning operations. The choice of strategy can significantly impact
//! scan performance, stealth, and network behavior.
//!
//! ## Available Strategies
//!
//! - **Serial**: Sequential port scanning from start to end
//! - **Random**: Randomized port order to evade detection
//! - **Manual**: Custom port lists with optional randomization
//!
//! ## Usage Examples
//!
//! ```rust
//! use rustscan::port_strategy::PortStrategy;
//! use rustscan::input::{PortRange, ScanOrder};
//!
//! // Serial scanning of common ports
//! let range1 = PortRange { start: 1, end: 1024 };
//! let serial_strategy = PortStrategy::pick(&Some(range1), None, ScanOrder::Serial);
//!
//! // Random scanning for evasion
//! let range2 = PortRange { start: 1, end: 1024 };
//! let random_strategy = PortStrategy::pick(&Some(range2), None, ScanOrder::Random);
//!
//! // Custom port list
//! let custom_ports = vec![22, 80, 443, 8080, 9000];
//! let manual_strategy = PortStrategy::pick(&None, Some(custom_ports), ScanOrder::Serial);
//! ```
mod range_iterator;
use crate::input::{PortRange, ScanOrder};
use rand::rng;
use rand::seq::SliceRandom;
use range_iterator::RangeIterator;

/// Defines the strategy and ordering for port scanning operations.
///
/// Port scanning strategies determine the order in which ports are tested,
/// which can significantly impact performance, detection evasion, and
/// network behavior. Each strategy is optimized for different use cases.
///
/// ## Strategy Types
///
/// ### Serial Strategy
/// Tests ports in sequential order (1, 2, 3, ...). Best for:
/// - Systematic coverage verification
/// - Predictable resource usage
/// - Debugging and troubleshooting
/// - Compliance with sequential requirements
///
/// ### Random Strategy  
/// Tests ports in randomized order. Best for:
/// - Evasion of detection systems
/// - Load balancing across network infrastructure
/// - Avoiding patterns that trigger rate limiting
/// - Penetration testing scenarios
///
/// ### Manual Strategy
/// Uses custom port lists with optional randomization. Best for:
/// - Targeted service discovery
/// - Known infrastructure assessment
/// - Custom scanning profiles
/// - Specific compliance requirements
///
/// ## Performance Characteristics
///
/// | Strategy | Memory | CPU | Network Pattern | Detection Risk |
/// |----------|---------|-----|-----------------|----------------|
/// | Serial   | Low     | Low | Predictable     | High           |
/// | Random   | Medium  | Medium | Scattered    | Low            |
/// | Manual   | Variable| Low | Custom          | Variable       |
///
/// ## Examples
///
/// ```rust
/// use rustscan::port_strategy::PortStrategy;
/// use rustscan::input::{PortRange, ScanOrder};
///
/// // Create different strategies
/// let range1 = PortRange { start: 1, end: 65535 };
/// let range2 = PortRange { start: 1, end: 65535 };
///
/// // Sequential scanning
/// let serial = PortStrategy::pick(&Some(range1), None, ScanOrder::Serial);
///
/// // Randomized scanning  
/// let random = PortStrategy::pick(&Some(range2), None, ScanOrder::Random);
///
/// // Custom port list
/// let web_ports = vec![80, 443, 8080, 8443, 9000, 9443];
/// let manual = PortStrategy::pick(&None, Some(web_ports), ScanOrder::Random);
///
/// // Generate port vectors for scanning
/// let serial_ports = serial.order();
/// let random_ports = random.order();
/// let manual_ports = manual.order();
/// ```
#[derive(Debug)]
pub enum PortStrategy {
    Manual(Vec<u16>),
    Serial(SerialRange),
    Random(RandomRange),
}

impl PortStrategy {
    /// Creates a port scanning strategy based on the specified parameters.
    ///
    /// This factory method constructs the appropriate `PortStrategy` variant
    /// based on the provided range, custom ports, and ordering preference.
    /// It handles the logic for choosing between range-based and manual strategies.
    ///
    /// ## Strategy Selection Logic
    ///
    /// 1. **Range + Serial Order**: Creates `PortStrategy::Serial`
    /// 2. **Range + Random Order**: Creates `PortStrategy::Random`  
    /// 3. **Custom Ports + Serial Order**: Creates `PortStrategy::Manual` (preserves order)
    /// 4. **Custom Ports + Random Order**: Creates `PortStrategy::Manual` (shuffled)
    ///
    /// ## Parameters
    ///
    /// - `range`: Optional port range (start-end). Used when `ports` is None
    /// - `ports`: Optional custom port list. Takes precedence over `range`
    /// - `order`: Scanning order preference (Serial or Random)
    ///
    /// ## Returns
    ///
    /// A configured `PortStrategy` ready for port generation.
    ///
    /// ## Examples
    ///
    /// ```rust
    /// use rustscan::port_strategy::PortStrategy;
    /// use rustscan::input::{PortRange, ScanOrder};
    ///
    /// // Range-based strategies
    /// let range1 = PortRange { start: 1, end: 1000 };
    /// let range2 = PortRange { start: 1, end: 1000 };
    /// let serial = PortStrategy::pick(&Some(range1), None, ScanOrder::Serial);
    /// let random = PortStrategy::pick(&Some(range2), None, ScanOrder::Random);
    ///
    /// // Custom port strategies
    /// let ports = vec![22, 80, 443];
    /// let manual_serial = PortStrategy::pick(&None, Some(ports.clone()), ScanOrder::Serial);
    /// let manual_random = PortStrategy::pick(&None, Some(ports), ScanOrder::Random);
    /// ```
    ///
    /// ## Panics
    ///
    /// This method will panic if `range` is None when `ports` is also None,
    /// as this would result in an empty scanning strategy.
    pub fn pick(range: &Option<PortRange>, ports: Option<Vec<u16>>, order: ScanOrder) -> Self {
        match order {
            ScanOrder::Serial if ports.is_none() => {
                let range = range.as_ref().unwrap();
                PortStrategy::Serial(SerialRange {
                    start: range.start,
                    end: range.end,
                })
            }
            ScanOrder::Random if ports.is_none() => {
                let range = range.as_ref().unwrap();
                PortStrategy::Random(RandomRange {
                    start: range.start,
                    end: range.end,
                })
            }
            ScanOrder::Serial => PortStrategy::Manual(ports.unwrap()),
            ScanOrder::Random => {
                let mut rng = rng();
                let mut ports = ports.unwrap();
                ports.shuffle(&mut rng);
                PortStrategy::Manual(ports)
            }
        }
    }

    /// Generates the final ordered list of ports for scanning.
    ///
    /// This method produces the actual vector of port numbers that will be
    /// used during the scanning process. The order and contents depend on
    /// the specific strategy variant and its configuration.
    ///
    /// ## Output Characteristics
    ///
    /// - **Serial**: Ports in ascending order (1, 2, 3, ...)
    /// - **Random**: Ports in randomized order (3, 1, 7, 2, ...)
    /// - **Manual**: Custom ports in specified or shuffled order
    ///
    /// ## Memory Allocation
    ///
    /// This method creates a new `Vec<u16>` containing all ports to be scanned.
    /// For large ranges (e.g., 1-65535), this allocates significant memory
    /// (~130KB for full port range).
    ///
    /// ## Returns
    ///
    /// A `Vec<u16>` containing all ports in the order they should be scanned.
    ///
    /// ## Examples
    ///
    /// ```rust
    /// use rustscan::port_strategy::PortStrategy;
    /// use rustscan::input::{PortRange, ScanOrder};
    ///
    /// let range1 = PortRange { start: 78, end: 82 };
    /// let strategy = PortStrategy::pick(&Some(range1), None, ScanOrder::Serial);
    ///
    /// let ports = strategy.order();
    /// assert_eq!(ports, vec![78, 79, 80, 81, 82]);
    ///
    /// // Random order will vary each time
    /// let range2 = PortRange { start: 78, end: 82 };
    /// let random_strategy = PortStrategy::pick(&Some(range2), None, ScanOrder::Random);
    /// let random_ports = random_strategy.order();
    /// assert_eq!(random_ports.len(), 5); // Same count, different order
    /// ```
    ///
    /// ## Performance Notes
    ///
    /// - **Serial/Random ranges**: O(n) time and space complexity
    /// - **Manual lists**: O(1) time (clone), O(n) space
    /// - Large ranges may cause memory pressure in resource-constrained environments
    pub fn order(&self) -> Vec<u16> {
        match self {
            PortStrategy::Manual(ports) => ports.clone(),
            PortStrategy::Serial(range) => range.generate(),
            PortStrategy::Random(range) => range.generate(),
        }
    }
}

/// Trait for generating ordered port sequences from range definitions.
///
/// This trait defines the interface for converting port range configurations
/// into concrete vectors of port numbers. Different implementations provide
/// different ordering strategies optimized for various use cases.
///
/// ## Design Pattern
///
/// The `RangeOrder` trait follows the Strategy pattern, allowing different
/// algorithms for port sequence generation while maintaining a consistent
/// interface. This enables runtime strategy selection and easy extension.
///
/// ## Implementations
///
/// - [`SerialRange`]: Sequential port ordering (1, 2, 3, ...)
/// - [`RandomRange`]: Pseudo-random port ordering using LCG algorithm
///
/// ## Performance Considerations
///
/// Implementations should consider memory allocation patterns and CPU usage:
/// - Large ranges (1-65535) require significant memory (~130KB)
/// - Random generation may have higher CPU overhead
/// - Iterative approaches can reduce memory pressure
trait RangeOrder {
    /// Generates a vector of port numbers according to the strategy.
    ///
    /// This method converts the range configuration into a concrete list
    /// of port numbers ready for scanning. The ordering and distribution
    /// depend on the specific implementation.
    ///
    /// ## Returns
    ///
    /// A `Vec<u16>` containing all ports in the range, ordered according
    /// to the implementation's strategy.
    ///
    /// ## Memory Allocation
    ///
    /// This method allocates a new vector containing all ports. For large
    /// ranges, this can consume significant memory.
    fn generate(&self) -> Vec<u16>;
}

/// Sequential port range generator that produces ports in ascending order.
///
/// `SerialRange` implements a straightforward sequential scanning strategy,
/// generating ports in numerical order from start to end. This strategy
/// provides predictable behavior and minimal CPU overhead.
///
/// ## Use Cases
///
/// - **Systematic Coverage**: Ensures all ports are tested in order
/// - **Debugging**: Predictable patterns aid in troubleshooting
/// - **Compliance**: Some security standards require sequential testing
/// - **Resource Constraints**: Minimal CPU and memory overhead
///
/// ## Performance Characteristics
///
/// - **Generation Time**: O(n) where n = end - start + 1
/// - **Memory Usage**: O(n) for the resulting vector
/// - **CPU Overhead**: Minimal (simple iteration)
/// - **Deterministic**: Always produces the same order
///
/// ## Examples
///
/// ```rust
/// use rustscan::port_strategy::{PortStrategy};
/// use rustscan::input::{PortRange, ScanOrder};
///
/// let range = PortRange { start: 80, end: 85 };
/// let strategy = PortStrategy::pick(&Some(range), None, ScanOrder::Serial);
/// let ports = strategy.order();
///
/// assert_eq!(ports, vec![80, 81, 82, 83, 84, 85]);
/// ```
///
/// ## Network Behavior
///
/// Sequential scanning creates predictable network patterns that may:
/// - Trigger intrusion detection systems
/// - Cause rate limiting on target systems
/// - Generate distinctive traffic signatures
///
/// Consider using [`RandomRange`] for evasion scenarios.
#[derive(Debug)]
pub struct SerialRange {
    start: u16,
    end: u16,
}

impl RangeOrder for SerialRange {
    fn generate(&self) -> Vec<u16> {
        (self.start..=self.end).collect()
    }
}

/// Randomized port range generator using Linear Congruential Generator (LCG).
///
/// `RandomRange` implements a pseudo-random port ordering strategy designed
/// to evade detection systems and distribute network load. It uses a LCG
/// algorithm to generate port sequences with good distribution properties.
///
/// ## Algorithm Details
///
/// The implementation uses a Linear Congruential Generator that:
/// - Provides good statistical distribution across the port range
/// - Ensures maximum distance between consecutive port numbers
/// - Maintains reproducible sequences for testing
/// - Optimizes for both randomness and performance
///
/// ## Use Cases
///
/// - **Evasion Scanning**: Avoid detection by security systems
/// - **Load Distribution**: Spread network load across infrastructure
/// - **Penetration Testing**: Simulate realistic attack patterns
/// - **Rate Limit Avoidance**: Prevent triggering of rate limiting
///
/// ## Performance Characteristics
///
/// - **Generation Time**: O(n) where n = end - start + 1
/// - **Memory Usage**: O(n) for the resulting vector  
/// - **CPU Overhead**: Moderate (LCG calculations)
/// - **Randomness Quality**: Good distribution, cryptographically weak
///
/// ## Examples
///
/// ```rust
/// use rustscan::port_strategy::{PortStrategy};
/// use rustscan::input::{PortRange, ScanOrder};
///
/// let range = PortRange { start: 1, end: 100 };
/// let strategy = PortStrategy::pick(&Some(range), None, ScanOrder::Random);
/// let ports = strategy.order();
///
/// // Ports will be in random order but contain all values 1-100
/// assert_eq!(ports.len(), 100);
/// let mut sorted_ports = ports.clone();
/// sorted_ports.sort_unstable();
/// assert_eq!(sorted_ports, (1..=100).collect::<Vec<u16>>());
/// ```
///
/// ## Security Considerations
///
/// While the randomization helps evade simple detection, the LCG algorithm:
/// - Is not cryptographically secure
/// - May have predictable patterns with sufficient analysis
/// - Should not be relied upon for cryptographic security
///
/// For maximum security, consider combining with other evasion techniques.
#[derive(Debug)]
pub struct RandomRange {
    start: u16,
    end: u16,
}

impl RangeOrder for RandomRange {
    // Right now using RangeIterator and generating a range + shuffling the
    // vector is pretty much the same. The advantages of it will come once
    // we have to generate different ranges for different IPs without storing
    // actual vectors.
    //
    // Another benefit of RangeIterator is that it always generate a range with
    // a certain distance between the items in the Array. The chances of having
    // port numbers close to each other are pretty slim due to the way the
    // algorithm works.
    fn generate(&self) -> Vec<u16> {
        RangeIterator::new(self.start.into(), self.end.into()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::PortStrategy;
    use crate::input::{PortRange, ScanOrder};

    #[test]
    fn serial_strategy_with_range() {
        let range = PortRange { start: 1, end: 100 };
        let strategy = PortStrategy::pick(&Some(range), None, ScanOrder::Serial);
        let result = strategy.order();
        let expected_range = (1..=100).collect::<Vec<u16>>();
        assert_eq!(expected_range, result);
    }
    #[test]
    fn random_strategy_with_range() {
        let range = PortRange { start: 1, end: 100 };
        let strategy = PortStrategy::pick(&Some(range), None, ScanOrder::Random);
        let mut result = strategy.order();
        let expected_range = (1..=100).collect::<Vec<u16>>();
        assert_ne!(expected_range, result);

        result.sort_unstable();
        assert_eq!(expected_range, result);
    }

    #[test]
    fn serial_strategy_with_ports() {
        let strategy = PortStrategy::pick(&None, Some(vec![80, 443]), ScanOrder::Serial);
        let result = strategy.order();
        assert_eq!(vec![80, 443], result);
    }

    #[test]
    fn random_strategy_with_ports() {
        let strategy = PortStrategy::pick(&None, Some((1..10).collect()), ScanOrder::Random);
        let mut result = strategy.order();
        let expected_range = (1..10).collect::<Vec<u16>>();
        assert_ne!(expected_range, result);

        result.sort_unstable();
        assert_eq!(expected_range, result);
    }
}
