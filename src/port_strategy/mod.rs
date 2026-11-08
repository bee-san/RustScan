//! Provides a means to hold configuration options specifically for port scanning.
mod range_iterator;
use crate::input::{PortRanges, ScanOrder};
use rand::rng;
use rand::seq::SliceRandom;
use range_iterator::RangeIterator;

/// Represents options of port scanning.
///
/// Right now all these options involve ranges, but in the future
/// it will also contain custom lists of ports.
#[derive(Debug)]
pub enum PortStrategy {
    Manual(Vec<u16>),
    Serial(SerialRange),
    Random(RandomRange),
}

impl PortStrategy {
    /// Picks a strategy from an optional range and an optional port list.
    ///
    /// An explicit port list always wins over the range. When the caller
    /// passes neither (the CLI never does this, it defaults the range, but
    /// library callers can), the full `1-65535` range is scanned instead of
    /// panicking.
    pub fn pick(range: &Option<PortRanges>, ports: Option<Vec<u16>>, order: ScanOrder) -> Self {
        if let Some(ports) = ports {
            return match order {
                ScanOrder::Serial => PortStrategy::Manual(ports),
                ScanOrder::Random => {
                    let mut rng = rng();
                    let mut ports = ports;
                    ports.shuffle(&mut rng);
                    PortStrategy::Manual(ports)
                }
            };
        }
        // No explicit ports: scan the range, or the full range when the
        // caller gave neither, mirroring the CLI default in `Opts`.
        let ranges = range
            .as_ref()
            .map_or(vec![(1, 65535)], |port_ranges| port_ranges.0.clone());
        match order {
            ScanOrder::Serial => PortStrategy::Serial(SerialRange { range: ranges }),
            ScanOrder::Random => PortStrategy::Random(RandomRange { range: ranges }),
        }
    }

    pub fn order(&self) -> Vec<u16> {
        match self {
            PortStrategy::Manual(ports) => ports.clone(),
            PortStrategy::Serial(range) => range.generate(),
            PortStrategy::Random(range) => range.generate(),
        }
    }
}

/// Trait associated with a port strategy. Each PortStrategy must be able
/// to generate an order for future port scanning.
trait RangeOrder {
    fn generate(&self) -> Vec<u16>;
}

/// As the name implies SerialRange will always generate a vector in
/// ascending order.
#[derive(Debug)]
pub struct SerialRange {
    range: Vec<(u16, u16)>,
}

impl RangeOrder for SerialRange {
    fn generate(&self) -> Vec<u16> {
        RangeIterator::new_serial(&self.range).collect()
    }
}

/// As the name implies RandomRange will always generate a vector with
/// a random order. This vector is built following the LCG algorithm.
#[derive(Debug)]
pub struct RandomRange {
    range: Vec<(u16, u16)>,
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
        RangeIterator::new_random(&self.range).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::PortStrategy;
    use crate::input::{PortRanges, ScanOrder};
    use std::collections::HashSet;

    fn expected_ports_from_ranges(input: &[(u16, u16)]) -> Vec<u16> {
        let mut s = HashSet::new();
        for &(start, end) in input {
            for p in start..=end {
                s.insert(p);
            }
        }
        let mut v: Vec<u16> = s.into_iter().collect();
        v.sort_unstable();
        v
    }
    #[test]
    fn serial_strategy_with_range() {
        let ranges = PortRanges(vec![(1u16, 10u16), (20u16, 30u16), (100u16, 110u16)]);
        let strategy = PortStrategy::pick(&Some(ranges.clone()), None, ScanOrder::Serial);
        let result = strategy.order();
        let expected = expected_ports_from_ranges(&ranges.0);

        assert_eq!(expected, result);
    }
    #[test]
    fn random_strategy_with_range() {
        let ranges = PortRanges(vec![(1u16, 10u16), (20u16, 30u16), (100u16, 110u16)]);
        let strategy = PortStrategy::pick(&Some(ranges.clone()), None, ScanOrder::Random);
        let mut result = strategy.order();
        let expected = expected_ports_from_ranges(&ranges.0);

        assert_ne!(expected, result);
        result.sort_unstable();

        assert_eq!(expected, result);
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
        let expected = (1..10).collect::<Vec<u16>>();
        assert_ne!(expected, result);

        result.sort_unstable();
        assert_eq!(expected, result);
    }

    #[test]
    fn pick_with_neither_range_nor_ports_scans_full_range_serial() {
        let strategy = PortStrategy::pick(&None, None, ScanOrder::Serial);
        let result = strategy.order();

        assert_eq!(result.len(), 65_535);
        assert_eq!(result[0], 1);
        assert_eq!(result[65_534], 65_535);
    }

    #[test]
    fn pick_with_neither_range_nor_ports_scans_full_range_random() {
        let strategy = PortStrategy::pick(&None, None, ScanOrder::Random);
        let mut result = strategy.order();
        assert_eq!(result.len(), 65_535);

        result.sort_unstable();
        assert_eq!(result, (1..=65_535).collect::<Vec<u16>>());
    }

    #[test]
    fn pick_with_empty_ports_stays_manual() {
        let strategy = PortStrategy::pick(&None, Some(Vec::new()), ScanOrder::Serial);

        assert!(strategy.order().is_empty());
    }

    #[test]
    fn pick_with_both_ports_and_range_prefers_ports() {
        let ranges = PortRanges(vec![(1u16, 10u16)]);
        let strategy = PortStrategy::pick(&Some(ranges), Some(vec![80, 443]), ScanOrder::Serial);

        assert_eq!(strategy.order(), vec![80, 443]);
    }
}
