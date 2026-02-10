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
    pub fn pick(range: Option<PortRanges>, ports: Option<Vec<u16>>, order: ScanOrder) -> Self {
        match order {
            ScanOrder::Serial if ports.is_none() => {
                let port_ranges = range.unwrap();
                PortStrategy::Serial(SerialRange {
                    range: port_ranges.0,
                })
            }
            ScanOrder::Random if ports.is_none() => {
                let port_ranges = range.unwrap();
                PortStrategy::Random(RandomRange {
                    range: port_ranges.0,
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
        let strategy = PortStrategy::pick(Some(ranges.clone()), None, ScanOrder::Serial);
        let result = strategy.order();
        let expected = expected_ports_from_ranges(&ranges.0);

        assert_eq!(expected, result);
    }
    #[test]
    fn random_strategy_with_range() {
        let ranges = PortRanges(vec![(1u16, 10u16), (20u16, 30u16), (100u16, 110u16)]);
        let strategy = PortStrategy::pick(Some(ranges.clone()), None, ScanOrder::Random);
        let mut result = strategy.order();
        let expected = expected_ports_from_ranges(&ranges.0);

        assert_ne!(expected, result);
        result.sort_unstable();

        assert_eq!(expected, result);
    }

    #[test]
    fn serial_strategy_with_ports() {
        let strategy = PortStrategy::pick(None, Some(vec![80, 443]), ScanOrder::Serial);
        let result = strategy.order();
        assert_eq!(vec![80, 443], result);
    }

    #[test]
    fn random_strategy_with_ports() {
        let strategy = PortStrategy::pick(None, Some((1..10).collect()), ScanOrder::Random);
        let mut result = strategy.order();
        let expected = (1..10).collect::<Vec<u16>>();
        assert_ne!(expected, result);

        result.sort_unstable();
        assert_eq!(expected, result);
    }
}
