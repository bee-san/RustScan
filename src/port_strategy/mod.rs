//! Provides a means to hold configuration options specifically for port scanning.
mod range_iterator;
use crate::input::{PortRange, ScanOrder};
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
    pub fn pick(range: &Option<Vec<PortRange>>, ports: Option<Vec<u16>>, order: ScanOrder) -> Self {
        // If ports are specified, use them (shuffle if Random)
        if let Some(mut ports_vec) = ports {
            return match order {
                ScanOrder::Serial => PortStrategy::Manual(ports_vec),
                ScanOrder::Random => {
                    let mut rng = rng();
                    ports_vec.shuffle(&mut rng);
                    PortStrategy::Manual(ports_vec)
                }
            };
        }

        // No explicit ports provided: fall back to ranges (one or many)
        if let Some(ranges) = range {
            if ranges.len() == 1 {
                let r = &ranges[0];
                return match order {
                    ScanOrder::Serial => PortStrategy::Serial(SerialRange {
                        start: r.start,
                        end: r.end,
                    }),
                    ScanOrder::Random => PortStrategy::Random(RandomRange {
                        start: r.start,
                        end: r.end,
                    }),
                };
            }

            // Multiple ranges: expand into a single Vec<u16>
            let mut combined: Vec<u16> = Vec::new();
            for r in ranges {
                combined.extend(r.start..=r.end);
            }

            // For Random order, shuffle the combined vector
            if let ScanOrder::Random = order {
                let mut rng = rng();
                combined.shuffle(&mut rng);
            }

            return PortStrategy::Manual(combined);
        }

        // No ranges or ports provided: this should not happen because Opts::read()
        // sets a default range, but handle defensively.
        PortStrategy::Serial(SerialRange {
            start: 1,
            end: 65_535,
        })
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
    start: u16,
    end: u16,
}

impl RangeOrder for SerialRange {
    fn generate(&self) -> Vec<u16> {
        (self.start..=self.end).collect()
    }
}

/// As the name implies RandomRange will always generate a vector with
/// a random order. This vector is built following the LCG algorithm.
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
        let strategy = PortStrategy::pick(&Some(vec![range.clone()]), None, ScanOrder::Serial);
        let result = strategy.order();
        let expected_range = (1..=100).collect::<Vec<u16>>();
        assert_eq!(expected_range, result);
    }
    #[test]
    fn random_strategy_with_range() {
        let range = PortRange { start: 1, end: 100 };
        let strategy = PortStrategy::pick(&Some(vec![range.clone()]), None, ScanOrder::Random);
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
