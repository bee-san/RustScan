//! Provides a means to hold configuration options specifically for port scanning.
use either::Either;
use crate::input::{PortRange, ScanOrder};
use rand::seq::SliceRandom;

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
                let mut rng = rand::rng();
                let mut ports = ports.unwrap();
                ports.shuffle(&mut rng);
                PortStrategy::Manual(ports)
            }
        }
    }

    pub fn ordered_iter(&self) -> impl Iterator<Item=u16> + use<'_> {
        match self {
            PortStrategy::Manual(ports) => Either::Left(Either::Left(ports.iter().copied())),
            PortStrategy::Serial(range) => {
                Either::Left(Either::Right(range.start..=range.end))
            },
            PortStrategy::Random(range) => {
                let length = range.end - range.start;
                let start = range.start;
                let iter = blackrock2::BlackRockIter::new(u64::from(length) + 1)
                    .map(move |port| port as u16 + start);
                Either::Right(iter)
            },
        }
    }
}

/// As the name implies SerialRange will always generate a vector in
/// ascending order.
#[derive(Debug)]
pub struct SerialRange {
    start: u16,
    end: u16,
}

/// As the name implies RandomRange will always generate a vector with
/// a random order. This vector is built following the LCG algorithm.
#[derive(Debug)]
pub struct RandomRange {
    start: u16,
    end: u16,
}

#[cfg(test)]
mod tests {
    use super::PortStrategy;
    use crate::input::{PortRange, ScanOrder};

    #[test]
    fn serial_strategy_with_range() {
        let range = PortRange { start: 1, end: 100 };
        let strategy = PortStrategy::pick(&Some(range), None, ScanOrder::Serial);
        let result = strategy.ordered_iter().collect::<Vec<_>>();
        let expected_range = (1..=100).collect::<Vec<u16>>();
        assert_eq!(expected_range, result);
    }
    #[test]
    fn random_strategy_with_range() {
        let range = PortRange { start: 1, end: 100 };
        let strategy = PortStrategy::pick(&Some(range), None, ScanOrder::Random);
        let mut result = strategy.ordered_iter().collect::<Vec<_>>();
        let expected_range = (1..=100).collect::<Vec<u16>>();
        assert_ne!(expected_range, result);

        result.sort_unstable();
        assert_eq!(expected_range, result);
    }

    #[test]
    fn serial_strategy_with_ports() {
        let strategy = PortStrategy::pick(&None, Some(vec![80, 443]), ScanOrder::Serial);
        let result = strategy.ordered_iter().collect::<Vec<_>>();
        assert_eq!(vec![80, 443], result);
    }

    #[test]
    fn random_strategy_with_ports() {
        let strategy = PortStrategy::pick(&None, Some((1..10).collect()), ScanOrder::Random);
        let mut result = strategy.ordered_iter().collect::<Vec<_>>();
        let expected_range = (1..10).collect::<Vec<u16>>();
        assert_ne!(expected_range, result);

        result.sort_unstable();
        assert_eq!(expected_range, result);
    }
}
