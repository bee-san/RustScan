use bit_set::BitSet;
use gcd::Gcd;
use rand::Rng;
use std::convert::TryInto;

pub struct RangeIterator {
    active: bool,
    total: u32,
    normalized_first_pick: u32,
    normalized_pick: u32,
    step: u32,
    ranges: Vec<(u32, u32)>,
    prefix: Vec<u32>,
    serial_itr: Option<Box<dyn Iterator<Item = u16>>>,
    serial_itr_bitset: Option<BitSet>,
}

/// Yields ports produced from a collection of (possibly overlapping)
/// inclusive `u16` ranges in two modes:
///
/// **Randomized** — created by `RangeIterator::new_random`:
///    - The algorithm generates a permutation of indices `0..N-1` using the
///      additive congruential step `x_{i+1} = (x_i + step) % N`.
///    - `step` is chosen so `gcd(step, N) == 1` to ensure the sequence is a
///      full-length cycle (visits each index exactly once).
///    - `x_0` (the seed stored as `normalized_first_pick`) is chosen uniformly
///      in `0..N`.
///
///      For more information: <https://en.wikipedia.org/wiki/Linear_congruential_generator>
///
/// **Serial** — `RangeIterator::new_serial`:
///     Iterates the input ranges in the **original input order** and yields
///     each port the first time it is encountered. Duplicate ports (from
///     overlapping ranges) are skipped using a small `BitSet` of size 65_536.
///

impl RangeIterator {
    /// Construct a randomized iterator (LCG permutation).
    ///
    /// Preconditions:
    /// - `input` must contain at least one `(u16,u16)`
    /// and each pair must satisfy `start <= end`.

    pub fn new_random(input: &[(u16, u16)]) -> Self {
        // normalize & merge into (start, len) u32 pairs
        // Example: [(10,12),(11,15)] -> merged [(10,6)]
        let mut ranges: Vec<(u32, u32)> = input
            .into_iter()
            .map(|(s, e)| {
                let start = *s as u32;
                let end_excl = (*e as u32) + 1; // convert inclusive -> exclusive
                (start, end_excl)
            })
            .collect();

        ranges.sort_unstable_by_key(|&(s, _)| s);

        let mut merged: Vec<(u32, u32)> = Vec::with_capacity(ranges.len());
        if !ranges.is_empty() {
            let mut iter = ranges.into_iter();
            let (mut cur_s, mut cur_end) = iter.next().unwrap(); // cur_end exclusive
            for (s, end_excl) in iter {
                if s <= cur_end {
                    // overlap/adjacent -> extend
                    if end_excl > cur_end {
                        cur_end = end_excl;
                    }
                } else {
                    // push disjoint segment as (start, len)
                    merged.push((cur_s, cur_end - cur_s)); // len = excl - start
                    cur_s = s;
                    cur_end = end_excl;
                }
            }
            merged.push((cur_s, cur_end - cur_s));
        }
        // build prefix sums (prefix[0] = 0; prefix.len() == merged.len() + 1)
        let prefix = merged.iter().fold(vec![0u32], |mut acc, (_, len)| {
            let last = acc.last().unwrap();
            acc.push(last.saturating_add(*len));
            acc
        });

        // total is guaranteed > 0 by precondition (input.len() >= 1)
        let total = *prefix.last().unwrap();

        // pick step and seed
        let step = pick_random_coprime(total);
        let mut rng = rand::rng();
        let first = rng.random_range(0..total);

        Self {
            active: true,
            total,
            normalized_first_pick: first,
            normalized_pick: first,
            step,
            ranges: merged,
            prefix,
            serial_itr: None,
            serial_itr_bitset: None,
        }
    }

    /// Construct a serial iterator that yields ports in original input order,
    /// skipping duplicates. The deduplication is done on the fly with a BitSet.
    ///
    /// Preconditions:
    /// - `input` must contain at least one `(u16,u16)` and each pair must satisfy `start <= end`.
    pub fn new_serial(input: &[(u16, u16)]) -> Self {
        // Build a serial iterator that yields ports in *input order* (start..=end).
        // We keep the merged ranges/prefix empty here (they are not needed for serial mode).
        let input = input.to_vec();
        let serial_itr = input.into_iter().flat_map(|(start, end)| start..=end);

        let serial_itr_boxed: Box<dyn Iterator<Item = u16>> = Box::new(serial_itr);
        // BitSet needs to be large enough for ports 0..=65535
        let bitset = BitSet::with_capacity(65536);

        Self {
            active: true,
            total: 0,
            normalized_first_pick: 0,
            normalized_pick: 0,
            step: 0,
            ranges: Vec::new(),
            prefix: Vec::new(),
            serial_itr: Some(serial_itr_boxed),
            serial_itr_bitset: Some(bitset),
        }
    }
}
impl Iterator for RangeIterator {
    type Item = u16;

    /// Advance the iterator by one port.
    ///
    /// 1. Read the current normalized index `cur`.
    /// 2. Compute `next = (cur + step) % total` and update `normalized_pick`.
    /// 3. If `next == normalized_first_pick` mark `active = false` (we completed the cycle).
    /// 4. Map the returned index `cur` into the merged ranges via the prefix array:
    ///    - find the range index `idx` where `prefix[idx] <= cur < prefix[idx+1]`,
    ///    - offset = `cur - prefix[idx]`,
    ///    - port = `ranges[idx].0 + offset`.
    /// 5. Return `port as u16`.
    ///
    fn next(&mut self) -> Option<Self::Item> {
        if !self.active {
            return None;
        }

        // SERIAL iterator fast-path: preserve original input order but skip duplicates.
        if let (Some(it), Some(bitset)) =
            (self.serial_itr.as_mut(), self.serial_itr_bitset.as_mut())
        {
            while let Some(p) = it.next() {
                // `insert` returns true when the value was NOT present before.
                if bitset.insert(p as usize) {
                    return Some(p);
                }
                // otherwise skip duplicate and continue
            }
            // serial iterator exhausted: drop it and mark inactive
            self.serial_itr = None;
            self.serial_itr_bitset = None;
            self.active = false;
            return None;
        }

        // RANDOMIZED (LCG) path
        let cur = self.normalized_pick;
        let next = (cur + self.step) % self.total;

        // if next equals the original seed we finished the cycle after returning cur
        if next == self.normalized_first_pick {
            self.active = false;
        }

        self.normalized_pick = next;

        // Map cur -> port using prefix + ranges (binary search)
        let mut lo: usize = 0;
        let mut hi: usize = self.ranges.len();
        while lo < hi {
            let mid = (lo + hi) / 2;
            if self.prefix[mid + 1] > cur {
                hi = mid;
            } else {
                lo = mid + 1;
            }
        }
        let idx = lo;
        let offset = cur - self.prefix[idx];
        let (start, _len) = self.ranges[idx];
        let port = (start + offset)
            .try_into()
            .expect("Could not convert u32 to u16");
        Some(port)
    }
}

/// The probability that two random integers are coprime to one another
/// works out to be around 61%, given that we can safely pick a random
/// number and test it. Just in case we are having a bad day and we cannot
/// pick a coprime number after 10 tries we just return "end - 1" which
/// is guaranteed to be a coprime, but won't provide ideal randomization.
///
/// We pick between "lower_range" and "upper_range" since values too close to
/// the boundaries, which in these case are the "start" and "end" arguments
/// would also provide non-ideal randomization as discussed on the paragraph
/// above.
fn pick_random_coprime(end: u32) -> u32 {
    let range_boundary = end / 4;
    let lower_range = range_boundary;
    let upper_range = end - range_boundary;
    let mut rng = rand::rng();
    let mut candidate = rng.random_range(lower_range..upper_range);

    for _ in 0..10 {
        if end.gcd(candidate) == 1 {
            return candidate;
        }
        candidate = rng.random_range(lower_range..upper_range);
    }

    end - 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    // Helper: collect, sort and return ports produced by randomized RangeIterator
    fn generate_sorted_from_ranges_random(input: &[(u16, u16)]) -> Vec<u16> {
        let mut it = RangeIterator::new_random(input);
        let mut v: Vec<u16> = it.by_ref().collect();
        v.sort_unstable();
        v
    }

    // Helper: collect, sort and return ports produced by serial RangeIterator
    fn generate_sorted_from_ranges_serial(input: &[(u16, u16)]) -> Vec<u16> {
        let mut it = RangeIterator::new_serial(input);
        let mut v: Vec<u16> = it.by_ref().collect();
        v.sort_unstable();
        v
    }

    // Build expected sorted unique ports from input ranges (inclusive)
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
    fn random_range_iterator_test() {
        // small disjoint ranges
        let input = &[(1u16, 10u16), (20u16, 30u16), (100u16, 110u16)];
        let result = generate_sorted_from_ranges_random(input);
        let expected = expected_ports_from_ranges(input);
        assert_eq!(expected, result);

        // larger disjoint ranges
        let input = &[(1u16, 100u16), (200u16, 500u16)];
        let result = generate_sorted_from_ranges_random(input);
        let expected = expected_ports_from_ranges(input);
        assert_eq!(expected, result);

        // overlapping and adjacent
        let input = &[(10u16, 20u16), (15u16, 25u16), (26u16, 30u16)];
        let result = generate_sorted_from_ranges_random(input);
        let expected = expected_ports_from_ranges(input);
        assert_eq!(expected, result);

        // near-full domain (heavy): we only assert lengths & equality
        let input = &[(1u16, 65_535u16)];
        let result = generate_sorted_from_ranges_random(input);
        let expected = expected_ports_from_ranges(input);
        assert_eq!(expected.len(), result.len());
        assert_eq!(expected, result);

        // multiple disjoint ranges - check dedupe & coverage
        let input = &[(50u16, 100u16), (1000u16, 2000u16), (30000u16, 30010u16)];
        let result = generate_sorted_from_ranges_random(input);
        let set_len = result.iter().copied().collect::<HashSet<u16>>().len();
        assert_eq!(set_len, result.len());
        let expected = expected_ports_from_ranges(input);
        assert_eq!(expected, result);
    }

    #[test]
    fn serial_range_iterator_test() {
        // serial should preserve input-order semantics but here we only assert
        // coverage (no duplicates) by sorting results and comparing expected set.

        // small disjoint ranges
        let input = &[(1u16, 10u16), (20u16, 30u16), (100u16, 110u16)];
        let result = generate_sorted_from_ranges_serial(input);
        let expected = expected_ports_from_ranges(input);
        assert_eq!(expected, result);

        // overlapping and adjacent
        let input = &[(10u16, 20u16), (15u16, 25u16), (26u16, 30u16)];
        let result = generate_sorted_from_ranges_serial(input);
        let expected = expected_ports_from_ranges(input);
        assert_eq!(expected, result);

        // multiple disjoint ranges
        let input = &[(50u16, 100u16), (1000u16, 2000u16), (30000u16, 30010u16)];
        let result = generate_sorted_from_ranges_serial(input);
        let set_len = result.iter().copied().collect::<HashSet<u16>>().len();
        assert_eq!(set_len, result.len());
        let expected = expected_ports_from_ranges(input);
        assert_eq!(expected, result);

        // all possible inputs
        let input = &[(u16::MIN, u16::MAX)];
        let result = generate_sorted_from_ranges_serial(input);
        let set_len = result.iter().copied().collect::<HashSet<u16>>().len();
        assert_eq!(set_len, result.len());
        let expected = expected_ports_from_ranges(input);
        assert_eq!(expected, result);
    }
}
