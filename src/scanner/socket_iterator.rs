use itertools::{iproduct, Product};
use std::iter::FusedIterator;
use std::net::{IpAddr, SocketAddr};
use std::slice;

/// An iterator that receives a slice of IPs and ports and returns a
/// [`SocketAddr`] for each IP/port pair until all combinations are exhausted.
///
/// The goal of this iterator is to walk every IP and port combination
/// *without* allocating a big intermediate buffer — the alternative would be
/// materialising a `Vec<SocketAddr>` of every pair up front.
///
/// # Ordering
///
/// The IP/port order is intentionally reversed inside `product_it`: we want
/// `iproduct!` to iterate *all IPs for one port* before advancing to the next
/// port ("hold the port, go through all the IPs, then advance the port").
///
/// # Example
///
/// ```
/// # use std::net::IpAddr;
/// # use your_crate::SocketIterator;
/// let ips = [
///     "127.0.0.1".parse::<IpAddr>().unwrap(),
///     "192.168.0.1".parse::<IpAddr>().unwrap(),
/// ];
/// let ports = [80u16, 443];
///
/// let mut it = SocketIterator::new(&ips, &ports);
/// assert_eq!(it.next(), Some("127.0.0.1:80".parse().unwrap()));
/// assert_eq!(it.next(), Some("192.168.0.1:80".parse().unwrap()));
/// assert_eq!(it.next(), Some("127.0.0.1:443".parse().unwrap()));
/// assert_eq!(it.next(), Some("192.168.0.1:443".parse().unwrap()));
/// assert_eq!(it.next(), None);
/// ```
#[derive(Clone)]
pub struct SocketIterator<'s> {
    // No boxing: the iterator owns the concrete slice iterators directly.
    // This keeps `SocketIterator` allocation-free and makes `Clone` free too.
    product_it: Product<slice::Iter<'s, u16>, slice::Iter<'s, IpAddr>>,
}

impl<'s> SocketIterator<'s> {
    pub fn new(ips: &'s [IpAddr], ports: &'s [u16]) -> Self {
        Self {
            // `iproduct!` calls `.into_iter()` on each argument; `slice::Iter`
            // is already an iterator, so this is a no-op (no allocation).
            product_it: iproduct!(ports.iter(), ips.iter()),
        }
    }
}

impl Iterator for SocketIterator<'_> {
    type Item = SocketAddr;

    /// Returns the next socket, or `None` when all combinations are exhausted.
    /// Every IP is paired with the same port until the port advances.
    fn next(&mut self) -> Option<Self::Item> {
        self.product_it
            .next()
            .map(|(port, ip)| SocketAddr::new(*ip, *port))
    }

    // Delegate the size hint so callers like `collect()` can pre-size buffers.
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.product_it.size_hint()
    }
}

// `Product` and `slice::Iter` are both fused, so we are too.
impl FusedIterator for SocketIterator<'_> {}

#[cfg(test)]
mod tests {
    use super::SocketIterator;
    use std::net::{IpAddr, SocketAddr};

    #[test]
    fn goes_through_every_ip_port_combination() {
        let addrs = vec![
            "127.0.0.1".parse::<IpAddr>().unwrap(),
            "192.168.0.1".parse::<IpAddr>().unwrap(),
        ];
        let ports: Vec<u16> = vec![22, 80, 443];
        let mut it = SocketIterator::new(&addrs, &ports);

        assert_eq!(Some(SocketAddr::new(addrs[0], ports[0])), it.next());
        assert_eq!(Some(SocketAddr::new(addrs[1], ports[0])), it.next());
        assert_eq!(Some(SocketAddr::new(addrs[0], ports[1])), it.next());
        assert_eq!(Some(SocketAddr::new(addrs[1], ports[1])), it.next());
        assert_eq!(Some(SocketAddr::new(addrs[0], ports[2])), it.next());
        assert_eq!(Some(SocketAddr::new(addrs[1], ports[2])), it.next());
        assert_eq!(None, it.next());
    }

    #[test]
    fn size_hint_is_exact() {
        let addrs = ["127.0.0.1".parse::<IpAddr>().unwrap()];
        let ports: Vec<u16> = vec![22, 80, 443];
        let mut it = SocketIterator::new(&addrs, &ports);

        assert_eq!(it.size_hint(), (3, Some(3)));
        it.next();
        assert_eq!(it.size_hint(), (2, Some(2)));
    }

    #[test]
    fn clone_resumes_independently() {
        let addrs = [
            "127.0.0.1".parse::<IpAddr>().unwrap(),
            "192.168.0.1".parse::<IpAddr>().unwrap(),
        ];
        let ports: Vec<u16> = vec![22, 80];

        let mut a = SocketIterator::new(&addrs, &ports);
        a.next(); // consume one
        let mut b = a.clone(); // b starts where a is now

        assert_eq!(a.next(), b.next());
        assert_eq!(a.next(), b.next());
        assert_eq!(a.next(), None);
        assert_eq!(b.next(), None);
    }
}
