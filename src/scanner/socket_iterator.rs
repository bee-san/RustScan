use itertools::{iproduct, Product};
use std::net::{IpAddr, SocketAddr};

pub struct SocketIterator<'s, I: Iterator<Item=u16>> {
    // product_it is a cartesian product iterator over
    // the slices of ports and IP addresses.
    //
    // The IP/port order is intentionally reversed here since we want
    // the itertools::iproduct! macro below to generate the pairs with
    // all the IPs for one port before moving on to the next one
    // ("hold the port, go through all the IPs, then advance the port...").
    // See also the comments in the iterator implementation for an example.
    product_it: Product<I, std::slice::Iter<'s, IpAddr>>,
}

/// An iterator that receives a slice of IPs and ports and returns a Socket
/// for each IP and port pair until all of these combinations are exhausted.
/// The goal of this iterator is to go over every IP and port combination
/// without generating a big memory footprint. The alternative would be
/// generating a vector containing all these combinations.
impl<'s, I: Iterator<Item=u16>> SocketIterator<'s, I> {
    pub fn new(ips: &'s [IpAddr], ports: I) -> Self {
        Self {
            product_it: iproduct!(ports, ips.iter()),
        }
    }
}

impl<'s, I: Iterator<Item=u16>> Iterator for SocketIterator<'s, I> {
    type Item = SocketAddr;

    /// Returns a socket based on the combination of one of the provided
    /// IPs and ports or None when these combinations are exhausted. Every
    /// IP will have the same port until a port is incremented.
    /// ```ignore
    /// # use std::net::IpAddr;
    /// let it = SocketIterator::new(&["127.0.0.1", "192.168.0.1"], &[80, 443]);
    /// let sock = |ip: &str| -> IpAddr { ip.parse().unwrap() };
    /// assert_eq!(it.next(), Some(sock("127.0.0.1:80")));
    /// assert_eq!(it.next(), Some(sock("192.168.0.1:80")));
    /// assert_eq!(it.next(), Some(sock("127.0.0.1:443")));
    /// assert_eq!(it.next(), Some(sock("192.168.0.1:443")));
    /// assert_eq!(it.next(), None);
    /// ```
    fn next(&mut self) -> Option<Self::Item> {
        self.product_it
            .next()
            .map(|(port, &ip)| SocketAddr::new(ip, port))
    }
}

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
        let mut it = SocketIterator::new(&addrs, ports.iter().copied());

        assert_eq!(Some(SocketAddr::new(addrs[0], ports[0])), it.next());
        assert_eq!(Some(SocketAddr::new(addrs[1], ports[0])), it.next());
        assert_eq!(Some(SocketAddr::new(addrs[0], ports[1])), it.next());
        assert_eq!(Some(SocketAddr::new(addrs[1], ports[1])), it.next());
        assert_eq!(Some(SocketAddr::new(addrs[0], ports[2])), it.next());
        assert_eq!(Some(SocketAddr::new(addrs[1], ports[2])), it.next());
        assert_eq!(None, it.next());
    }
}
