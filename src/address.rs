//! Provides functions to parse input IP addresses, CIDRs or files.
use std::fs::{self, File};
use std::io::{prelude::*, BufReader};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::str::FromStr;

use cidr_utils::cidr::IpCidr;
use hickory_resolver::{
    config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts},
    Resolver,
};
use log::debug;

use crate::input::Opts;
use crate::warning;

/// Parses the string(s) into IP addresses.
///
/// Goes through all possible IP inputs (files or via argparsing).
///
/// ```rust
/// # use rustscan::input::Opts;
/// # use rustscan::address::parse_addresses;
/// let mut opts = Opts::default();
/// opts.addresses = vec!["192.168.0.0/30".to_owned()];
///
/// let ips = parse_addresses(&opts);
/// ```
pub fn parse_addresses(input: &Opts) -> Vec<IpAddr> {
    let mut ips: Vec<IpAddr> = Vec::new();
    let mut unresolved_addresses: Vec<&str> = Vec::new();
    let mut self_resolve = true;
    let mut backup_resolver =
        Resolver::new(ResolverConfig::cloudflare_tls(), ResolverOpts::default()).unwrap();

    if input.resolver.ne("") {
        let resolver_ips = if let Ok(r) = read_resolver_from_file(input.resolver.as_str()) {
            r
        } else {
            // Get resolvers from the comma-delimited list string
            let mut r = Vec::new();
            input.resolver.split(',').for_each(|item| {
                if let Ok(ip) = IpAddr::from_str(item) {
                    r.push(ip)
                }
            });
            r
        };
        let mut rc = ResolverConfig::new();
        for ip in resolver_ips {
            rc.add_name_server(NameServerConfig::new(
                SocketAddr::new(ip, 53),
                Protocol::Udp,
            ));
        }
        backup_resolver = Resolver::new(rc, ResolverOpts::default()).unwrap();
        self_resolve = false;
    }

    for address in &input.addresses {
        let parsed_ips = parse_address(address, &backup_resolver, self_resolve);
        if !parsed_ips.is_empty() {
            ips.extend(parsed_ips);
        } else {
            unresolved_addresses.push(address);
        }
    }

    // If we got to this point this can only be a file path or the wrong input.
    for file_path in unresolved_addresses {
        let file_path = Path::new(file_path);

        if !file_path.is_file() {
            warning!(
                format!("Host {file_path:?} could not be resolved."),
                input.greppable,
                input.accessible
            );

            continue;
        }

        if let Ok(x) = read_ips_from_file(file_path, &backup_resolver, self_resolve) {
            ips.extend(x);
        } else {
            warning!(
                format!("Host {file_path:?} could not be resolved."),
                input.greppable,
                input.accessible
            );
        }
    }

    ips
}

/// Given a string, parse it as a host, IP address, or CIDR.
///
/// This allows us to pass files as hosts or cidr or IPs easily
/// Call this every time you have a possible IP-or-host.
///
/// If the address is a domain, we can self-resolve the domain locally
/// or resolve it by dns resolver list.
///
/// ```rust
/// # use rustscan::address::parse_address;
/// # use hickory_resolver::Resolver;
/// let ips = parse_address("127.0.0.1", &Resolver::default().unwrap(), false);
/// ```
pub fn parse_address(address: &str, resolver: &Resolver, self_resolve: bool) -> Vec<IpAddr> {
    IpCidr::from_str(address)
        .map(|cidr| cidr.iter().collect())
        .ok()
        .or_else(|| {
            if !self_resolve {
                // This will trigger `unwrap_or_else` then call `resolve_ips_from_host` function
                return None;
            };
            format!("{}:{}", &address, 80)
                .to_socket_addrs()
                .ok()
                .map(|mut iter| vec![iter.next().unwrap().ip()])
        })
        .unwrap_or_else(|| resolve_ips_from_host(address, resolver))
}

/// Uses DNS to get the IPS associated with host
fn resolve_ips_from_host(source: &str, backup_resolver: &Resolver) -> Vec<IpAddr> {
    let mut ips: Vec<std::net::IpAddr> = Vec::new();

    if let Ok(addrs) = source.to_socket_addrs() {
        for ip in addrs {
            ips.push(ip.ip());
        }
    } else if let Ok(addrs) = backup_resolver.lookup_ip(source) {
        ips.extend(addrs.iter());
    }

    ips
}

fn read_resolver_from_file(path: &str) -> Result<Vec<std::net::IpAddr>, std::io::Error> {
    let mut ips = Vec::new();
    fs::read_to_string(path)?.split('\n').for_each(|line| {
        if let Ok(ip) = IpAddr::from_str(line) {
            ips.push(ip)
        }
    });
    Ok(ips)
}

#[cfg(not(tarpaulin_include))]
/// Parses an input file of IPs and uses those
fn read_ips_from_file(
    ips: &std::path::Path,
    backup_resolver: &Resolver,
    self_resolve: bool,
) -> Result<Vec<std::net::IpAddr>, std::io::Error> {
    let file = File::open(ips)?;
    let reader = BufReader::new(file);

    let mut ips: Vec<std::net::IpAddr> = Vec::new();

    for address_line in reader.lines() {
        if let Ok(address) = address_line {
            ips.extend(parse_address(&address, backup_resolver, self_resolve));
        } else {
            debug!("Line in file is not valid");
        }
    }

    Ok(ips)
}

#[cfg(test)]
mod tests {
    use super::{parse_addresses, Opts};
    use std::net::Ipv4Addr;

    #[test]
    fn parse_correct_addresses() {
        let mut opts = Opts::default();
        opts.addresses = vec!["127.0.0.1".to_owned(), "192.168.0.0/30".to_owned()];
        let ips = parse_addresses(&opts);

        assert_eq!(
            ips,
            [
                Ipv4Addr::new(127, 0, 0, 1),
                Ipv4Addr::new(192, 168, 0, 0),
                Ipv4Addr::new(192, 168, 0, 1),
                Ipv4Addr::new(192, 168, 0, 2),
                Ipv4Addr::new(192, 168, 0, 3)
            ]
        );
    }

    #[test]
    fn parse_correct_host_addresses() {
        let mut opts = Opts::default();
        opts.addresses = vec!["google.com".to_owned()];
        let ips = parse_addresses(&opts);

        assert_eq!(ips.len(), 1);
    }

    #[test]
    fn parse_correct_and_incorrect_addresses() {
        let mut opts = Opts::default();
        opts.addresses = vec!["127.0.0.1".to_owned(), "im_wrong".to_owned()];
        let ips = parse_addresses(&opts);

        assert_eq!(ips, [Ipv4Addr::new(127, 0, 0, 1),]);
    }

    #[test]
    fn parse_incorrect_addresses() {
        let mut opts = Opts::default();
        opts.addresses = vec!["im_wrong".to_owned(), "300.10.1.1".to_owned()];
        let ips = parse_addresses(&opts);

        assert!(ips.is_empty());
    }
    #[test]
    fn parse_hosts_file_and_incorrect_hosts() {
        // Host file contains IP, Hosts, incorrect IPs, incorrect hosts
        let mut opts = Opts::default();
        opts.addresses = vec!["fixtures/hosts.txt".to_owned()];
        let ips = parse_addresses(&opts);
        assert_eq!(ips.len(), 3);
    }

    #[test]
    fn parse_empty_hosts_file() {
        // Host file contains IP, Hosts, incorrect IPs, incorrect hosts
        let mut opts = Opts::default();
        opts.addresses = vec!["fixtures/empty_hosts.txt".to_owned()];
        let ips = parse_addresses(&opts);
        assert_eq!(ips.len(), 0);
    }

    #[test]
    fn parse_naughty_host_file() {
        // Host file contains IP, Hosts, incorrect IPs, incorrect hosts
        let mut opts = Opts::default();
        opts.addresses = vec!["fixtures/naughty_string.txt".to_owned()];
        let ips = parse_addresses(&opts);
        assert_eq!(ips.len(), 0);
    }
}
