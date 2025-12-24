//! Provides functions to parse input IP addresses, CIDRs or files.

use std::borrow::Cow;
use std::iter;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::str::FromStr;

use cidr_utils::cidr::IpCidr;
use either::Either;
use futures_lite::{stream, Stream};
use futures_util::StreamExt as _;
use hickory_resolver::{
    config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
};
use itertools::Itertools;
use tokio::{fs, io};
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, BufReader};
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
pub async fn parse_addresses(input: &Opts) -> Vec<IpAddr> {
    let backup_resolver = &get_resolver(&input.resolver).await;

    stream::iter(input.addresses.iter())
        .map(move |address| {
            let address = address.as_str();
            async move {
                (parse_address(Cow::Borrowed(address), backup_resolver).await, address)
            }
        })
        .buffer_unordered(10)
        .map(|(adresses, addr)| async move {
            let mut adresses = adresses.peekable();
            'file_lookup: {
                if adresses.peek().is_none() {
                    let Ok(file) = File::open(addr).await else {
                        warning!(
                            format!("Host {addr:?} could not be resolved."),
                            input.greppable,
                            input.accessible
                        );
                        break 'file_lookup
                    };

                    return read_ips_from_file(file, backup_resolver).boxed()
                }
            }

            stream::iter(adresses).boxed()
        })
        .buffer_unordered(10)
        .flat_map_unordered(None, |stream| stream)
        .collect()
        .await
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
/// let ips = parse_address("127.0.0.1", &Resolver::default().unwrap());
/// ```
pub async fn parse_address<'a>(address: Cow<'a, str>, resolver: &'a TokioAsyncResolver) -> impl Iterator<Item=IpAddr> + use<'a> {
    match IpCidr::from_str(&address) {
        Ok(cidr) => Either::Left(cidr.iter().map(|c| c.address())),
        Err(_) => Either::Right(resolve_ips_from_host(address, resolver).await),
    }
}

/// Uses DNS to get the IPS associated with host
async fn resolve_ips_from_host<'a>(source: Cow<'a, str>, backup_resolver: &'a TokioAsyncResolver) -> impl Iterator<Item=IpAddr> + use<'a> {
    if let Ok(addrs) = tokio::net::lookup_host((&*source, 80)).await {
        Either::Left(addrs.into_iter().map(|x| x.ip()).collect_vec().into_iter())
    } else if let Ok(addrs) = backup_resolver.lookup_ip(&*source).await {
        Either::Left(addrs.iter().collect_vec().into_iter())
    } else {
        Either::Right(iter::empty())
    }
}

/// Derive a DNS resolver.
///
/// 1. if the `resolver` parameter has been set:
///     1. assume the parameter is a path and attempt to read IPs.
///     2. parse the input as a comma-separated list of IPs.
/// 2. if `resolver` is not set:
///    1. attempt to derive a resolver from the system config. (e.g.
///       `/etc/resolv.conf` on *nix).
///    2. finally, build a CloudFlare-based resolver (default
///       behaviour).
async fn get_resolver(resolver: &Option<String>) -> TokioAsyncResolver {
    match resolver {
        Some(r) => {
            let mut config = ResolverConfig::new();
            let resolver_ips = match read_resolver_from_file(r).await {
                Ok(ips) => ips,
                Err(_) => r
                    .split(',')
                    .filter_map(|r| IpAddr::from_str(r).ok())
                    .collect::<Vec<_>>(),
            };
            for ip in resolver_ips {
                config.add_name_server(NameServerConfig::new(
                    SocketAddr::new(ip, 53),
                    Protocol::Udp,
                ));
            }
            TokioAsyncResolver::tokio(config, ResolverOpts::default())
        }
        None => TokioAsyncResolver::tokio_from_system_conf().unwrap_or_else(|_| {
            TokioAsyncResolver::tokio(ResolverConfig::cloudflare_tls(), ResolverOpts::default())
        }),
    }
}

/// Parses and input file of IPs for use in DNS resolution.
async fn read_resolver_from_file(path: &str) -> io::Result<Vec<IpAddr>> {
    let ips = fs::read_to_string(path).await?
        .lines()
        .filter_map(|line| IpAddr::from_str(line.trim()).ok())
        .collect();

    Ok(ips)
}

/// Parses an input file of IPs and uses those
fn read_ips_from_file(
    ips: File,
    backup_resolver: &TokioAsyncResolver,
) -> impl Stream<Item=IpAddr> + use<'_> {
    let stream = stream::once_future(async move {
        let reader = BufReader::new(ips);
        let mut lines = reader.lines();
        let stream = stream::poll_fn(move |cx| {
            Pin::new(&mut lines)
                .poll_next_line(cx)
                .map(Result::ok)
                .map(Option::flatten)
        });

        stream
            .map(move |address_line| async move {
                resolve_ips_from_host(address_line.into(), backup_resolver).await
            })
            .buffer_unordered(4)
            .map(stream::iter)
            .flatten()
    });

    stream.flatten()
}

#[cfg(test)]
mod tests {
    use super::{get_resolver, parse_addresses, Opts};
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn parse_correct_addresses() {
        let opts = Opts {
            addresses: vec!["127.0.0.1".to_owned(), "192.168.0.0/30".to_owned()],
            ..Opts::default()
        };
        let ips = parse_addresses(&opts).await;

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

    #[tokio::test]
    async fn parse_correct_host_addresses() {
        let opts = Opts {
            addresses: vec!["google.com".to_owned()],
            ..Opts::default()
        };
        let ips = parse_addresses(&opts).await;

        assert_eq!(ips.len(), 1);
    }

    #[tokio::test]
    async fn parse_correct_and_incorrect_addresses() {
        let opts = Opts {
            addresses: vec!["127.0.0.1".to_owned(), "im_wrong".to_owned()],
            ..Opts::default()
        };
        let ips = parse_addresses(&opts).await;

        assert_eq!(ips, [Ipv4Addr::new(127, 0, 0, 1),]);
    }

    #[tokio::test]
    async fn parse_incorrect_addresses() {
        let opts = Opts {
            addresses: vec!["im_wrong".to_owned(), "300.10.1.1".to_owned()],
            ..Opts::default()
        };
        let ips = parse_addresses(&opts).await;

        assert!(ips.is_empty());
    }

    #[tokio::test]
    async fn parse_hosts_file_and_incorrect_hosts() {
        // Host file contains IP, Hosts, incorrect IPs, incorrect hosts
        let opts = Opts {
            addresses: vec!["fixtures/hosts.txt".to_owned()],
            ..Opts::default()
        };
        let ips = parse_addresses(&opts).await;
        assert_eq!(ips.len(), 3);
    }

    #[tokio::test]
    async fn parse_empty_hosts_file() {
        // Host file contains IP, Hosts, incorrect IPs, incorrect hosts
        let opts = Opts {
            addresses: vec!["fixtures/empty_hosts.txt".to_owned()],
            ..Opts::default()
        };
        let ips = parse_addresses(&opts).await;
        assert!(ips.is_empty());
    }

    #[tokio::test]
    async fn parse_naughty_host_file() {
        // Host file contains IP, Hosts, incorrect IPs, incorrect hosts
        let opts = Opts {
            addresses: vec!["fixtures/naughty_string.txt".to_owned()],
            ..Opts::default()
        };
        let ips = parse_addresses(&opts).await;
        assert!(ips.is_empty());
    }

    #[tokio::test]
    async fn resolver_default_cloudflare() {
        let opts = Opts::default();

        let resolver = get_resolver(&opts.resolver).await;
        let lookup = resolver.lookup_ip("www.example.com.").await.unwrap();

        assert!(opts.resolver.is_none());
        assert!(lookup.iter().next().is_some());
    }

    #[tokio::test]
    async fn resolver_args_google_dns() {
        let opts = Opts {
            addresses: vec!["fixtures/naughty_string.txt".to_owned()],
            // https://developers.google.com/speed/public-dns
            resolver: Some("8.8.8.8,8.8.4.4".to_owned()),
            ..Opts::default()
        };

        let resolver = get_resolver(&opts.resolver).await;
        let lookup = resolver.lookup_ip("www.example.com.").await.unwrap();

        assert!(lookup.iter().next().is_some());
    }
}
