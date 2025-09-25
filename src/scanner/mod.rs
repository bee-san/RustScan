//! Core functionality for actual scanning behaviour.
use crate::generated::get_parsed_data;
use crate::port_strategy::PortStrategy;
use log::debug;

mod socket_iterator;
use socket_iterator::SocketIterator;

use async_std::net::TcpStream;
use async_std::prelude::*;
use async_std::{io, net::UdpSocket};
use colored::Colorize;
use futures::stream::FuturesUnordered;
use std::collections::BTreeMap;
use std::{
    collections::HashSet,
    net::{IpAddr, Shutdown, SocketAddr},
    num::NonZeroU8,
    time::Duration,
};

/// High-performance TCP/UDP port scanner with concurrent connection handling.
///
/// The `Scanner` struct is the core component of RustScan, responsible for efficiently
/// discovering open ports on target networks. It implements an asynchronous, batched
/// scanning approach that can handle thousands of concurrent connections.
///
/// ## Features
///
/// - **Concurrent Scanning**: Uses configurable batch sizes for optimal performance
/// - **Protocol Support**: Both TCP and UDP port scanning capabilities  
/// - **Retry Logic**: Configurable retry attempts for unreliable networks
/// - **Timeout Handling**: Precise timeout control for connection attempts
/// - **Port Exclusion**: Ability to exclude specific ports from scanning
/// - **Output Modes**: Support for greppable and accessibility-compliant output
/// - **IPv6 Support**: Full support for IPv6 addresses and networks
///
/// ## Performance Considerations
///
/// The scanner's performance is primarily controlled by three parameters:
///
/// - `batch_size`: Number of concurrent connections (limited by system ulimit)
/// - `timeout`: Connection timeout duration (balance speed vs accuracy)
/// - `tries`: Number of retry attempts per port (reliability vs speed)
///
/// ## Examples
///
/// ### Basic TCP Scan
/// ```rust
/// use rustscan::scanner::Scanner;
/// use rustscan::input::{PortRange, ScanOrder};
/// use rustscan::port_strategy::PortStrategy;
/// use std::{net::IpAddr, time::Duration};
/// use async_std::task::block_on;
///
/// let targets = vec!["127.0.0.1".parse().unwrap()];
/// let range = PortRange { start: 80, end: 443 };
/// let strategy = PortStrategy::pick(&Some(range), None, ScanOrder::Serial);
///
/// let scanner = Scanner::new(
///     &targets,
///     100,                        // Batch size
///     Duration::from_millis(200), // Timeout
///     2,                          // Retries
///     false,                      // Show output
///     strategy,
///     true,                       // Accessible mode
///     vec![],                     // No exclusions
///     false,                      // TCP scan
/// );
///
/// let results = block_on(scanner.run());
/// println!("Found {} open ports", results.len());
/// ```
///
/// ### High-Performance Scan
/// ```rust
/// # use rustscan::scanner::Scanner;
/// # use rustscan::input::{PortRange, ScanOrder};
/// # use rustscan::port_strategy::PortStrategy;
/// # use std::{net::IpAddr, time::Duration};
/// # use async_std::task::block_on;
/// // Optimized for maximum speed
/// let targets = vec!["192.168.1.1".parse().unwrap()];
/// let range = PortRange { start: 1, end: 1000 };
/// let strategy = PortStrategy::pick(&Some(range), None, ScanOrder::Random);
///
/// let fast_scanner = Scanner::new(
///     &targets,
///     2000,                       // Large batch for speed
///     Duration::from_millis(50),  // Quick timeout
///     1,                          // Single attempt
///     true,                       // Quiet mode
///     strategy,
///     false,
///     vec![],
///     false,
/// );
/// ```
#[cfg(not(tarpaulin_include))]
#[derive(Debug)]
pub struct Scanner {
    ips: Vec<IpAddr>,
    batch_size: u16,
    timeout: Duration,
    tries: NonZeroU8,
    greppable: bool,
    port_strategy: PortStrategy,
    accessible: bool,
    exclude_ports: Vec<u16>,
    udp: bool,
}

// Allowing too many arguments for clippy.
#[allow(clippy::too_many_arguments)]
impl Scanner {
    pub fn new(
        ips: &[IpAddr],
        batch_size: u16,
        timeout: Duration,
        tries: u8,
        greppable: bool,
        port_strategy: PortStrategy,
        accessible: bool,
        exclude_ports: Vec<u16>,
        udp: bool,
    ) -> Self {
        Self {
            batch_size,
            timeout,
            tries: NonZeroU8::new(std::cmp::max(tries, 1)).unwrap(),
            greppable,
            port_strategy,
            ips: ips.iter().map(ToOwned::to_owned).collect(),
            accessible,
            exclude_ports,
            udp,
        }
    }

    /// Executes the port scan across all configured targets and ports.
    ///
    /// This is the main entry point for port scanning operations. It orchestrates
    /// the entire scanning process including batching, concurrency management,
    /// retry logic, and result collection.
    ///
    /// ## Process Flow
    ///
    /// 1. **Port Generation**: Creates port list from strategy, applying exclusions
    /// 2. **Socket Creation**: Generates socket addresses for all IP/port combinations
    /// 3. **Batch Processing**: Groups sockets into concurrent batches based on batch_size
    /// 4. **Connection Testing**: Attempts connections with timeout and retry logic
    /// 5. **Result Collection**: Aggregates all successful connections
    ///
    /// ## Performance Characteristics
    ///
    /// - **Time Complexity**: O(n*m/b) where n=ports, m=IPs, b=batch_size
    /// - **Memory Usage**: Scales with batch_size, not total target count
    /// - **Network Load**: Controlled by batch_size and timeout settings
    ///
    /// ## Returns
    ///
    /// Returns a `Vec<SocketAddr>` containing all discovered open ports.
    /// Each `SocketAddr` contains both the IP address and port number.
    ///
    /// ## Examples
    ///
    /// ```rust
    /// # use rustscan::scanner::Scanner;
    /// # use rustscan::input::{PortRange, ScanOrder};
    /// # use rustscan::port_strategy::PortStrategy;
    /// # use std::{net::IpAddr, time::Duration};
    /// # use async_std::task::block_on;
    /// let targets = vec!["127.0.0.1".parse().unwrap()];
    /// let range = PortRange { start: 22, end: 80 };
    /// let strategy = PortStrategy::pick(&Some(range), None, ScanOrder::Serial);
    ///
    /// let scanner = Scanner::new(
    ///     &targets, 50, Duration::from_millis(100), 1,
    ///     false, strategy, true, vec![], false
    /// );
    ///
    /// let open_ports = block_on(scanner.run());
    /// for socket in open_ports {
    ///     println!("Open: {}", socket);
    /// }
    /// ```
    ///
    /// ## Error Handling
    ///
    /// Connection errors are logged but don't stop the scan. The scanner
    /// continues processing remaining targets. Critical errors (like
    /// "too many open files") will cause a panic with guidance.
    ///
    /// ## Thread Safety
    ///
    /// This method is async and can be safely called from multiple tasks.
    /// However, each Scanner instance should only run one scan at a time.
    pub async fn run(&self) -> Vec<SocketAddr> {
        let ports: Vec<u16> = self
            .port_strategy
            .order()
            .iter()
            .filter(|&port| !self.exclude_ports.contains(port))
            .copied()
            .collect();
        let mut socket_iterator: SocketIterator = SocketIterator::new(&self.ips, &ports);
        let mut open_sockets: Vec<SocketAddr> = Vec::new();
        let mut ftrs = FuturesUnordered::new();
        let mut errors: HashSet<String> = HashSet::new();
        let udp_map = get_parsed_data();

        for _ in 0..self.batch_size {
            if let Some(socket) = socket_iterator.next() {
                ftrs.push(self.scan_socket(socket, udp_map.clone()));
            } else {
                break;
            }
        }

        debug!("Start scanning sockets. \nBatch size {}\nNumber of ip-s {}\nNumber of ports {}\nTargets all together {} ",
            self.batch_size,
            self.ips.len(),
            &ports.len(),
            (self.ips.len() * ports.len()));

        while let Some(result) = ftrs.next().await {
            if let Some(socket) = socket_iterator.next() {
                ftrs.push(self.scan_socket(socket, udp_map.clone()));
            }

            match result {
                Ok(socket) => open_sockets.push(socket),
                Err(e) => {
                    let error_string = e.to_string();
                    if errors.len() < self.ips.len() * 1000 {
                        errors.insert(error_string);
                    }
                }
            }
        }
        debug!("Typical socket connection errors {errors:?}");
        debug!("Open Sockets found: {:?}", &open_sockets);
        open_sockets
    }

    /// Attempts to connect to a single socket with retry logic.
    ///
    /// This method handles the core connection logic for both TCP and UDP protocols.
    /// It implements the retry mechanism and error handling for individual socket
    /// connections, routing to appropriate protocol-specific handlers.
    ///
    /// ## Parameters
    ///
    /// - `socket`: The target socket address (IP + port)
    /// - `udp_map`: UDP payload mapping for service-specific probes
    ///
    /// ## Retry Logic
    ///
    /// The method attempts connection up to `self.tries` times, with each attempt
    /// subject to the configured timeout. This handles transient network issues
    /// and improves scan reliability.
    ///
    /// ## Error Handling
    ///
    /// - **Resource Exhaustion**: "Too many open files" triggers panic with guidance
    /// - **Network Errors**: Logged and returned as `io::Error`
    /// - **Timeouts**: Treated as closed ports after retry exhaustion
    ///
    /// ## Returns
    ///
    /// - `Ok(SocketAddr)`: Port is open and responsive
    /// - `Err(io::Error)`: Port is closed or unreachable after all retries
    ///
    /// ## Protocol Routing
    ///
    /// - **TCP Mode** (`!self.udp`): Uses standard TCP connection logic
    /// - **UDP Mode** (`self.udp`): Uses UDP probe/response methodology
    ///
    /// ## Performance Notes
    ///
    /// This method is called concurrently up to `batch_size` times. The actual
    /// performance depends on network latency and target responsiveness.
    async fn scan_socket(
        &self,
        socket: SocketAddr,
        udp_map: BTreeMap<Vec<u16>, Vec<u8>>,
    ) -> io::Result<SocketAddr> {
        if self.udp {
            return self.scan_udp_socket(socket, udp_map).await;
        }

        let tries = self.tries.get();
        for nr_try in 1..=tries {
            match self.connect(socket).await {
                Ok(tcp_stream) => {
                    debug!(
                        "Connection was successful, shutting down stream {}",
                        &socket
                    );
                    if let Err(e) = tcp_stream.shutdown(Shutdown::Both) {
                        debug!("Shutdown stream error {}", &e);
                    }
                    self.fmt_ports(socket);

                    debug!("Return Ok after {nr_try} tries");
                    return Ok(socket);
                }
                Err(e) => {
                    let mut error_string = e.to_string();

                    assert!(!error_string.to_lowercase().contains("too many open files"), "Too many open files. Please reduce batch size. The default is 5000. Try -b 2500.");

                    if nr_try == tries {
                        error_string.push(' ');
                        error_string.push_str(&socket.ip().to_string());
                        return Err(io::Error::other(error_string));
                    }
                }
            };
        }
        unreachable!();
    }

    async fn scan_udp_socket(
        &self,
        socket: SocketAddr,
        udp_map: BTreeMap<Vec<u16>, Vec<u8>>,
    ) -> io::Result<SocketAddr> {
        let mut payload: Vec<u8> = Vec::new();
        for (key, value) in udp_map {
            if key.contains(&socket.port()) {
                payload = value;
            }
        }

        let tries = self.tries.get();
        for _ in 1..=tries {
            match self.udp_scan(socket, &payload, self.timeout).await {
                Ok(true) => return Ok(socket),
                Ok(false) => continue,
                Err(e) => return Err(e),
            }
        }

        Err(io::Error::other(format!(
            "UDP scan timed-out for all tries on socket {socket}"
        )))
    }

    /// Establishes a TCP connection to the specified socket with timeout control.
    ///
    /// This is the core TCP connection method that handles the actual socket
    /// connection attempt. It wraps the async TCP connection in a timeout to
    /// prevent hanging on unresponsive targets.
    ///
    /// ## Timeout Behavior
    ///
    /// The connection attempt is bounded by `self.timeout`. If the target doesn't
    /// respond within this timeframe, the connection is considered failed.
    /// This prevents the scanner from hanging on filtered or blackholed ports.
    ///
    /// ## Connection Process
    ///
    /// 1. Initiates async TCP connection to target socket
    /// 2. Applies configured timeout wrapper
    /// 3. Returns established stream or timeout error
    ///
    /// ## Parameters
    ///
    /// - `socket`: Target socket address combining IP and port
    ///
    /// ## Returns
    ///
    /// - `Ok(TcpStream)`: Successful connection established
    /// - `Err(io::Error)`: Connection failed or timed out
    ///
    /// ## Examples
    ///
    /// ```rust
    /// # use std::net::SocketAddr;
    /// # use std::time::Duration;
    /// # use async_std::net::TcpStream;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // This is an internal method, typically called from scan_socket()
    /// let socket: SocketAddr = "127.0.0.1:80".parse()?;
    /// // let stream = scanner.connect(socket).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// ## Error Types
    ///
    /// - **Timeout**: Target didn't respond within configured timeout
    /// - **Connection Refused**: Target actively rejected connection
    /// - **Network Unreachable**: Routing issues to target
    /// - **Host Unreachable**: Target host is down or filtered
    ///
    async fn connect(&self, socket: SocketAddr) -> io::Result<TcpStream> {
        let stream = io::timeout(
            self.timeout,
            async move { TcpStream::connect(socket).await },
        )
        .await?;
        Ok(stream)
    }

    /// Creates a local UDP socket for sending probes to target addresses.
    ///
    /// This method establishes the local UDP socket that will be used to send
    /// service-specific probes to target UDP ports. It automatically selects
    /// the appropriate local address family (IPv4 or IPv6) based on the target.
    ///
    /// ## Address Family Handling
    ///
    /// - **IPv4 targets**: Binds to `0.0.0.0:0` (any IPv4 address, ephemeral port)
    /// - **IPv6 targets**: Binds to `[::]:0` (any IPv6 address, ephemeral port)
    ///
    /// The operating system automatically assigns an available ephemeral port
    /// for the local binding.
    ///
    /// ## Parameters
    ///
    /// - `socket`: Target socket address (used only for family determination)
    ///
    /// ## Returns
    ///
    /// - `Ok(UdpSocket)`: Successfully bound local UDP socket
    /// - `Err(io::Error)`: Failed to bind to local address
    ///
    /// ## Usage Flow
    ///
    /// 1. Called from `udp_scan()` method
    /// 2. Creates appropriate local socket for target family
    /// 3. Socket is used for bidirectional UDP communication
    /// 4. Automatically cleaned up when dropped
    ///
    /// ## Network Requirements
    ///
    /// Requires available UDP socket descriptors and appropriate network
    /// permissions for socket creation.
    ///
    async fn udp_bind(&self, socket: SocketAddr) -> io::Result<UdpSocket> {
        let local_addr = match socket {
            SocketAddr::V4(_) => "0.0.0.0:0".parse::<SocketAddr>().unwrap(),
            SocketAddr::V6(_) => "[::]:0".parse::<SocketAddr>().unwrap(),
        };

        UdpSocket::bind(local_addr).await
    }

    /// Executes a UDP port scan using service-specific payloads.
    ///
    /// UDP port scanning is inherently more complex than TCP scanning because
    /// UDP is connectionless. This method implements an active probing approach,
    /// sending service-specific payloads and analyzing responses to determine
    /// port state.
    ///
    /// ## Scanning Methodology
    ///
    /// 1. **Payload Selection**: Uses service-specific probe data for the target port
    /// 2. **Socket Creation**: Establishes local UDP socket for communication
    /// 3. **Probe Transmission**: Sends crafted payload to target port
    /// 4. **Response Analysis**: Waits for response within timeout window
    /// 5. **State Determination**: Response indicates open port, timeout suggests filtered/closed
    ///
    /// ## Service-Specific Probing
    ///
    /// The method uses predefined payloads for common UDP services:
    /// - DNS (53): DNS query packets
    /// - NTP (123): NTP time request
    /// - SNMP (161): SNMP community string probe
    /// - TFTP (69): TFTP read request
    ///
    /// ## Parameters
    ///
    /// - `socket`: Target UDP socket address
    /// - `payload`: Service-specific probe data
    /// - `wait`: Response timeout duration
    ///
    /// ## Returns
    ///
    /// - `Ok(true)`: Response received, port is open
    /// - `Ok(false)`: Timeout occurred, port likely filtered/closed
    /// - `Err(io::Error)`: Network error during scan
    ///
    /// ## Timeout Considerations
    ///
    /// UDP timeouts should be longer than TCP (typically 1-5 seconds) because:
    /// - UDP responses may be delayed
    /// - Network congestion affects UDP more
    /// - Some services have intentional delays
    ///
    /// ## False Positives/Negatives
    ///
    /// - **False Closed**: Firewall drops packets silently
    /// - **False Open**: ICMP unreachable not received
    /// - **Rate Limiting**: Target may throttle responses
    ///
    /// ## Examples
    ///
    /// ```rust
    /// # use std::net::SocketAddr;
    /// # use std::time::Duration;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let dns_server: SocketAddr = "8.8.8.8:53".parse()?;
    /// let dns_query = vec![0x12, 0x34, 0x01, 0x00]; // Simplified DNS query
    /// let timeout = Duration::from_secs(2);
    ///
    /// // This would be called internally by the scanner
    /// // let is_open = scanner.udp_scan(dns_server, &dns_query, timeout).await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn udp_scan(
        &self,
        socket: SocketAddr,
        payload: &[u8],
        wait: Duration,
    ) -> io::Result<bool> {
        match self.udp_bind(socket).await {
            Ok(udp_socket) => {
                let mut buf = [0u8; 1024];

                udp_socket.connect(socket).await?;
                udp_socket.send(payload).await?;

                match io::timeout(wait, udp_socket.recv(&mut buf)).await {
                    Ok(size) => {
                        debug!("Received {size} bytes");
                        self.fmt_ports(socket);
                        Ok(true)
                    }
                    Err(e) => {
                        if e.kind() == io::ErrorKind::TimedOut {
                            Ok(false)
                        } else {
                            Err(e)
                        }
                    }
                }
            }
            Err(e) => {
                println!("Err E binding sock {e:?}");
                Err(e)
            }
        }
    }

    /// Formats and displays discovered open ports according to output settings.
    ///
    /// This method handles the presentation of scan results, supporting multiple
    /// output formats based on configuration flags:
    ///
    /// ## Output Modes
    ///
    /// - **Greppable Mode** (`self.greppable = true`): No output during scan,
    ///   results printed only at completion for easier parsing
    /// - **Interactive Mode** (`self.greppable = false`): Real-time port discovery
    ///   output with optional color coding
    /// - **Accessible Mode** (`self.accessible = true`): Plain text output
    ///   compatible with screen readers and accessibility tools
    /// - **Standard Mode** (`self.accessible = false`): Color-coded output
    ///   using ANSI color codes for enhanced visibility
    ///
    /// ## Format Examples
    ///
    /// - Accessible: `"Open 192.168.1.1:80"`
    /// - Colorized: `"Open"` (in purple) + `"192.168.1.1:80"`
    /// - Greppable: (no output during scan)
    ///
    /// ## Parameters
    ///
    /// - `socket`: The open socket address to display
    ///
    /// ## Design Rationale
    ///
    /// The multi-format approach supports different use cases:
    /// - **Automation**: Greppable mode for script integration
    /// - **Accessibility**: A11Y compliance for inclusive design
    /// - **User Experience**: Visual enhancements for interactive use
    fn fmt_ports(&self, socket: SocketAddr) {
        if !self.greppable {
            if self.accessible {
                println!("Open {socket}");
            } else {
                println!("Open {}", socket.to_string().purple());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input::{PortRange, ScanOrder};
    use async_std::task::block_on;
    use std::{net::IpAddr, time::Duration};

    #[test]
    fn scanner_runs() {
        // Makes sure the program still runs and doesn't panic
        let addrs = vec!["127.0.0.1".parse::<IpAddr>().unwrap()];
        let range = PortRange {
            start: 1,
            end: 1_000,
        };
        let strategy = PortStrategy::pick(&Some(range), None, ScanOrder::Random);
        let scanner = Scanner::new(
            &addrs,
            10,
            Duration::from_millis(100),
            1,
            true,
            strategy,
            true,
            vec![9000],
            false,
        );
        block_on(scanner.run());
        // if the scan fails, it wouldn't be able to assert_eq! as it panicked!
        assert_eq!(1, 1);
    }
    #[test]
    fn ipv6_scanner_runs() {
        // Makes sure the program still runs and doesn't panic
        let addrs = vec!["::1".parse::<IpAddr>().unwrap()];
        let range = PortRange {
            start: 1,
            end: 1_000,
        };
        let strategy = PortStrategy::pick(&Some(range), None, ScanOrder::Random);
        let scanner = Scanner::new(
            &addrs,
            10,
            Duration::from_millis(100),
            1,
            true,
            strategy,
            true,
            vec![9000],
            false,
        );
        block_on(scanner.run());
        // if the scan fails, it wouldn't be able to assert_eq! as it panicked!
        assert_eq!(1, 1);
    }
    #[test]
    fn quad_zero_scanner_runs() {
        let addrs = vec!["0.0.0.0".parse::<IpAddr>().unwrap()];
        let range = PortRange {
            start: 1,
            end: 1_000,
        };
        let strategy = PortStrategy::pick(&Some(range), None, ScanOrder::Random);
        let scanner = Scanner::new(
            &addrs,
            10,
            Duration::from_millis(100),
            1,
            true,
            strategy,
            true,
            vec![9000],
            false,
        );
        block_on(scanner.run());
        assert_eq!(1, 1);
    }
    #[test]
    fn google_dns_runs() {
        let addrs = vec!["8.8.8.8".parse::<IpAddr>().unwrap()];
        let range = PortRange {
            start: 400,
            end: 445,
        };
        let strategy = PortStrategy::pick(&Some(range), None, ScanOrder::Random);
        let scanner = Scanner::new(
            &addrs,
            10,
            Duration::from_millis(100),
            1,
            true,
            strategy,
            true,
            vec![9000],
            false,
        );
        block_on(scanner.run());
        assert_eq!(1, 1);
    }
    #[test]
    fn infer_ulimit_lowering_no_panic() {
        // Test behaviour on MacOS where ulimit is not automatically lowered
        let addrs = vec!["8.8.8.8".parse::<IpAddr>().unwrap()];

        // mac should have this automatically scaled down
        let range = PortRange {
            start: 400,
            end: 600,
        };
        let strategy = PortStrategy::pick(&Some(range), None, ScanOrder::Random);
        let scanner = Scanner::new(
            &addrs,
            10,
            Duration::from_millis(100),
            1,
            true,
            strategy,
            true,
            vec![9000],
            false,
        );
        block_on(scanner.run());
        assert_eq!(1, 1);
    }

    #[test]
    fn udp_scan_runs() {
        // Makes sure the program still runs and doesn't panic
        let addrs = vec!["127.0.0.1".parse::<IpAddr>().unwrap()];
        let range = PortRange {
            start: 1,
            end: 1_000,
        };
        let strategy = PortStrategy::pick(&Some(range), None, ScanOrder::Random);
        let scanner = Scanner::new(
            &addrs,
            10,
            Duration::from_millis(100),
            1,
            true,
            strategy,
            true,
            vec![9000],
            true,
        );
        block_on(scanner.run());
        // if the scan fails, it wouldn't be able to assert_eq! as it panicked!
        assert_eq!(1, 1);
    }
    #[test]
    fn udp_ipv6_runs() {
        // Makes sure the program still runs and doesn't panic
        let addrs = vec!["::1".parse::<IpAddr>().unwrap()];
        let range = PortRange {
            start: 1,
            end: 1_000,
        };
        let strategy = PortStrategy::pick(&Some(range), None, ScanOrder::Random);
        let scanner = Scanner::new(
            &addrs,
            10,
            Duration::from_millis(100),
            1,
            true,
            strategy,
            true,
            vec![9000],
            true,
        );
        block_on(scanner.run());
        // if the scan fails, it wouldn't be able to assert_eq! as it panicked!
        assert_eq!(1, 1);
    }
    #[test]
    fn udp_quad_zero_scanner_runs() {
        let addrs = vec!["0.0.0.0".parse::<IpAddr>().unwrap()];
        let range = PortRange {
            start: 1,
            end: 1_000,
        };
        let strategy = PortStrategy::pick(&Some(range), None, ScanOrder::Random);
        let scanner = Scanner::new(
            &addrs,
            10,
            Duration::from_millis(100),
            1,
            true,
            strategy,
            true,
            vec![9000],
            true,
        );
        block_on(scanner.run());
        assert_eq!(1, 1);
    }
    #[test]
    fn udp_google_dns_runs() {
        let addrs = vec!["8.8.8.8".parse::<IpAddr>().unwrap()];
        let range = PortRange {
            start: 100,
            end: 150,
        };
        let strategy = PortStrategy::pick(&Some(range), None, ScanOrder::Random);
        let scanner = Scanner::new(
            &addrs,
            10,
            Duration::from_millis(100),
            1,
            true,
            strategy,
            true,
            vec![9000],
            true,
        );
        block_on(scanner.run());
        assert_eq!(1, 1);
    }
}
