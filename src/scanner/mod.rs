//! Core functionality for actual scanning behaviour.
use crate::generated::get_parsed_data;
use crate::port_strategy::PortStrategy;
use crate::tui::println_safe;
use log::debug;

mod socket_iterator;
mod timeout;
use socket_iterator::SocketIterator;
use timeout::io_timeout;

use colored::Colorize;
use futures::{stream::FuturesUnordered, StreamExt};
use std::collections::BTreeMap;
use std::{
    collections::{HashMap, HashSet},
    future::Future,
    io,
    net::{IpAddr, Shutdown, SocketAddr},
    num::NonZeroU8,
    sync::Arc,
    time::Duration,
};
use tokio::net::{TcpStream, UdpSocket};

/// UDP payload lookup: port -> payload bytes
///
/// `get_parsed_data()` returns a `&'static BTreeMap<...>`, so we can store
/// references to the payload bytes without cloning them.
#[doc(hidden)]
pub type UdpPayloadLookup = HashMap<u16, &'static [u8]>;

#[doc(hidden)]
pub fn build_udp_payload_lookup(udp_map: &'static BTreeMap<Vec<u16>, Vec<u8>>) -> UdpPayloadLookup {
    let mut lookup: UdpPayloadLookup = HashMap::new();

    for (ports, payload_vec) in udp_map.iter() {
        let payload: &'static [u8] = payload_vec.as_slice();
        for &port in ports.iter() {
            // Preserve existing behavior: if duplicates exist, last insert wins.
            lookup.insert(port, payload);
        }
    }

    lookup
}

/// The class for the scanner
/// IP is data type IpAddr and is the IP address
/// start & end is where the port scan starts and ends
/// batch_size is how many ports at a time should be scanned
/// Timeout is the time RustScan should wait before declaring a port closed. As datatype Duration.
/// greppable is whether or not RustScan should print things, or wait until the end to print only the ip and open ports.
#[cfg(not(tarpaulin_include))]
#[derive(Debug)]
pub struct Scanner {
    ips: Vec<IpAddr>,
    batch_size: usize,
    timeout: Duration,
    tries: NonZeroU8,
    greppable: bool,
    port_strategy: PortStrategy,
    accessible: bool,
    exclude_ports: Vec<u16>,
    udp: bool,
    print_open_ports: bool,
    report_closed: bool,
    interval: Duration,
}

/// The outcome for a single socket, as returned by [`Scanner::run_with_status`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortStatus {
    /// The TCP connection succeeded, or the UDP target answered.
    Open(SocketAddr),
    /// The target actively refused the TCP connection (for example with a
    /// RST). Only reported when [`Scanner::with_closed_ports`] is enabled.
    Closed(SocketAddr),
}

// Allowing too many arguments for clippy.
#[allow(clippy::too_many_arguments)]
impl Scanner {
    pub fn new(
        ips: &[IpAddr],
        batch_size: usize,
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
            print_open_ports: false,
            report_closed: false,
            interval: Duration::ZERO,
        }
    }

    /// Enables the CLI's incremental open-port output.
    ///
    /// Library callers are quiet by default and can inspect the sockets returned by [`Self::run`].
    #[must_use]
    pub fn with_open_port_output(mut self) -> Self {
        self.print_open_ports = true;
        self
    }

    /// Also reports TCP ports that actively refuse the connection, as
    /// [`PortStatus::Closed`] from [`Self::run_with_status`].
    ///
    /// Ports that time out are still treated as filtered and are not reported.
    /// UDP scans never report closed ports.
    #[must_use]
    pub fn with_closed_ports(mut self) -> Self {
        self.report_closed = true;
        self
    }

    /// Waits `interval` after scanning one port (on every address) before
    /// scanning the next port, for slow, low-noise scans.
    ///
    /// Within a port, up to `batch_size` addresses are still scanned
    /// concurrently. A zero interval (the default) scans all sockets in
    /// batches without any delay.
    #[must_use]
    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    /// Runs scan_range with chunk sizes
    /// If you want to run RustScan normally, this is the entry point used
    /// Returns all open sockets.
    ///
    /// Must be awaited inside a Tokio runtime with I/O and time enabled.
    pub async fn run(&self) -> Vec<SocketAddr> {
        self.run_with_status()
            .await
            .into_iter()
            .filter_map(|status| match status {
                PortStatus::Open(socket) => Some(socket),
                PortStatus::Closed(_) => None,
            })
            .collect()
    }

    /// Like [`Self::run`], but returns the status of every socket that gave a
    /// definitive answer: open sockets, plus closed sockets when
    /// [`Self::with_closed_ports`] is enabled.
    ///
    /// Must be awaited inside a Tokio runtime with I/O and time enabled.
    pub async fn run_with_status(&self) -> Vec<PortStatus> {
        // Tokio's millisecond rounding adds about 1 ms to each short interval.
        // This cancellable delay keeps the requested spacing without blocking
        // the async runtime or accumulating that rounding on every port.
        self.run_with_delay(|interval| async move {
            async_io::Timer::after(interval).await;
        })
        .await
    }

    /// Supplying the delay lets tests verify spacing with a virtual clock.
    async fn run_with_delay<D, F>(&self, delay: D) -> Vec<PortStatus>
    where
        D: Fn(Duration) -> F,
        F: Future<Output = ()>,
    {
        let ports: Vec<u16> = self
            .port_strategy
            .order()
            .iter()
            .filter(|&port| !self.exclude_ports.contains(port))
            .copied()
            .collect();
        let mut found_sockets: Vec<PortStatus> = Vec::new();
        let mut errors: HashSet<String> = HashSet::new();

        // Build UDP payload lookup once (only if we are scanning UDP).
        // This avoids cloning a big map into every spawned future and turns
        // payload selection from O(n) to O(1).
        let udp_payloads: Option<Arc<UdpPayloadLookup>> = if self.udp {
            Some(Arc::new(build_udp_payload_lookup(get_parsed_data())))
        } else {
            None
        };

        debug!("Start scanning sockets. \nBatch size {}\nNumber of ip-s {}\nNumber of ports {}\nTargets all together {}\nInterval between ports {:?}",
            self.batch_size,
            self.ips.len(),
            ports.len(),
            (self.ips.len() * ports.len()),
            self.interval);

        if self.interval.is_zero() {
            let sockets = SocketIterator::new(&self.ips, &ports);
            self.scan_sockets(sockets, &udp_payloads, &mut found_sockets, &mut errors)
                .await;
        } else {
            // Scan one port (on every address) at a time and wait `interval`
            // before moving on to the next port.
            for (i, port) in ports.iter().enumerate() {
                if i > 0 {
                    delay(self.interval).await;
                }
                let sockets = SocketIterator::new(&self.ips, std::slice::from_ref(port));
                self.scan_sockets(sockets, &udp_payloads, &mut found_sockets, &mut errors)
                    .await;
            }
        }

        debug!("Typical socket connection errors {errors:?}");
        debug!("Sockets found: {:?}", found_sockets);
        found_sockets
    }

    /// Scans every socket yielded by `sockets`, keeping at most `batch_size`
    /// connection attempts in flight.
    async fn scan_sockets(
        &self,
        mut sockets: SocketIterator<'_>,
        udp_payloads: &Option<Arc<UdpPayloadLookup>>,
        found_sockets: &mut Vec<PortStatus>,
        errors: &mut HashSet<String>,
    ) {
        let mut ftrs = FuturesUnordered::new();

        for _ in 0..self.batch_size {
            if let Some(socket) = sockets.next() {
                ftrs.push(self.scan_socket(socket, udp_payloads.clone()));
            } else {
                break;
            }
        }

        while let Some(result) = ftrs.next().await {
            if let Some(socket) = sockets.next() {
                ftrs.push(self.scan_socket(socket, udp_payloads.clone()));
            }

            match result {
                Ok(status) => found_sockets.push(status),
                Err(e) => {
                    let error_string = e.to_string();
                    if errors.len() < self.ips.len() * 1000 {
                        errors.insert(error_string);
                    }
                }
            }
        }
    }

    /// Given a socket, scan it self.tries times.
    /// Turns the address into a SocketAddr
    /// Deals with the `<result>` type
    /// If it experiences error ErrorKind::Other then too many files are open and it Panics!
    /// Else any other error, it returns the error in Result as a string
    /// If no errors occur, it returns the port number in Result to signify the port is open.
    /// This function mainly deals with the logic of Results handling.
    /// # Example
    ///
    /// ```compile_fail
    /// scanner.scan_socket(socket)
    /// ```
    ///
    /// Note: `self` must contain `self.ip`.
    async fn scan_socket(
        &self,
        socket: SocketAddr,
        udp_payloads: Option<Arc<UdpPayloadLookup>>,
    ) -> io::Result<PortStatus> {
        if self.udp {
            return self.scan_udp_socket(socket, udp_payloads).await;
        }

        let tries = self.tries.get();
        for nr_try in 1..=tries {
            match self.connect(socket).await {
                Ok(tcp_stream) => {
                    debug!("Connection was successful, shutting down stream {}", socket);
                    if let Err(e) = tcp_stream
                        .into_std()
                        .and_then(|stream| stream.shutdown(Shutdown::Both))
                    {
                        debug!("Shutdown stream error {}", e);
                    }
                    self.fmt_ports(socket);

                    debug!("Return Ok after {nr_try} tries");
                    return Ok(PortStatus::Open(socket));
                }
                Err(e) => {
                    // A refused connection is a definitive answer, so there is
                    // no point in retrying it.
                    if self.report_closed && e.kind() == io::ErrorKind::ConnectionRefused {
                        self.fmt_closed_port(socket);
                        return Ok(PortStatus::Closed(socket));
                    }

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
        udp_payloads: Option<Arc<UdpPayloadLookup>>,
    ) -> io::Result<PortStatus> {
        let payload: &[u8] = udp_payloads
            .as_ref()
            .and_then(|m| m.get(&socket.port()).copied())
            .unwrap_or(b"");

        let tries = self.tries.get();
        for _ in 1..=tries {
            match self.udp_scan(socket, payload, self.timeout).await {
                Ok(true) => return Ok(PortStatus::Open(socket)),
                Ok(false) => continue,
                Err(e) => return Err(e),
            }
        }

        Err(io::Error::other(format!(
            "UDP scan timed-out for all tries on socket {socket}"
        )))
    }

    /// Performs the connection to the socket with timeout
    /// # Example
    ///
    /// ```compile_fail
    /// # use std::net::{IpAddr, Ipv6Addr, SocketAddr};
    /// let port: u16 = 80;
    /// // ip is an IpAddr type
    /// let ip = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
    /// let socket = SocketAddr::new(ip, port);
    /// scanner.connect(socket);
    /// // returns Result which is either Ok(stream) for port is open, or Er for port is closed.
    /// // Timeout occurs after self.timeout seconds
    /// ```
    ///
    async fn connect(&self, socket: SocketAddr) -> io::Result<TcpStream> {
        io_timeout(self.timeout, TcpStream::connect(socket)).await
    }

    /// Binds to a UDP socket so we can send and receive packets
    /// # Example
    ///
    /// ```compile_fail
    /// # use std::net::{IpAddr, Ipv6Addr, SocketAddr};
    /// let port: u16 = 80;
    /// // ip is an IpAddr type
    /// let ip = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
    /// let socket = SocketAddr::new(ip, port);
    /// scanner.udp_bind(socket);
    /// // returns Result which is either Ok(stream) for port is open, or Err for port is closed.
    /// // Timeout occurs after self.timeout seconds
    /// ```
    ///
    async fn udp_bind(&self, socket: SocketAddr) -> io::Result<UdpSocket> {
        let local_addr = match socket {
            SocketAddr::V4(_) => "0.0.0.0:0".parse::<SocketAddr>().unwrap(),
            SocketAddr::V6(_) => "[::]:0".parse::<SocketAddr>().unwrap(),
        };

        UdpSocket::bind(local_addr).await
    }

    /// Performs a UDP scan on the specified socket with a payload and wait duration
    /// # Example
    ///
    /// ```compile_fail
    /// # use std::net::{IpAddr, Ipv6Addr, SocketAddr};
    /// # use std::time::Duration;
    /// let port: u16 = 123;
    /// // ip is an IpAddr type
    /// let ip = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
    /// let socket = SocketAddr::new(ip, port);
    /// let payload = vec![0, 1, 2, 3];
    /// let wait = Duration::from_secs(1);
    /// let result = scanner.udp_scan(socket, payload, wait).await;
    /// // returns Result which is either Ok(true) if response received, or Ok(false) if timed out.
    /// // Err is returned for other I/O errors.
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

                match io_timeout(wait, udp_socket.recv(&mut buf)).await {
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
                debug!("Error binding UDP socket: {e:?}");
                Err(e)
            }
        }
    }

    /// Formats and prints the port status
    fn fmt_ports(&self, socket: SocketAddr) {
        if self.print_open_ports && !self.greppable {
            if self.accessible {
                println_safe(format_args!("Open {socket}"));
            } else {
                println_safe(format_args!("Open {}", socket.to_string().purple()));
            }
        }
    }

    /// Prints a closed port (CLI output only, never in greppable mode).
    fn fmt_closed_port(&self, socket: SocketAddr) {
        if self.print_open_ports && !self.greppable {
            if self.accessible {
                println_safe(format_args!("Closed {socket}"));
            } else {
                println_safe(format_args!("Closed {}", socket.to_string().red()));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::input::{PortRanges, ScanOrder};

    // These tests never open sockets: operations are simulated futures, and
    // scanners that run have no target addresses.

    fn test_runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .unwrap()
    }

    #[test]
    fn timeout_preserves_success_including_empty_udp_responses() {
        test_runtime().block_on(async {
            // A zero-byte UDP datagram is still a successful response.
            let result = io_timeout(Duration::from_secs(1), async { Ok(0_usize) }).await;
            assert_eq!(result.unwrap(), 0);
        });
    }

    #[test]
    fn timeout_preserves_io_errors() {
        test_runtime().block_on(async {
            for kind in [
                io::ErrorKind::ConnectionRefused,
                io::ErrorKind::PermissionDenied,
                io::ErrorKind::TimedOut,
            ] {
                let result = io_timeout(Duration::from_secs(1), async {
                    Err::<(), _>(io::Error::new(kind, "socket error"))
                })
                .await;

                let error = result.unwrap_err();
                assert_eq!(error.kind(), kind);
                assert_eq!(error.to_string(), "socket error");
            }
        });
    }

    #[test]
    fn ready_operation_wins_at_zero_timeout() {
        test_runtime().block_on(async {
            assert_eq!(
                io_timeout(Duration::ZERO, async { Ok(7) }).await.unwrap(),
                7
            );
        });
    }

    #[test]
    fn timeout_preserves_wakes_from_the_first_poll() {
        test_runtime().block_on(async {
            let mut polled = false;
            let operation = std::future::poll_fn(|context| {
                if polled {
                    std::task::Poll::Ready(Ok(7))
                } else {
                    polled = true;
                    context.waker().wake_by_ref();
                    std::task::Poll::Pending
                }
            });

            assert_eq!(
                io_timeout(Duration::from_secs(1), operation).await.unwrap(),
                7
            );
        });
    }

    #[test]
    fn expired_timeout_cancels_the_operation() {
        use std::cell::Cell;

        struct DropGuard<'a>(&'a Cell<bool>);

        impl Drop for DropGuard<'_> {
            fn drop(&mut self) {
                self.0.set(true);
            }
        }

        for duration in [Duration::from_millis(5), Duration::from_millis(80)] {
            test_runtime().block_on(async {
                let dropped = Cell::new(false);
                let started = std::time::Instant::now();
                let operation = async {
                    let _guard = DropGuard(&dropped);
                    std::future::pending::<io::Result<()>>().await
                };

                let error = io_timeout(duration, operation).await.unwrap_err();

                assert_eq!(error.kind(), io::ErrorKind::TimedOut);
                assert!(started.elapsed() >= duration);
                assert!(dropped.get(), "the timed-out operation must be dropped");
            });
        }
    }

    #[test]
    fn operation_can_complete_before_the_precise_timeout_phase() {
        test_runtime().block_on(async {
            let result = io_timeout(Duration::from_secs(1), async {
                tokio::time::sleep(Duration::from_millis(10)).await;
                Ok(7)
            })
            .await;

            assert_eq!(result.unwrap(), 7);
        });
    }

    #[test]
    fn interval_waits_only_between_included_ports() {
        test_runtime().block_on(async {
            let interval = Duration::from_millis(250);
            let mut scanner = test_scanner().with_interval(interval);
            scanner.ips.clear();
            scanner.port_strategy = PortStrategy::Manual(vec![80, 443, 8080, 8443]);
            scanner.exclude_ports = vec![443];
            let started = tokio::time::Instant::now();

            assert!(scanner.run_with_delay(tokio::time::sleep).await.is_empty());
            assert_eq!(started.elapsed(), interval * 2);
        });
    }

    #[test]
    fn dropping_a_scan_cancels_a_pending_interval() {
        use std::cell::Cell;
        use std::task::Poll;

        struct PendingDelay<'a>(&'a Cell<bool>);

        impl Future for PendingDelay<'_> {
            type Output = ();

            fn poll(self: std::pin::Pin<&mut Self>, _: &mut std::task::Context<'_>) -> Poll<()> {
                Poll::Pending
            }
        }

        impl Drop for PendingDelay<'_> {
            fn drop(&mut self) {
                self.0.set(true);
            }
        }

        test_runtime().block_on(async {
            let dropped = Cell::new(false);
            let mut scanner = test_scanner().with_interval(Duration::from_secs(3600));
            scanner.ips.clear();
            scanner.port_strategy = PortStrategy::Manual(vec![80, 443]);

            let mut scan = Box::pin(scanner.run_with_delay(|_| PendingDelay(&dropped)));
            assert!(futures::poll!(scan.as_mut()).is_pending());
            assert!(!dropped.get());
            drop(scan);
            assert!(dropped.get());
        });
    }

    #[test]
    fn zero_interval_and_empty_port_sets_do_not_wait() {
        test_runtime().block_on(async {
            let mut scanner = test_scanner();
            scanner.ips.clear();
            scanner.port_strategy = PortStrategy::Manual(vec![80, 443]);
            let started = tokio::time::Instant::now();

            assert!(scanner.run().await.is_empty());
            assert_eq!(started.elapsed(), Duration::ZERO);

            scanner = scanner.with_interval(Duration::from_secs(1));
            scanner.exclude_ports = vec![80, 443];
            assert!(scanner.run().await.is_empty());
            assert_eq!(started.elapsed(), Duration::ZERO);

            scanner.port_strategy = PortStrategy::Manual(Vec::new());
            assert!(scanner.run().await.is_empty());
            assert_eq!(started.elapsed(), Duration::ZERO);
        });
    }

    fn test_scanner() -> Scanner {
        let addrs = vec!["127.0.0.1".parse::<IpAddr>().unwrap()];
        let strategy = PortStrategy::pick(&Some(PortRanges(vec![(1, 1)])), None, ScanOrder::Serial);
        Scanner::new(
            &addrs,
            1,
            Duration::from_millis(100),
            1,
            false,
            strategy,
            false,
            Vec::new(),
            false,
        )
    }

    #[test]
    fn library_scanner_is_quiet_by_default() {
        let scanner = test_scanner();

        assert!(!scanner.print_open_ports);
    }

    #[test]
    fn cli_can_enable_open_port_output() {
        let scanner = test_scanner().with_open_port_output();

        assert!(scanner.print_open_ports);
    }

    #[test]
    fn closed_ports_are_not_reported_by_default() {
        assert!(!test_scanner().report_closed);
    }

    #[test]
    fn closed_port_reporting_is_opt_in() {
        assert!(test_scanner().with_closed_ports().report_closed);
    }

    #[test]
    fn no_interval_by_default() {
        assert!(test_scanner().interval.is_zero());
    }

    #[test]
    fn with_interval_sets_the_delay_between_ports() {
        let scanner = test_scanner().with_interval(Duration::from_millis(250));

        assert_eq!(scanner.interval, Duration::from_millis(250));
    }

    /// Regression test for https://github.com/bee-san/RustScan/issues/933:
    /// the SNMP public-walk probe must be the exact 33-byte BER packet, with
    /// the literal `public` community string intact. The old hexdigits-only
    /// decoding mangled it into a 28-byte probe that agents never answered.
    #[test]
    fn udp_snmp_probe_bytes_match_nmap() {
        let payload = get_parsed_data()
            .iter()
            .find(|(ports, _)| ports.contains(&161))
            .map(|(_, payload)| payload)
            .expect("no UDP payload registered for port 161");
        let expected: Vec<u8> = vec![
            0x30, 0x1f, 0x02, 0x01, 0x00, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', 0xa1,
            0x12, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x07, 0x30, 0x05,
            0x06, 0x01, 0x00, 0x05, 0x00,
        ];
        assert_eq!(*payload, expected);
    }

    /// The SSDP probe mixes `\xNN` escapes, `\"` escapes and literal text
    /// across two quoted segments: segments must decode and concatenate
    /// with no separators.
    #[test]
    fn udp_ssdp_probe_decodes_escapes_and_literal_text() {
        let payload = get_parsed_data()
            .iter()
            .find(|(ports, _)| ports.contains(&1900))
            .map(|(_, payload)| payload)
            .expect("no UDP payload registered for port 1900");
        let expected =
            b"M-SEARCH * HTTP/1.1\r\nHost: 239.255.255.250:1900\r\nMan: \"ssdp:discover\"\r\nMX: 5\r\nST: ssdp:all\r\n\r\n"
                .to_vec();
        assert_eq!(*payload, expected);
    }
}
