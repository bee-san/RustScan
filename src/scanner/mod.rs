//! Core functionality for actual scanning behaviour.
use crate::generated::get_parsed_data;
use crate::port_strategy::PortStrategy;
use crate::tui::println_safe;
use log::debug;

mod socket_iterator;
use socket_iterator::SocketIterator;

use colored::Colorize;
use futures::stream::{FuturesUnordered, StreamExt};
use std::collections::BTreeMap;
use std::future::poll_fn;
use std::task::Poll;
use std::{
    collections::{HashMap, HashSet},
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr},
    num::NonZeroU8,
    sync::Arc,
    time::Duration,
};
use tokio::io::Interest;
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{sleep, timeout};

/// How many sockets the scan starts or finishes (counted together) between
/// two polls of the runtime's I/O driver; see `Scanner::scan_sockets`.
///
/// Every round ends with a non-blocking poll of the OS selector, so this
/// keeps the overhead far below 1% while bounding the time between two
/// polls to about a millisecond on Linux.
const WORK_PER_TURN: usize = 128;

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
///
/// # Runtime
///
/// The futures returned by [`Scanner::run`] and [`Scanner::run_with_status`]
/// use Tokio sockets and timers, so they must be polled from within a
/// [Tokio](https://docs.rs/tokio) runtime that has both the I/O and the time
/// drivers enabled (for example `#[tokio::main]`, or a runtime built with
/// `enable_all()`). Polling them from another executor panics.
///
/// The scan never spawns tasks: every socket is driven from the one future
/// you await, so a current-thread runtime is enough (it is what the
/// `rustscan` binary uses), and the future is `Send` if you prefer to spawn
/// it on a multi-threaded runtime.
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
    pub async fn run_with_status(&self) -> Vec<PortStatus> {
        // Every in-flight socket is polled from this single future through a
        // `FuturesUnordered`. Under Tokio's cooperative budget the future
        // would be forced to yield after ~128 sockets made progress, and the
        // `FuturesUnordered` would then re-poll every other ready socket just
        // to have it return `Pending` again. Opt out; `scan_sockets` yields to
        // the runtime by itself, in rounds of `WORK_PER_TURN` sockets.
        tokio::task::unconstrained(self.scan()).await
    }

    async fn scan(&self) -> Vec<PortStatus> {
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
                    sleep(self.interval).await;
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
    ///
    /// Starts sockets and handles finished ones in rounds of at most
    /// [`WORK_PER_TURN`] of either, and lets the runtime poll for I/O and fire
    /// timers between rounds. One poll of the scan future otherwise lasts
    /// until no socket is ready, which can take long: starting a whole large
    /// batch at once, or a run of UDP probes that all finish straight away.
    /// Sockets that finish in the meantime are only noticed once the poll
    /// ends, so their results come late, and if the poll outlasts the timeout
    /// their timers fire before their answers are seen.
    async fn scan_sockets(
        &self,
        mut sockets: SocketIterator<'_>,
        udp_payloads: &Option<Arc<UdpPayloadLookup>>,
        found_sockets: &mut Vec<PortStatus>,
        errors: &mut HashSet<String>,
    ) {
        let mut ftrs = FuturesUnordered::new();

        loop {
            let mut work = 0;
            while work < WORK_PER_TURN {
                let mut started = false;
                if ftrs.len() < self.batch_size {
                    if let Some(socket) = sockets.next() {
                        ftrs.push(self.scan_socket(socket, udp_payloads.clone()));
                        started = true;
                        work += 1;
                    }
                }

                // Poll once without waiting; this starts the new socket.
                match poll_fn(|cx| Poll::Ready(ftrs.poll_next_unpin(cx))).await {
                    Poll::Ready(Some(result)) => {
                        self.record(result, found_sockets, errors);
                        work += 1;
                    }
                    // Nothing in flight and nothing left to start.
                    Poll::Ready(None) => return,
                    // Nothing has finished; keep starting sockets while there is room.
                    Poll::Pending if started => {}
                    Poll::Pending => break,
                }
            }

            if work >= WORK_PER_TURN {
                tokio::task::yield_now().await;
            } else {
                // The batch is full (or complete) and every socket in it is
                // waiting on the network.
                match ftrs.next().await {
                    Some(result) => self.record(result, found_sockets, errors),
                    None => return,
                }
            }
        }
    }

    /// Records the outcome of one socket.
    fn record(
        &self,
        result: io::Result<PortStatus>,
        found_sockets: &mut Vec<PortStatus>,
        errors: &mut HashSet<String>,
    ) {
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
                    if let Err(e) = shutdown_both(tcp_stream) {
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
        timeout(self.timeout, TcpStream::connect(socket))
            .await
            .unwrap_or_else(|_elapsed| Err(timed_out()))
    }

    /// Binds a non-blocking UDP socket on the unspecified address of the
    /// target's address family, so we can send and receive packets.
    fn udp_bind(socket: SocketAddr) -> io::Result<std::net::UdpSocket> {
        let local_addr = match socket {
            SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
        };

        let udp_socket = std::net::UdpSocket::bind(local_addr)?;
        udp_socket.set_nonblocking(true)?;
        Ok(udp_socket)
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
        let udp_socket = match Self::udp_bind(socket) {
            Ok(udp_socket) => udp_socket,
            Err(e) => {
                debug!("Error binding UDP socket: {e:?}");
                return Err(e);
            }
        };
        let mut buf = [0u8; 1024];

        udp_socket.connect(socket)?;

        // Send the probe and try the first receive straight away, as
        // async-std did. Tokio's readiness-based I/O would first wait for the
        // reactor to report the socket ready, costing every probe extra trips
        // through the event loop, while the probe can almost always be sent
        // immediately and, on the local host, the answer (often an ICMP "port
        // unreachable", seen as a refused connection) is usually already
        // there when the send returns. The socket is only registered with
        // Tokio when we really have to wait.
        let sent = match udp_socket.send(payload) {
            Ok(_) => true,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => false,
            Err(e) => return Err(e),
        };
        let early = if sent {
            udp_socket.recv(&mut buf)
        } else {
            Err(io::ErrorKind::WouldBlock.into())
        };

        let received = match early {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                let udp_socket = UdpSocket::from_std(udp_socket)?;
                if !sent {
                    udp_socket.send(payload).await?;
                }
                match timeout(wait, recv_or_error(&udp_socket, &mut buf)).await {
                    Ok(received) => received,
                    // Nothing came back in time.
                    Err(_elapsed) => return Ok(false),
                }
            }
            early => early,
        };

        match received {
            Ok(size) => {
                debug!("Received {size} bytes");
                self.fmt_ports(socket);
                Ok(true)
            }
            Err(e) if e.kind() == io::ErrorKind::TimedOut => Ok(false),
            Err(e) => Err(e),
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

/// Shuts down both halves of a connected stream before it is closed, as the
/// async-std implementation did (`TcpStream::shutdown(Shutdown::Both)`).
///
/// Tokio only offers an asynchronous write-side shutdown, so take the socket
/// back from the reactor and shut it down synchronously instead.
fn shutdown_both(stream: TcpStream) -> io::Result<()> {
    stream.into_std()?.shutdown(Shutdown::Both)
}

/// Waits for a datagram on a connected UDP socket, or for the error the
/// system queued for it: an ICMP "port unreachable" is reported as a refused
/// connection, which is how closed UDP ports are told apart from filtered
/// ones.
///
/// `UdpSocket::recv` alone does not do this on Linux: a queued ICMP error
/// only raises `EPOLLERR`, which Tokio does not count as readable, so `recv`
/// would sleep until the timeout. async-io treated `EPOLLERR` as readable.
async fn recv_or_error(socket: &UdpSocket, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        let ready = socket.ready(Interest::READABLE | Interest::ERROR).await?;

        if ready.is_readable() {
            match socket.try_recv(buf) {
                // A spurious wake-up; wait again (unless the socket is closed
                // for reading, which would wake us up forever).
                Err(e) if e.kind() == io::ErrorKind::WouldBlock && !ready.is_read_closed() => {}
                received => return received,
            }
        }

        if ready.is_error() {
            // Take (and clear) the queued error. `WouldBlock` when there is
            // none makes Tokio clear the error readiness, so this cannot spin.
            let queued = socket.try_io(Interest::ERROR, || {
                socket
                    .take_error()?
                    .map_or_else(|| Err(io::ErrorKind::WouldBlock.into()), Ok)
            });
            match queued {
                Ok(error) => return Err(error),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            }
        }
    }
}

/// The error reported for a connection attempt that hit the timeout; the same
/// kind and message async-std's `io::timeout` used.
fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "future timed out")
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::input::{PortRanges, ScanOrder};

    // These tests never open sockets: they only build a `Scanner` (and its
    // futures), run a scan that has no socket to scan, or inspect the payload
    // table generated by build.rs.

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
    fn port_exclusions_preserve_order_duplicates_and_boundaries() {
        let inputs = [
            Vec::new(),
            vec![65535, 0, 80, 443, 80, 65535, 1],
            (0..=65535).collect(),
            PortStrategy::pick(&Some(PortRanges(vec![(0, 1023)])), None, ScanOrder::Random).order(),
        ];
        let exclusions = [
            Vec::new(),
            vec![0],
            vec![0, 65535, 0, 443],
            (0..1024).collect(),
            (0..=65535).collect(),
        ];

        for ports in inputs {
            for excluded in &exclusions {
                let excluded_set: HashSet<_> = excluded.iter().copied().collect();
                let expected: Vec<u16> = ports
                    .iter()
                    .filter(|&port| !excluded_set.contains(port))
                    .copied()
                    .collect();
                assert_eq!(filter_excluded_ports(ports.clone(), excluded), expected);
            }
        }
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

    /// Embedders may spawn the scan on a multi-threaded runtime, which needs
    /// `Send` futures. The futures are only created here, never polled, so
    /// no socket is opened.
    #[test]
    fn scan_futures_are_send() {
        fn assert_send<T: Send>(_: &T) {}

        let scanner = test_scanner();
        assert_send(&scanner.run());
        assert_send(&scanner.run_with_status());
    }

    /// Drives a scan on the same kind of runtime the CLI builds. Every port
    /// is excluded, so the scan has no socket to open and returns at once.
    #[test]
    fn scan_without_sockets_completes_on_a_current_thread_runtime() {
        let addrs = vec!["127.0.0.1".parse::<IpAddr>().unwrap()];
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .unwrap();

        for interval in [Duration::ZERO, Duration::from_millis(10)] {
            let scanner = Scanner::new(
                &addrs,
                10,
                Duration::from_millis(100),
                1,
                true,
                PortStrategy::Manual(vec![1, 2]),
                true,
                vec![1, 2],
                false,
            )
            .with_interval(interval);

            assert!(runtime.block_on(scanner.run_with_status()).is_empty());
        }
    }

    #[test]
    fn timeouts_are_reported_as_timed_out_errors() {
        let error = timed_out();

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(error.to_string(), "future timed out");
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
