//! Core functionality for actual scanning behaviour.
use crate::port_strategy::PortStrategy;
use crate::udp_packets::udp_payload::cust_payload;
use log::debug;

mod socket_iterator;
use socket_iterator::SocketIterator;

use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    num::NonZero,
    time::Duration,
};
use tokio::{
    net::{TcpStream, UdpSocket},
    io::{self, AsyncWriteExt},
    time,
};
use colored::Colorize;
use futures_lite::{stream, StreamExt};
use tokio_par_stream::TokioParStream;

#[derive(Debug)]
struct ScannerConnector {
    udp: bool,
    tries: NonZero<u8>,
    timeout: Duration,
    greppable: bool,
    accessible: bool,
}

impl ScannerConnector {
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
    async fn scan_socket(&self, socket: SocketAddr) -> io::Result<SocketAddr> {
        if self.udp {
            let payload = cust_payload(socket.port());

            let tries = self.tries.get();
            for _ in 1..=tries {
                match self.udp_scan(socket, &payload, self.timeout).await {
                    Ok(true) => return Ok(socket),
                    Ok(false) => continue,
                    Err(e) => return Err(e),
                }
            }
            return Ok(socket);
        }

        let tries = self.tries.get();
        let mut last_err = None;
        for nr_try in 1..=tries {
            match self.connect(socket).await {
                Ok(tcp_stream) => {
                    debug!(
                        "Connection was successful, shutting down stream {}",
                        &socket
                    );
                    if let Err(e) = {tcp_stream}.shutdown().await {
                        debug!("Shutdown stream error {}", &e);
                    }
                    self.fmt_ports(socket);

                    debug!("Return Ok after {} tries", nr_try);
                    return Ok(socket);
                }
                Err(e) => {
                    let mut error_string = e.to_string();

                    assert!(
                        !error_string.to_lowercase().contains("too many open files"),
                        "Too many open files. Please reduce batch size. The default is 5000. Try -b 2500."
                    );

                    let ip = socket.ip();
                    last_err = Some(move || {
                        use std::fmt::Write;
                        error_string.push(' ');
                        write!(error_string, "{ip}").unwrap();
                        io::Error::other(error_string)
                    });
                }
            };
        }

        Err(last_err.unwrap()())
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
        time::timeout(
            self.timeout,
            async move { TcpStream::connect(socket).await },
        ).await?
    }

    /// Binds to a UDP socket so we can send and recieve packets
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

                match time::timeout(wait, udp_socket.recv(&mut buf)).await {
                    Ok(Ok(size)) => {
                        debug!("Received {} bytes", size);
                        self.fmt_ports(socket);
                        Ok(true)
                    }
                    Ok(Err(e)) => Err(e),
                    Err(_) => Ok(false),
                }
            }
            Err(e) => {
                println!("Err E binding sock {:?}", e);
                Err(e)
            }
        }
    }

    /// Formats and prints the port status
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


/// The class for the scanner
/// IP is data type IpAddr and is the IP address
/// start & end is where the port scan starts and ends
/// batch_size is how many ports at a time should be scanned
/// Timeout is the time RustScan should wait before declaring a port closed. As datatype Duration.
/// greppable is whether or not RustScan should print things, or wait until the end to print only the ip and open ports.
/// Added by wasuaje - 01/26/2024:
///     exclude_ports  is an exclusion port list
#[derive(Debug)]
pub struct Scanner {
    ips: Box<[IpAddr]>,
    port_strategy: PortStrategy,
    exclude_ports: Vec<u16>,
    batch_size: u16,
    connector: Arc<ScannerConnector>,
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
            port_strategy,
            ips: Box::from(ips),
            exclude_ports,
            connector: Arc::new(ScannerConnector {
                udp,
                accessible,
                timeout,
                tries: NonZero::new(tries).unwrap_or(NonZero::<u8>::MIN),
                greppable,
            })
        }
    }

    /// Runs scan_range with chunk sizes
    /// If you want to run RustScan normally, this is the entry point used
    /// Returns all open ports as `Vec<u16>`
    /// Added by wasuaje - 01/26/2024:
    ///    Filtering port against exclude port list
    pub async fn run(&self) -> Vec<SocketAddr> {
        let ports = self
            .port_strategy
            .ordered_iter()
            .filter(|&port| !self.exclude_ports.contains(&port))
            .collect::<Vec<_>>();

        let ports_len = ports.len();

        let socket_iterator = SocketIterator::new(&self.ips, ports.into_iter());
        let mut errors: HashSet<String> = HashSet::new();

        let stream = stream::iter(socket_iterator)
            .map(|socket| (socket, Arc::clone(&self.connector)))
            .map(|(socket, connector)| async move {
                connector.scan_socket(socket).await
            })
            .par_buffered_unordered(usize::from(self.batch_size))
            .filter_map(|result| {
                let err = match result {
                    Ok(sock) => return Some(sock),
                    Err(err) => err,
                };
                let error_string = err.to_string();
                if errors.len() < self.ips.len() * 1000 {
                    errors.insert(error_string);
                }
                None
            });


        debug!(
            "Start scanning sockets. \nBatch size {}\nNumber of ip-s {}\nNumber of ports {}\nTargets all together {} ",
            self.batch_size,
            self.ips.len(),
            &ports_len,
            self.ips.len() * ports_len
        );

        let open_sockets = stream.collect::<Vec<_>>().await;

        debug!("Typical socket connection errors {:?}", errors);
        debug!("Open Sockets found: {:?}", &open_sockets);
        open_sockets
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input::{PortRange, ScanOrder};
    use std::{net::IpAddr, time::Duration};

    #[tokio::test]
    async fn scanner_runs() {
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
        scanner.run().await;
    }

    #[tokio::test]
    async fn ipv6_scanner_runs() {
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
        scanner.run().await;
    }

    #[tokio::test]
    async fn quad_zero_scanner_runs() {
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
        scanner.run().await;
    }

    #[tokio::test]
    async fn google_dns_runs() {
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
        scanner.run().await;
    }

    #[tokio::test]
    async fn infer_ulimit_lowering_no_panic() {
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
        scanner.run().await;
    }

    #[tokio::test]
    async fn udp_scan_runs() {
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
        scanner.run().await;
    }

    #[tokio::test]
    async fn udp_ipv6_runs() {
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
        scanner.run().await;
    }

    #[tokio::test]
    async fn udp_quad_zero_scanner_runs() {
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
        scanner.run().await;
    }

    #[tokio::test]
    async fn udp_google_dns_runs() {
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
        scanner.run().await;
    }
}
