# Tokio scan benchmark

The runtime migration was compared with its parent using real TCP and UDP
sockets on 2026-10-01. This was a one-off, explicitly requested measurement in
an isolated Linux network namespace. No network benchmark was added to the
automated test or Criterion suites.

## Builds and environment

- Baseline: `cfb864590161d1c8a003811dcf4846ceb8c8284f`, async-std 1.13.2.
- Migration: `2e57686260e2b3bb140548ac53cef44cd816624c`, Tokio 1.53.1.
- Both are optimized release binaries with the repository's LTO settings,
  built using Rust 1.98.1.
- Intel Core Ultra 7 165U, Linux 7.2.6-1-cachyos, x86_64.
- Scanner processes were restricted to CPUs 0-3 (two physical performance
  cores); the responder process used CPUs 4-7. Both runtimes used the same
  affinity. The harness used CPUs 8-9.
- File descriptor soft limit: 65,536, so the requested batches of 256 and 4,500
  were not reduced by RustScan's limit checks.
- The private namespace contained only loopback, with no external interface.
  Targets used literal IPv4/IPv6 addresses; scripts and configuration loading
  were disabled. The normal synchronous resolver initialization still occurred.

Binary SHA-256 hashes:

```text
async-std 00c7f0d91bab260ac622540e86083175afacfd1677647d2b8e96e56ba4f60732
tokio     3ea4f152078f97349f1de9886e99fd7c2a138ff8b65d57b4702ffd1c7a94280b
```

## Method

Each workload used two warmup runs and twelve measured runs per binary. The
order alternated between async-std/Tokio and Tokio/async-std for each pair.
Each run started a fresh CLI process, matching ordinary command-line use.

The primary measurement is RustScan's `Portscan` timer, read using
`RUST_LOG=info`. It includes scan runtime initialization and cleanup and excludes
address parsing and final output. The wall time measures the entire process,
including startup, address parsing and output capture. Runtime startup was
excluded from the earlier synthetic Criterion measurements, so those numbers
measure a different workload.

The responder bound 512 TCP listeners, 256 UDP echo sockets and 128 silent UDP
sockets on each of `127.0.0.1` and `::1`. Empty UDP requests received empty replies.
TCP connections were accepted and closed immediately. Silent UDP sockets received
datagrams without replying. A firewall rule inside the private namespace dropped
TCP packets to `127.0.0.3:40000-40127`, producing actual connection timeouts.
No listeners were bound to `127.0.0.2`, used for the all-closed TCP scans.

Every run checked the exact set of reported open ports and rejected duplicates.
A separate check verified closed-port reporting and port exclusions for both
binaries. Each invocation used this common prefix:

```sh
RUST_LOG=info taskset -c 0-3 /path/to/rustscan \
  --no-config --config-path /dev/null --no-banner --scripts none \
  --greppable --scan-order serial
```

Append the arguments for the workload:

| Workload | Arguments |
| --- | --- |
| TCP closed, 65,535 ports | `-a 127.0.0.2 -r 1-65535 -b 256` or `-b 4500` |
| TCP mixed, 512 open / 4,096 ports | `-a 127.0.0.1 -r 20000-24095 -b 256` or `-b 4500` |
| TCP open, 512 ports | `-a 127.0.0.1 -r 20000-20511 -b 4500` |
| TCP IPv6 mixed, 512 open / 4,096 ports | `-a ::1 -r 20000-24095 -b 4500` |
| UDP echo, 256 ports | `-a 127.0.0.1 -r 30000-30255 -b 256 --udp` |
| UDP IPv6 echo, 256 ports | `-a ::1 -r 30000-30255 -b 256 --udp` |
| TCP filtered, short timeout and retries | `-a 127.0.0.3 -r 40000-40127 -b 64 -t 20 --tries 2` |
| TCP filtered, default timeout | `-a 127.0.0.3 -r 40000-40127 -b 4500 -t 1500` |
| UDP silent, short timeout and retries | `-a 127.0.0.1 -r 31000-31127 -b 64 -t 20 --tries 2 --udp` |
| UDP silent, default timeout | `-a 127.0.0.1 -r 31000-31127 -b 4500 -t 1500 --udp` |
| TCP open, 16 ports with intervals | `-a 127.0.0.1 -r 20000-20015 -b 256 --interval 5` |

All unspecified timeouts use 1,500 ms and one try. The mixed TCP workloads have
listeners on ports 20000-20511 and no listeners on the remaining ports.

## Results

All values below are medians of twelve measured runs. Negative changes mean
less elapsed time. [Raw per-run timings and summaries](tokio-benchmark-results.json)
include the warmups and bootstrap intervals for paired scan-time ratios.

| Workload | async-std scan (ms) | Tokio scan (ms) | Change |
| --- | ---: | ---: | ---: |
| TCP closed, 65,535 ports, batch 256 | 571.89 | 370.29 | -35.3% |
| TCP closed, 65,535 ports, batch 4,500 | 795.35 | 574.69 | -27.7% |
| TCP mixed, 4,096 ports, batch 256 | 68.16 | 28.41 | -58.3% |
| TCP mixed, 4,096 ports, batch 4,500 | 114.30 | 44.19 | -61.3% |
| TCP open, 512 ports, batch 4,500 | 51.72 | 6.72 | -87.0% |
| TCP IPv6 mixed, 4,096 ports, batch 4,500 | 141.81 | 67.37 | -52.5% |
| UDP echo, 256 ports, batch 256 | 37.88 | 5.79 | -84.7% |
| UDP IPv6 echo, 256 ports, batch 256 | 33.84 | 6.48 | -80.9% |
| TCP filtered, 20 ms, two tries, batch 64 | 93.55 | 87.53 | -6.4% |
| TCP filtered, 1,500 ms, batch 4,500 | 1519.73 | 1502.24 | -1.2% |
| UDP silent, 20 ms, two tries, batch 64 | 94.58 | 87.50 | -7.5% |
| UDP silent, 1,500 ms, batch 4,500 | 1520.39 | 1503.11 | -1.1% |
| TCP open, 16 ports, 5 ms interval | 76.45 | 91.79 | +20.1% |

Connection-heavy loopback scans improved in every measured case. For the
4,500-port batch, the scan phase took 27.7% less time for all-closed TCP,
61.3% less for mixed TCP, and 87.0% less for all-open TCP. UDP echo scans took
84.7% less scan time. These percentages include each CLI process's runtime
initialization and cleanup; they are not measurements of a long-lived embedded
scanner.

At the default 1,500 ms timeout, both runtimes were dominated by the requested
wait and differed by about 1%. The 5 ms interval case regressed by 20.1%
(76.45 ms to 91.79 ms), consistent with Tokio's millisecond timer granularity
adding roughly one millisecond to each of the fifteen waits.

### Entire CLI process

Address parsing and startup contribute substantial time on this machine, whose
hosts file is approximately 2.7 MB. Total process improvements are consequently
smaller than scan-phase improvements. The figures below include that work:

| Workload | async-std wall (ms) | Tokio wall (ms) | Change |
| --- | ---: | ---: | ---: |
| TCP closed, 65,535 ports, batch 256 | 686.83 | 489.36 | -28.8% |
| TCP closed, 65,535 ports, batch 4,500 | 922.47 | 691.28 | -25.1% |
| TCP mixed, 4,096 ports, batch 256 | 191.18 | 156.33 | -18.2% |
| TCP mixed, 4,096 ports, batch 4,500 | 242.17 | 172.42 | -28.8% |
| TCP open, 512 ports, batch 4,500 | 177.36 | 128.03 | -27.8% |
| TCP IPv6 mixed, 4,096 ports, batch 4,500 | 336.62 | 260.83 | -22.5% |
| UDP echo, 256 ports, batch 256 | 219.38 | 187.84 | -14.4% |
| UDP IPv6 echo, 256 ports, batch 256 | 252.76 | 216.28 | -14.4% |
| TCP filtered, 20 ms, two tries, batch 64 | 286.49 | 271.43 | -5.3% |
| TCP filtered, 1,500 ms, batch 4,500 | 1625.95 | 1611.28 | -0.9% |
| UDP silent, 20 ms, two tries, batch 64 | 206.90 | 196.30 | -5.1% |
| UDP silent, 1,500 ms, batch 4,500 | 1626.91 | 1610.40 | -1.0% |
| TCP open, 16 ports, 5 ms interval | 184.31 | 198.31 | +7.6% |

### Correctness

All 364 runs (312 measured and 52 warmups) returned exactly the expected open
ports, with no duplicates or missing replies. Both binaries also passed the
separate closed-port and exclusion check. Responder counters matched the expected
57,806 accepted TCP connections, 14,336 echoed UDP datagrams and 10,752 silent UDP
datagrams, including retries. The isolated firewall counted 14,336 dropped TCP
packets during the filtered-port workloads.

## Scope

These results apply to this machine and its loopback stack. They do not establish
throughput across a LAN or WAN, under packet loss, or on macOS or Windows. The
single Python responder can affect reply timing. Both binaries used the same
responder and every expected reply was checked.
