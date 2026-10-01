# Tokio scan benchmark

The runtime migration was compared with its async-std base using real TCP and UDP
sockets on 2026-10-01. This was a one-off, explicitly requested measurement in
an isolated Linux network namespace. No network benchmark was added to the
automated test or Criterion suites.

## Builds and environment

- Baseline: `cfb864590161d1c8a003811dcf4846ceb8c8284f`, async-std 1.13.2.
- Migration: `42427e88c1a6587d0a8b198a73bac4553bb4ad72`, Tokio 1.53.1.
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
tokio     669627834d8a32f60e2167e78a9518dcede7562831adb85fb61a9d94871494b8
```

## Method

Each workload used two warmup runs and twelve measured runs per binary. The
order alternated between async-std/Tokio and Tokio/async-std for each pair.
Each run started a fresh CLI process, matching ordinary command-line use.

The primary measurement is RustScan's `Portscan` timer, read using
`RUST_LOG=info`. It includes scan runtime initialization and cleanup and excludes
address parsing and final output. The wall time measures the entire process,
including startup, address parsing and output capture. Runtime startup was
excluded from the synthetic Criterion measurements below, so those numbers
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
| TCP open, 16 ports with intervals | `-a 127.0.0.1 -r 20000-20015 -b 256 --interval 1` (also 5 and 20 ms) |
| TCP filtered, short serial timeouts | `-a 127.0.0.3 -r 40000-40127 -b 1 -t 1` (also 5 ms) |
| UDP silent, short serial timeouts | `-a 127.0.0.1 -r 31000-31127 -b 1 -t 1 --udp` (also 5 ms) |

All unspecified timeouts use 1,500 ms and one try. The mixed TCP workloads have
listeners on ports 20000-20511 and no listeners on the remaining ports.

## Results

These results cover the revised timeout implementation. The initial migration
added 20.1% to the 5 ms interval workload (76.45 to 91.79 ms). Port intervals and
short deadlines now retain the existing `async_io::Timer`; long deadlines use
Tokio until 32 ms before expiry, then finish with the precise timer. Both phases
preserve the original deadline. This avoids timer rounding on short waits and
avoids registering a second timer for normal early socket replies.

All values below are medians of twelve measured runs. Negative changes mean
less elapsed time. The final column is a bootstrap 95% interval for the median
of paired Tokio/async-std scan-time ratios, expressed as a percentage change.
It uses 5,000 resamples of twelve pairs and does not account for every source
of system noise. It differs from the ratio of the two medians in the Change
column. [Per-run timings and summaries](tokio-benchmark-results.json) include
the warmups and full precision.

| Workload | async-std scan (ms) | Tokio scan (ms) | Change | Paired change, 95% interval |
| --- | ---: | ---: | ---: | ---: |
| TCP closed, 65,535 ports, batch 256 | 565.62 | 377.77 | -33.21% | -34.85% to -31.97% |
| TCP closed, 65,535 ports, batch 4,500 | 769.26 | 571.34 | -25.73% | -27.30% to -23.46% |
| TCP mixed, 4,096 ports, batch 256 | 68.14 | 27.08 | -60.26% | -62.18% to -56.78% |
| TCP mixed, 4,096 ports, batch 4,500 | 105.18 | 40.72 | -61.28% | -62.90% to -58.33% |
| TCP open, 512 ports, batch 4,500 | 47.70 | 6.26 | -86.87% | -88.76% to -85.17% |
| TCP IPv6 mixed, 4,096 ports, batch 4,500 | 106.26 | 40.98 | -61.43% | -63.84% to -60.18% |
| UDP echo, 256 ports, batch 256 | 26.10 | 3.55 | -86.40% | -89.28% to -83.06% |
| UDP IPv6 echo, 256 ports, batch 256 | 27.63 | 3.80 | -86.25% | -88.36% to -84.90% |
| TCP filtered, 20 ms, two tries, batch 64 | 87.64 | 90.20 | +2.92% | -0.36% to +6.30% |
| TCP filtered, 1,500 ms, batch 4,500 | 1519.99 | 1500.68 | -1.27% | -1.40% to -1.07% |
| UDP silent, 20 ms, two tries, batch 64 | 91.01 | 82.37 | -9.49% | -13.15% to -6.01% |
| UDP silent, 1,500 ms, batch 4,500 | 1518.53 | 1501.66 | -1.11% | -1.35% to -1.01% |
| TCP open, 16 ports, 5 ms interval | 76.53 | 76.20 | -0.43% | -0.59% to -0.28% |
| TCP filtered, 1 ms, batch 1 | 130.93 | 131.10 | +0.13% | -0.00% to +0.22% |
| TCP filtered, 5 ms, batch 1 | 644.51 | 644.95 | +0.07% | -0.03% to +0.10% |
| UDP silent, 1 ms, batch 1 | 133.38 | 133.44 | +0.04% | -0.17% to +0.10% |
| UDP silent, 5 ms, batch 1 | 647.45 | 647.54 | +0.01% | -0.04% to +0.06% |
| TCP open, 16 ports, 1 ms interval | 16.38 | 15.97 | -2.52% | -3.62% to -1.56% |
| TCP open, 16 ports, 20 ms interval | 302.22 | 301.94 | -0.09% | -0.13% to -0.04% |

Bulk TCP scans took 25.7-86.9% less scan time, and UDP echo scans took
86.2-86.4% less. All three interval workloads improved; the former 5 ms
regression is gone. Serial 1 ms and 5 ms timeout medians took 0.01-0.13% more
time. Default 1,500 ms timeout scans took about 1.1-1.3% less time.

These measurements support substantial bulk-scan gains, but **do not establish
literally zero regressions**. The noisy filtered TCP case and the remaining
synthetic overhead are detailed below.

### Follow-up on the noisy filtered TCP case

The 20 ms filtered TCP workload had a 2.92% higher median in the main run, with
substantial variation. A separate repeat used the same binaries, setup and
alternating order, with two warmups and **40 measured runs per binary**:

| Measurement | async-std | Tokio | Change |
| --- | ---: | ---: | ---: |
| Scan median | 90.81 ms | 89.67 ms | -1.25% |
| Entire CLI median | 199.80 ms | 199.90 ms | +0.05% |

The paired scan-ratio bootstrap 95% interval was **-4.16% to +1.73%**. The
repeat does not establish a slowdown, but it cannot rule out a small change
in this noisy case. Its 84 runs all returned the expected results. The original
result remains in the table above; the JSON includes both runs.

### Entire CLI process

Address parsing and startup contribute substantial time on this machine, whose
hosts file is approximately 2.7 MB. Total process changes are consequently
smaller than scan-phase changes. These figures include startup, address parsing,
output capture and process exit:

| Workload | async-std wall (ms) | Tokio wall (ms) | Change |
| --- | ---: | ---: | ---: |
| TCP closed, 65,535 ports, batch 256 | 678.41 | 490.92 | -27.64% |
| TCP closed, 65,535 ports, batch 4,500 | 886.49 | 686.16 | -22.60% |
| TCP mixed, 4,096 ports, batch 256 | 187.83 | 141.97 | -24.42% |
| TCP mixed, 4,096 ports, batch 4,500 | 223.57 | 156.73 | -29.90% |
| TCP open, 512 ports, batch 4,500 | 160.65 | 124.34 | -22.61% |
| TCP IPv6 mixed, 4,096 ports, batch 4,500 | 225.67 | 154.43 | -31.57% |
| UDP echo, 256 ports, batch 256 | 144.53 | 117.11 | -18.97% |
| UDP IPv6 echo, 256 ports, batch 256 | 145.42 | 119.61 | -17.75% |
| TCP filtered, 20 ms, two tries, batch 64 | 203.20 | 203.25 | +0.02% |
| TCP filtered, 1,500 ms, batch 4,500 | 1625.54 | 1607.90 | -1.08% |
| UDP silent, 20 ms, two tries, batch 64 | 198.82 | 193.47 | -2.69% |
| UDP silent, 1,500 ms, batch 4,500 | 1626.34 | 1608.17 | -1.12% |
| TCP open, 16 ports, 5 ms interval | 184.30 | 182.87 | -0.78% |
| TCP filtered, 1 ms, batch 1 | 239.22 | 239.95 | +0.31% |
| TCP filtered, 5 ms, batch 1 | 753.12 | 753.69 | +0.08% |
| UDP silent, 1 ms, batch 1 | 241.22 | 241.50 | +0.12% |
| UDP silent, 5 ms, batch 1 | 754.51 | 756.26 | +0.23% |
| TCP open, 16 ports, 1 ms interval | 127.33 | 123.30 | -3.17% |
| TCP open, 16 ports, 20 ms interval | 412.45 | 411.54 | -0.22% |

### Correctness

All 532 runs (456 measured and 76 warmups) returned exactly the expected open
ports, with no duplicates or missing replies. Both binaries also passed the
separate closed-port and exclusion check. Responder counters matched the expected
58,702 accepted TCP connections, 14,336 echoed UDP datagrams and 17,920 silent UDP
datagrams, including retries. The isolated firewall counted 21,504 dropped TCP
packets during the filtered-port workloads.

## Synthetic scheduling comparison

These use simulated operations without sockets, DNS, or scripts. Each iteration
completes 4,096 operations through a 256-operation window. One workload replies
immediately; the other expires every operation after 10 ms. Both builds use the
same loop; the baseline uses `async_std::io::timeout` and its original
`futures::executor::block_on`, while the migration uses the production timeout
helper and Tokio. Runtime construction is outside the measurement.

Each Criterion run has twenty samples, a one-second warmup and a five-second
measurement target. The ready case was repeated on CPU 0 in A/B/B/A order to
reduce core-migration and run-order effects. Its table value is the median of
the forty per-sample batch times for each binary. The expiration case used one
run per binary on CPUs 0-3. No builds or socket benchmarks ran concurrently.

| Simulated workload | async-std median | Tokio median | Change |
| --- | ---: | ---: | ---: |
| Immediately ready operations | 0.29120 ms | 0.30204 ms | +3.72% |
| Every operation expires after 10 ms | 160.88186 ms | 160.96872 ms | +0.05% |

The ready case still costs about **11 microseconds more per 4,096 operations**.
Its two individual run medians were 0.28344/0.29476 ms for async-std and
0.30039/0.30309 ms for Tokio. This remaining overhead is included rather than
claiming that every workload improved. The original 11% synthetic expiration
regression has been reduced to about 0.05% in this comparison.

Reproduce the migration benchmark with:

```sh
cargo bench --locked --bench benchmark_helpers -- 'runtime scheduling'
```

For the baseline, apply [the benchmark adapter](tokio-benchmark-baseline.patch)
with `git apply --unidiff-zero` to a checkout of
`cfb864590161d1c8a003811dcf4846ceb8c8284f`, then run the same benchmark command.
The JSON includes per-sample times and benchmark binary hashes.

## Scope

These results apply to this machine and its loopback stack. They do not establish
throughput across a LAN or WAN, under packet loss, or on macOS or Windows. The
single Python responder can affect reply timing, and the host was an ordinary
interactive system. Both binaries used the same responder and CPU restrictions,
and every expected reply was checked. A finite benchmark cannot guarantee zero
slowdown for every workload or distinguish every sub-percent difference from
system noise.
