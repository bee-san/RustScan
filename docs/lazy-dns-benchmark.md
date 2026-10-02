# Lazy DNS initialization benchmark

Compared current Tokio master `67c08a33100362c54b56fde784b0fd234f70fa11` with the lazy-resolver implementation
at `a05592a8a88b77ad85d961137943dfadfe98b612` on 2026-10-02.

## Method

Both binaries are release builds with LTO, using Rust 1.98.1 on an Intel Core
Ultra 7 165U running Linux 7.2.6-1-cachyos. Each workload used twenty measured
runs and two warmups per binary, alternating A/B and B/A order. Binaries used
CPUs 0-3; the harness used CPUs 8-9. No builds ran during measurement.

The harness ran in a private network namespace. Every invocation excluded
its only requested port, so no scan traffic was sent. Configuration and
scripts were disabled. Timing spans process launch through exit, including
the same `taskset` affinity launcher for both builds.

Common arguments:

```sh
--no-config --config-path /dev/null --no-banner --scripts none --greppable \
  --ports 80 --exclude-ports 80
```

The literal case adds `-a 127.0.0.1`. The mixed case adds
`-a 127.0.0.1,192.0.2.0/30,2001:db8::/126` and
`--exclude-addresses 192.0.2.1,2001:db8::1`. Both use `RUST_LOG=rustscan=info`.

## Results

| Workload | Master median | Lazy DNS median | Time saved |
| --- | ---: | ---: | ---: |
| Literal IPv4 | 168.23 ms | 2.25 ms | 165.98 ms (98.66%) |
| IPv4/IPv6 CIDRs and exclusions | 178.09 ms | 2.45 ms | 175.63 ms (98.62%) |

All 88 invocations exited successfully with the expected empty scan output.
A separate syscall trace of the optimized literal-IP invocation recorded no
reads of `/etc/hosts` or `/etc/resolv.conf` and no network connects or sends.

This host has a 2,760,051-byte hosts file. Eager Hickory initialization parses
that file even for numeric targets. Systems with smaller hosts files will
save less; this measures CLI startup, not socket throughput. Hostnames that
need fallback DNS still pay resolver initialization once, and parsing order,
file handling, deduplication and exclusions keep their existing behavior.

[Raw samples, setup and binary hashes](lazy-dns-benchmark-results.json) are
included. Network-free regression tests verify that literal IPv4/IPv6 targets,
CIDRs, exclusions, duplicates and empty inputs do not construct the resolver.
