# Lazy DNS initialization benchmark

Compared the Tokio build at `eae9fce582b28b198ffded0dfacc491025f1e239` with the lazy-resolver implementation
at `a810e17ed26e1978def99701f007aa185b9a96e2` on 2026-10-01.

## Method

Both binaries are release builds with LTO, compiled using Rust 1.98.1 on an
Intel Core Ultra 7 165U running Linux 7.2.6-1-cachyos. Each workload ran twenty
measured times plus two warmups per binary, alternating A/B and B/A order.
Both binaries were restricted to CPUs 0-3; the harness used CPUs 8-9.

Every invocation excluded its only requested port, so this measures full CLI
startup and address parsing without sending scan traffic. The runs used a
private network namespace with only loopback. Configuration and scripts were
disabled. No builds ran concurrently with the measurement.

Common arguments:

```sh
--no-config --config-path /dev/null --no-banner --scripts none --greppable \
  --ports 80 --exclude-ports 80
```

The IPv4 case adds `-a 127.0.0.1`. The mixed case adds
`-a 127.0.0.1,192.0.2.0/30,2001:db8::/126` and
`--exclude-addresses 192.0.2.1,2001:db8::1`. Both use `RUST_LOG=info`.

## Results

| Workload | Before, median CLI time | Lazy DNS, median CLI time | Time saved |
| --- | ---: | ---: | ---: |
| Literal IPv4 | 107.92 ms | 1.85 ms | 106.07 ms (98.29%) |
| IPv4/IPv6 CIDRs and exclusions | 108.38 ms | 1.89 ms | 106.49 ms (98.26%) |

All 88 invocations exited successfully with the expected empty scan output.
A separate syscall trace of the literal-IP invocation confirmed no reads of
`/etc/hosts` or `/etc/resolv.conf` and no network connects or sends.

This host has a 2,760,051-byte hosts file. Eager Hickory initialization parsed
that file even when only numeric addresses were requested. Deferring the
resolver removes that cost; systems with smaller hosts files will save less.
This is a startup measurement, not a measurement of socket throughput.
Hostname and file lookup precedence are unchanged. A hostname that needs the
fallback resolver still pays its initialization cost, once per parse operation.

[Raw timings and binary hashes](lazy-dns-benchmark-results.json) are included.
Regression tests use a resolver factory that panics if called, verifying that
IPv4/IPv6 literals, CIDRs, exclusions, duplicates and empty target lists stay
independent of DNS initialization. No hostname lookups were added to the tests.
