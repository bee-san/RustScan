# Port exclusion preparation benchmark

Compared Tokio master `b7119f7f3eb1601e81126ef3572699ed7b3b7c0b` with
implementation `270561d553688acbd99f61c460cdfa7c76c1423e` on 2026-10-02.

## Method

Release builds with LTO, Rust 1.98.1, Intel Core Ultra 7 165U, Linux
7.2.6-1-cachyos. Both versions use the same lockfile and identical
`benches/benchmark_helpers.rs`; copy the final benchmark harness into the
baseline worktree before building it. The benchmark runs the production
`Scanner::run_with_status` with **zero target addresses**, so it opens no
sockets and does no DNS or scripting. It includes generating/cloning the
port list, filtering and empty scan setup. Scanner construction and the
current-thread Tokio runtime construction are outside the timer.

Manual ports are `1..=port_count`; exclusions are
`(i * 13 % 65536) as u16` for `i` in `0..excluded_count`. Each case has two
independent twenty-sample Criterion runs per build, a 500 ms warmup and a
2 s target measurement. Cases run in A/B then B/A order on CPU 0. No builds
or other local checks ran during timing. CPU frequency was not fixed on
this shared laptop, so the table retains both repetitions rather than
selecting one result. Values are Criterion's mean point estimates.

Build command for each worktree:

```sh
cargo bench --locked --bench benchmark_helpers --no-run
```

The saved benchmark executables are then run serially, for each case:

```sh
CARGO_TARGET_DIR=/tmp/preparation-results taskset -c 0 /path/to/benchmark_helpers \
  --bench 'port preparation/65535 ports, 4096 exclusions' --save-baseline base-a
```

Repeat with the candidate binary as `head-a`, then the candidate as
`head-b` and the baseline as `base-b`. To run the group normally without
comparing builds:

```sh
cargo bench --locked --bench benchmark_helpers -- 'port preparation'
```

## Results

Times are microseconds; A and B are separate matched repetitions.

| Ports | Exclusions | Master µs A / B | Optimized µs A / B | Time saved A / B |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 1 | 0.289 / 0.286 | 0.261 / 0.271 | 9.7% / 5.2% |
| 16 | 4 | 0.260 / 0.268 | 0.232 / 0.237 | 10.6% / 11.6% |
| 64 | 1 | 0.433 / 0.437 | 0.237 / 0.239 | 45.2% / 45.4% |
| 64 | 4,096 | 6.231 / 10.093 | 2.484 / 3.038 | 60.1% / 69.9% |
| 4,096 | 0 | 10.889 / 10.037 | 0.335 / 0.397 | 96.9% / 96.0% |
| 4,096 | 64 | 20.680 / 20.363 | 2.930 / 3.064 | 85.8% / 85.0% |
| 4,096 | 4,096 | 524.223 / 519.670 | 6.805 / 6.710 | 98.7% / 98.7% |
| 65,535 | 0 | 166.113 / 115.686 | 3.655 / 2.333 | 97.8% / 98.0% |
| 65,535 | 4 | 175.717 / 181.343 | 29.769 / 30.230 | 83.1% / 83.3% |
| 65,535 | 64 | 207.617 / 206.910 | 31.595 / 31.462 | 84.8% / 84.8% |
| 65,535 | 1,024 | 2018.463 / 3271.564 | 33.403 / 33.520 | 98.3% / 99.0% |
| 65,535 | 4,096 | 8811.234 / 8469.706 | 59.853 / 63.211 | 99.3% / 99.3% |

All twelve cases improved in both repetitions. This measures **preparation,
not end-to-end network scan speed**: many scans are dominated by socket I/O,
timeouts and reporting. In particular, the default no-exclusion saving is
only a fraction of a millisecond.

## Implementation and correctness

With no exclusions, keep the already generated vector. For fewer than 64
ports, filter in place with linear membership checks; this avoids bitmap
setup and a second allocation. Larger lists use an 8 KiB bitmap covering
all 65,536 values representable by `u16`, then retain ports in place. This
changes the large-list filtering cost from ports × exclusions to ports +
exclusions, while preserving order, duplicate ports and boundary values.
The helper is kept out of line: release assembly showed an inlined bitmap
reserved 8,424 bytes in every async poll, whereas the final poll frame uses
344 bytes and the helper reserves its bitmap only during preparation.

Exploration found that in-place linear membership slows large cases. A
first production candidate also slowed 64 ports with 4,096 exclusions;
using the bitmap for that case corrected the regression before the final
matched runs. The cutoff is a performance choice, not a limit on input.

One focused network-free regression test compares the implementation with
an independent membership oracle for empty inputs, endpoints 0/65535,
duplicate ports/exclusions, all ports, and a frozen random order.
`cargo test --locked` passes 74 tests with one pre-existing ignored doctest.
All-target Clippy, formatting, documentation and diff checks pass. The
CI-only scan harness adds an excluded-port sweep using the existing
listeners, checking expected results and using the actual attempted socket
count for throughput.

[Raw Criterion samples, confidence intervals, revisions and binary hashes](port-exclusion-benchmark-results.json)
are included. Hosted correctness/performance results are linked in the PR.

## macOS runner setup

Repeated hosted sweeps on Darwin 25.6 returned `ENOBUFS` (error 55) on
both master and the candidate, missing fixture listeners. Such runs are
invalid for performance claims. The workflow provisions the TCP memory
budget once before either build is measured, raising it from the default
1/32 to 1/8 of physical memory when necessary, and prints the actual limit
and allocation counters. It retains every scenario, repeat, listener
comparison and performance threshold. An immediate untimed diagnostic
scan records errors and kernel counters if a measured pair misses a
listener; that failed dataset is not used to claim a speedup.

This uses XNU's [TCP budget initialization](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/netinet/tcp_subr.c)
and [memory accounting interface](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/mem_acct_private.h).
It changes the disposable benchmark environment, not RustScan's behavior
or the operating system configuration on users' machines.
