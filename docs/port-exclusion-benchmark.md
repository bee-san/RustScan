# Port exclusion preparation benchmark

Compared Tokio master `b7119f7f3eb1601e81126ef3572699ed7b3b7c0b` with
implementation `209299ce8a17401f340d061792cca21965cf6e0c` on 2026-10-02.

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
| 1 | 1 | 0.273 / 0.329 | 0.265 / 0.253 | 2.9% / 23.0% |
| 16 | 4 | 0.374 / 0.408 | 0.325 / 0.325 | 13.0% / 20.2% |
| 64 | 1 | 0.644 / 0.416 | 0.319 / 0.226 | 50.4% / 45.8% |
| 64 | 4,096 | 6.083 / 6.175 | 2.439 / 2.468 | 59.9% / 60.0% |
| 4,096 | 0 | 8.026 / 8.107 | 0.242 / 0.233 | 97.0% / 97.1% |
| 4,096 | 64 | 14.605 / 20.223 | 2.072 / 3.023 | 85.8% / 85.1% |
| 4,096 | 4,096 | 587.432 / 541.722 | 5.615 / 5.875 | 99.0% / 98.9% |
| 65,535 | 0 | 170.424 / 165.198 | 3.880 / 3.707 | 97.7% / 97.8% |
| 65,535 | 4 | 249.493 / 255.563 | 39.227 / 42.499 | 84.3% / 83.4% |
| 65,535 | 64 | 244.115 / 203.029 | 28.939 / 29.779 | 88.1% / 85.3% |
| 65,535 | 1,024 | 1996.094 / 1997.401 | 30.588 / 31.003 | 98.5% / 98.4% |
| 65,535 | 4,096 | 6309.348 / 6313.109 | 32.724 / 32.774 | 99.5% / 99.5% |

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
