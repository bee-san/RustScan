# Tokio runtime migration

This implements the runtime migration discussed in [#856](https://github.com/bee-san/RustScan/pull/856)
and [#944](https://github.com/bee-san/RustScan/issues/944), based on master at
`cfb864590161d1c8a003811dcf4846ceb8c8284f`.

## CLI behavior

TCP connections and UDP sockets now use Tokio. The CLI creates a runtime on the calling thread for the
scan. `FuturesUnordered` still polls at most `batch_size` socket attempts at once;
concurrent sockets do not require a thread per socket or a task per socket.

Address parsing and Hickory's synchronous resolver run before entering the scan
runtime. Script execution runs after the runtime has been dropped. Port ordering,
exclusions, retries, UDP payloads, closed-port reporting and CLI options retain
their existing implementations.

Port intervals and short timeouts retain `async_io::Timer`, the timer underneath
async-std, independently of the Tokio socket runtime. Longer timeouts first use
Tokio's timer until 32 ms before the deadline, then use `async_io::Timer` for the
remaining wait. This avoids registering a second timer for ordinary replies
while leaving room for coarse timer rounding. Both phases use the original
deadline, including time spent setting up the socket.
An expired timer maps to `std::io::ErrorKind::TimedOut`. Socket errors retain
their original kind, so TCP refusal reporting and UDP timeout retries continue
to distinguish replies from failures. Successful TCP streams are converted to
standard streams, shut down in both directions, and dropped before another
attempt is polled.

Using Tokio's timers for short waits added approximately one millisecond per
interval in the first benchmark. Retaining the existing timer avoids that extra
rounding while keeping the async runtime responsive.
Dropping a scan cancels its timers; runtime shutdown never has to wait for a
sleeping blocking task. Immediately ready I/O operations avoid timer allocation,
and the time spent polling a pending operation is charged to its original timeout.

## Library callers

`Scanner::new`, `run`, `run_with_status`, `PortStrategy`, and the address helpers
keep their signatures. However, awaiting a scan now requires a Tokio runtime
with both I/O and time enabled. Calling it from `futures::executor::block_on` or
`async_std::task::block_on` alone is no longer sufficient.

Treat this new runtime requirement as a **breaking library change for the next
major release**. This PR does not publish a release or change the package version.

Add Tokio to the embedding application's dependencies:

```toml
tokio = { version = "1.53.1", features = ["rt", "net", "time"] }
```

For a synchronous application, resolve inputs first, then create the runtime:

```rust,ignore
let ips = rustscan::address::parse_addresses(&opts);
let scanner = Scanner::new(/* existing arguments, including &ips */);
let runtime = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()?;
let sockets = runtime.block_on(scanner.run());
```

The [crate example](../src/lib.rs) provides a complete, compile-checked example.
Applications already running on Tokio can simply use `scanner.run().await` or
`scanner.run_with_status().await`; do not nest `Runtime::block_on` calls.

Keep the synchronous address helpers outside async runtime execution. If an
existing Tokio application needs to call `parse_addresses`, move owned options
into `tokio::task::spawn_blocking(move || parse_addresses(&opts)).await` and handle
the join result before constructing the scanner. Hickory's synchronous resolver
owns its own runtime and performs blocking lookups.

## Dependencies and validation

The direct Tokio dependency enables only `rt`, `net`, and `time`; `test-util` is
enabled for deterministic tests with a paused clock. Tokio was already present
through Hickory. The existing `futures` dependency continues to provide
`FuturesUnordered`, `StreamExt` and future polling. `async-io` becomes a direct
dependency solely to retain the existing timer implementation and its short-wait
performance; socket I/O uses Tokio. `async-std` and its executor are absent from
the resolved dependency tree.

Regression tests cover successful operations (including zero-byte responses),
preservation of I/O errors, timeout cancellation, immediate results at a zero
deadline, wakeups during the first poll, scan cancellation, and interval timing with
excluded or empty port sets. They use simulated operations and scanners with no
target addresses, following the repository's rule against network tests.

Run the repository checks with `just test`. Run the isolated scheduling
microbenchmarks with:

```sh
cargo bench --locked --bench benchmark_helpers -- 'runtime scheduling'
```

Each benchmark completes 4,096 simulated operations through a 256-operation
window. One case completes immediately; the other expires every operation after
10 ms. Runtime construction is outside the measurement. Criterion uses 20
samples, a one-second warmup and a five-second measurement target. These measure
scheduling and timer costs. The [real TCP/UDP scan comparison](tokio-benchmark.md)
records a separate measurement in an isolated loopback environment, including
full CLI timings and short port intervals. LAN/WAN performance
and network performance on other operating systems remain unmeasured.
