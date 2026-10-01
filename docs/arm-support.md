# ARM support

This page covers which ARM targets RustScan's CI builds and tests, and how to build ARM binaries yourself.

## What CI covers

| Target | Built by | Tested by |
| --- | --- | --- |
| `aarch64-unknown-linux-gnu` (64-bit ARM Linux) | `build-nix` job in [build.yml](../.github/workflows/build.yml) | `Test Suite (ubuntu-24.04-arm)` in [test.yml](../.github/workflows/test.yml) |
| `armv7-unknown-linux-gnueabihf` (32-bit ARM Linux) | `build-nix` job in [build.yml](../.github/workflows/build.yml) | not tested in CI |
| `aarch64-apple-darwin` (Apple Silicon macOS) | `build-macos-aarch64` job in [build.yml](../.github/workflows/build.yml) | `Test Suite (macos-latest)` in [test.yml](../.github/workflows/test.yml) |

- **Builds** use [`houseabsolute/actions-rust-cross`](https://github.com/houseabsolute/actions-rust-cross). It cross-compiles the Linux ARM targets with [`cross`](https://github.com/cross-rs/cross) on x86_64 runners.
- **Tests** run natively on GitHub-hosted arm64 runners: `ubuntu-24.04-arm` for Linux, and `macos-latest`, which runs on Apple Silicon. They run the same `just test` recipe as every other platform.

## Building ARM binaries locally

The simplest option is `cross`, which runs the build in a container that already has the right toolchain and linker. It needs Docker or Podman.

```sh
cargo install cross
cross build --locked --release --target aarch64-unknown-linux-gnu
# or, for 32-bit ARM:
cross build --locked --release --target armv7-unknown-linux-gnueabihf
```

The binary ends up at `target/<target>/release/rustscan`.

On an ARM machine (for example a Raspberry Pi running a 64-bit OS, or an Apple Silicon Mac) you don't need `cross`; a normal native build works:

```sh
cargo build --locked --release
```

## Troubleshooting

- **`error[E0463]: can't find crate for std`, or linker errors:** you're cross-compiling with plain `cargo`. Either use `cross`, or install the target (`rustup target add <target>`) along with a matching cross linker.
- **`cross` can't pull its image:** check that Docker or Podman is running and that your user can reach it.
