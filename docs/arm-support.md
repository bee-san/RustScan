# ARM support

This document explains how RustScan's ARM support works, how to build ARM binaries locally, and how the CI pipeline validates ARM builds and tests.

## What ARM targets are supported

The CI pipeline builds and tests Linux ARM64 using the target:

- `aarch64-unknown-linux-gnu`

The build pipeline also produces additional Linux artifacts for other targets, but ARM validation focuses on aarch64 Linux.

## CI overview (GitHub Actions)

ARM support is provided via GitHub Actions using `actions/setup-rust` plus `cross` for cross-compilation. The pipeline includes:

- A build matrix that includes `aarch64-unknown-linux-gnu` for Linux builds.
- A dedicated ARM test job that runs `cross test` for the aarch64 target.
- Explicit Python installation and dependency setup for the scripting integration tests.

Key files:

- CI workflows: [.github/workflows/build.yml](../.github/workflows/build.yml) and [.github/workflows/test.yml](../.github/workflows/test.yml)
- Cross configuration: [Cross.toml](../Cross.toml)

### Why `cross`

`cross` runs builds and tests inside a container that has the right toolchain for the target. This avoids local toolchain setup and makes the aarch64 Linux build reproducible in CI.

### Python dependencies in ARM CI

RustScan’s scripting tests execute a Python script from the fixtures directory, so Python must exist in the test environment. For ARM CI, Python is installed in the cross container using the `pre-build` hooks in [Cross.toml](../Cross.toml).

## Local builds for ARM

You can build ARM binaries locally using `cross` on any host OS that supports Docker/Podman.

### 1) Install cross

```
cargo install cross
```

### 2) Build for aarch64 Linux

```
cross build --locked --release --target aarch64-unknown-linux-gnu
```

The resulting binary is located at:

```
target/aarch64-unknown-linux-gnu/release/rustscan
```

## Local tests for ARM

Run the test suite for the ARM target with:

```
cross test --target aarch64-unknown-linux-gnu
```

This runs the Rust unit and integration tests inside the aarch64 container. The Python script-based test is included and relies on the Python setup defined in [Cross.toml](../Cross.toml).

## Customizing the ARM container

If you need additional tools in the ARM container (for example, extra Python packages), update the `pre-build` list in [Cross.toml](../Cross.toml). The current configuration installs Python and basic packaging tools.

## Troubleshooting

### Python script test failures

If the `run_python_script` test fails, verify that the container has Python installed and that the script shebang is executable. In CI, this is handled by the `pre-build` steps in [Cross.toml](../Cross.toml). For local use, ensure your Docker/Podman backend is functioning and that `cross` can download the base image.

### Missing target errors

If you see target-related errors, ensure `cross` is installed and you are using the correct target triple:

- `aarch64-unknown-linux-gnu`

## FAQ

**Does this add native ARM runners?**

No. The ARM jobs run on standard GitHub-hosted runners and use `cross` to build and test aarch64 Linux in containers.

**Can I build ARM binaries without cross?**

Yes, but you’ll need to install a compatible target toolchain and linker locally. `cross` is the recommended approach because it’s consistent with CI.
