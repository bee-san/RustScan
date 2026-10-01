# Dockerfile for RustScan development environment
# Provides a containerized setup with Rust and development tools
FROM rust
# Install rustfmt for code formatting and clippy for linting.
RUN rustup component add rustfmt clippy
