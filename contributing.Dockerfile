# Dockerfile for RustScan development environment
# Provides a containerized setup with Rust, nmap, and development tools
FROM rust
# Install nmap first.
RUN apt-get update -qy && apt-get install -qy nmap
# Then install rustfmt for code formatting and clippy for linting.
RUN rustup component add rustfmt clippy