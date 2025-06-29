# Dockerfile for RustScan development environment
# Provides a containerized setup with Rust, nmap, and development tools
FROM rust
# Install nmap first.
RUN apt-get update -qy && apt-get install -qy nmap
# Then install rustfmt and clippy for cargo.
RUN rustup component add rustfmt clippy