# GitHub Actions Workflows

This repository includes automated GitHub Actions workflows for building and testing RustScan across multiple platforms.

## Workflows

### 1. CI Workflow (`.github/workflows/ci.yml`)
- **Trigger**: Every push to main/master branch and pull requests
- **Purpose**: Run tests, formatting checks, and clippy lints
- **Platforms**: Ubuntu, Windows, macOS
- **Actions**:
  - Code formatting check (`cargo fmt`)
  - Clippy linting (`cargo clippy`)
  - Unit tests (`cargo test`)
  - Build verification for each platform

### 2. Release Workflow (`.github/workflows/release.yml`)
- **Trigger**: 
  - When a tag starting with `v` is pushed (e.g., `v2.4.1`)
  - Manual workflow dispatch
- **Purpose**: Build release binaries for all platforms and create GitHub Release
- **Platforms**:
  - Windows x64 (MSVC)
  - macOS Intel x64
  - macOS Apple Silicon (ARM64)
  - Linux x64 (GNU)
  - Linux ARM64 (GNU)

## How to Create a Release

### Method 1: Tag-based Release (Recommended)
```bash
# Create and push a version tag
git tag v2.4.1
git push origin v2.4.1
```

### Method 2: Manual Release
1. Go to the "Actions" tab in your GitHub repository
2. Select "Build and Release" workflow
3. Click "Run workflow"
4. Enter the version number (e.g., `v2.4.1`)
5. Click "Run workflow"

## Generated Artifacts

Each release automatically generates the following packages:

| Platform | File | Description |
|----------|------|-------------|
| Windows x64 | `rustscan-x86_64-pc-windows-msvc.zip` | Windows executable with installer |
| macOS Intel | `rustscan-x86_64-apple-darwin.tar.gz` | macOS binary for Intel Macs |
| macOS ARM64 | `rustscan-aarch64-apple-darwin.tar.gz` | macOS binary for Apple Silicon |
| Linux x64 | `rustscan-x86_64-unknown-linux-gnu.tar.gz` | Linux binary for x64 systems |
| Linux ARM64 | `rustscan-aarch64-unknown-linux-gnu.tar.gz` | Linux binary for ARM64 systems |

Each package includes:
- The compiled `rustscan` binary
- `README.md` and `LICENSE` files
- `config.toml` configuration file
- `install.sh` installation script
- `SHA256SUMS` checksum file for verification

## Installation for Users

Users can install RustScan by:

1. **Download**: Go to the [Releases page](../../releases) and download the appropriate package
2. **Extract**: Unzip or untar the downloaded file
3. **Install**: Run the installation script:
   ```bash
   # For Unix-like systems (Linux/macOS)
   ./install.sh
   
   # For Windows
   # Just run the install.sh script in Git Bash or WSL
   ```

## Caching

The workflows use cargo caching to speed up builds:
- Cargo registry cache
- Cargo git index cache  
- Target build cache

This significantly reduces build times for subsequent runs.

## Security

- Uses official GitHub Actions with pinned versions
- No external dependencies or custom scripts
- All builds are performed in isolated GitHub-hosted runners
- Generated binaries are automatically checksummed for verification