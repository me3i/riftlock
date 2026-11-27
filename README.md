<div align="center">
  <img src="assets/riftlock-banner.png" alt="Riftlock emblem" width="420" />

  <h1>RIFTLOCK</h1>
  <p><strong>Find the gap. Prove the exposure.</strong></p>
  <p>Evidence-first security assessment for web applications and BaaS.</p>
</div>

## Install on Linux

Install the latest Linux release. This downloads the installer from jsDelivr (not GitHub Raw), then runs it after the download completes:

```sh
curl -fL --retry 5 --retry-all-errors --connect-timeout 15 \
  https://cdn.jsdelivr.net/gh/me3i/riftlock@806304d/install.sh -o install.sh
bash install.sh
```

If no release is available yet, clone the repository and run the installer. It builds from source, so Rust and Cargo are required:

```sh
git clone https://github.com/me3i/riftlock.git
cd riftlock
chmod +x install.sh
./install.sh
```

## Usage

Scan a system you own or are authorized to test:

```sh
riftlock scan https://your-authorized-target.example
```

Choose a provider and export a SARIF report:

```sh
riftlock scan https://your-authorized-target.example \
  --provider supabase \
  --format sarif \
  --output report.sarif
```

Run `riftlock --help` or `riftlock scan --help` to see all commands and options.

## Features

- Web application and BaaS security checks
- Automatic discovery and provider selection
- Evidence-based findings and scan coverage
- Terminal, JSON, SARIF, HTML, Markdown, and PDF reports

## Build from source

Requires Rust and Cargo.

```sh
cargo build --workspace
cargo test --workspace
```

## Authorization

Use Riftlock only on systems you own or have explicit permission to test. High-impact checks require separate authorization.

## License

See [LICENSE](LICENSE).
