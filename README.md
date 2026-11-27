<div align="center">
  <img src="assets/riftlock-banner.png" alt="Riftlock emblem" width="420" />

  <h1>RIFTLOCK</h1>
  <p><strong>Find the gap. Prove the exposure.</strong></p>
  <p>Evidence-first security assessment for web applications and BaaS.</p>
</div>

## Install (Linux)

The installer supports Linux x86_64 and aarch64. It downloads the latest musl release binary (Rust is not needed) and verifies it against the release checksum when available. If no release binary is available, it builds from source and may install Rust with rustup.

```sh
curl -fsSL https://raw.githubusercontent.com/me3i/riftlock/main/install.sh | bash
```

By default the installer writes to `/usr/local/bin` and may ask for `sudo`. To install to a writable directory, set `RIFTLOCK_INSTALL_DIR`, for example:

```sh
curl -fsSL https://raw.githubusercontent.com/me3i/riftlock/main/install.sh | env RIFTLOCK_INSTALL_DIR="$HOME/.local/bin" bash
```

## Manual Install

To build from a local clone instead:

```sh
git clone https://github.com/me3i/riftlock.git
cd riftlock
./install.sh
```

Check `install.sh` for prerequisites on other Linux distributions. The supplied release builds are Linux-only.

## Quick start

Only scan systems you own or have explicit permission to assess. Start with passive discovery, then use the default `read` depth for safe active checks:

```sh
riftlock scan https://your-authorized-target.example --depth normal
riftlock scan https://your-authorized-target.example
```

## Commands

- `riftlock scan [URL]` — run selected scanners (default `--provider auto`), with configurable depth and output. URL can be omitted when `target` is set in `riftlock.toml`.
- `riftlock audit URL` — run all applicable scanners and write `./riftlock-report.sarif`; read depth is the default.
- `riftlock fingerprint URL` — passively inspect the page and its bundles for Supabase key material.

Run `riftlock --help`, `riftlock scan --help`, `riftlock audit --help`, or `riftlock fingerprint --help` for command options.

## Scope and authorization

Requests are host-scoped. LAN/private targets are permitted when explicitly named, but local network access is not itself authorization. A non-empty `--scope` replaces the default target origin, so include the target if it should remain in scope:

```sh
riftlock scan http://192.168.1.10/
riftlock scan https://app.example.test --scope https://app.example.test,https://api.example.test
```

The default `--depth read` performs safe active checks; state-changing methods are blocked. `--depth normal` performs passive discovery and fingerprinting without active payloads, but may still send GET requests for passive observations. Rate limits are 5 requests/second for `normal`, 20 for `read`, and 50 for `--godmode`.

`--godmode` enables destructive/high-impact probes and requires explicit authorization. A matching scope file must set `max_depth: write` and `allow_destructive: true`; without a scope file, an interactive operator must type `yes` at the TTY prompt. Non-interactive godmode without a scope file is refused. Example scope file:

```yaml
target: https://your-authorized-target.example
max_depth: write
allow_destructive: true
authorized_by: "Your name or team"
authorized_at: "2026-11-27T12:00:00Z"
```

The scope file's `target` must have the same host as the scan URL; scheme and port do not affect this match. `--scope` separately controls which hosts Riftlock may request.

## Configuration and discovery

An optional `./riftlock.toml` supplies defaults for scan runs. CLI options override those defaults:

```toml
target = "https://your-authorized-target.example"
depth = 0                 # 0 = normal; any nonzero value = read
format = "sarif"
wordlist = "./parameters.txt"
discovery_budget = 300    # seconds
```

Use `--config PATH` to load another config file. `--wordlist PATH` supplies endpoint parameter names, one per line (`#` begins a comment); otherwise the built-in list is used. `--discovery-budget SECONDS` changes only the discovery wall-clock budget, not request timeouts, scope, or rate limits. Interrupted scans print a scan ID and save a checkpoint; resume with `riftlock scan --resume SCAN_ID`. Checkpoints may contain target, scope, and scan state, so handle them as sensitive data.

## Reports and exit status

Supported `--format` values are `human` (default), `json`, `ndjson`, `sarif`, `html`, `markdown` (`md` alias), and `pdf`. JSON is one array; NDJSON is one object per line. Completed scans save a self-contained HTML report alongside the selected format, except when `html` is itself the primary report. For HTML output, `--output` sets the path; if omitted, Riftlock chooses a timestamped filename in the current directory. For other formats, `--output` writes the primary report to the chosen path. With `--format human`, `--output` instead saves a SARIF report. PDF requires `--output`.

`--show-secrets` can reveal full credential values only in interactive human terminal output; avoid it on shared terminals.

Exit status: `0` clean, `1` findings, `2` scan error or incomplete coverage, `3` scope/authorization refusal. Treat incomplete coverage as a non-clean result.

## Build and test from source

Requires Rust and Cargo.

```sh
cargo build --workspace
cargo test --workspace
```

## License

See [LICENSE](LICENSE).
