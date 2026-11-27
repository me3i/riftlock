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

To build from a local clone instead:

```sh
git clone https://github.com/me3i/riftlock.git
cd riftlock
./install.sh
```

Check `install.sh` for prerequisites on other Linux distributions. The supplied release builds are Linux-only.

## Quick start

Only scan systems you own or have explicit permission to assess. The default `read` depth performs safe active checks. Start with passive discovery using `normal`:

```sh
riftlock scan https://your-authorized-target.example --depth normal
riftlock scan https://your-authorized-target.example
```

Completed scans save a self-contained HTML report. Unless `--format html` selects the primary report, Riftlock writes it to a timestamped file in the current directory; for HTML output, `--output` sets the path, or Riftlock chooses a timestamped filename when omitted. `--format` selects the primary report format, and `--output` writes it to the chosen path. With `--format human`, `--output` instead saves a SARIF report. PDF requires `--output`.

```sh
riftlock scan https://your-authorized-target.example \
  --provider supabase --format sarif --output report.sarif
riftlock scan https://your-authorized-target.example \
  --format pdf --output report.pdf
```

LAN/private targets are permitted when explicitly named. Requests remain host-scoped; a non-empty `--scope` replaces the default target origin, so include the target if it should remain in scope:

```sh
riftlock scan http://192.168.1.10/
riftlock scan https://app.example.test --scope https://app.example.test,https://api.example.test
```

## Commands

- `riftlock scan [URL]` — run selected scanners (default `--provider auto`), with configurable depth and output. URL can be omitted when `target` is set in `riftlock.toml`.
- `riftlock audit URL` — run all applicable scanners and write `./riftlock-report.sarif`; read depth is the default.
- `riftlock fingerprint URL` — passively inspect the page and its bundles for Supabase key material.

Run `riftlock --help`, `riftlock scan --help`, `riftlock audit --help`, or `riftlock fingerprint --help` for the complete option reference. The scan command accepts `--bearer`, `--cookie`, `--provider`, `--depth`, `--quiet`, `--scope-file`, `--scope`, `--format`, `--output`, `--show-secrets`, `--config`, `--wordlist`, `--discovery-budget`, `--godmode`, and `--resume`.

### Depth and authorization

- `--depth normal` performs passive discovery/fingerprinting without active payloads, with a 5 requests/second rate limit. It may still send GET requests for passive observations.
- The default `--depth read` performs safe active checks, with a 20 requests/second rate limit; state-changing methods are blocked.
- `--godmode` selects destructive/high-impact probes at 50 requests/second. Use it only with explicit authorization. A matching `--scope-file` must set `max_depth: write` and `allow_destructive: true`, or an interactive operator must type `yes` at the TTY prompt. Non-interactive godmode without a scope file is refused. A scope file is YAML:

```yaml
target: https://your-authorized-target.example
max_depth: write
allow_destructive: true
authorized_by: "Your name or team"
authorized_at: "2026-11-27T12:00:00Z"
```

A scope file authorizes destructive probes only when `target` has the same host as the scan URL, `max_depth` is `write`, and `allow_destructive` is `true`. Host matching ignores scheme and port; `--scope` separately controls which hosts Riftlock may request.

### Config, wordlists, and resume

An optional `./riftlock.toml` supplies defaults for scan runs. CLI options override those defaults:

```toml
target = "https://your-authorized-target.example"
depth = 0                 # 0 = normal; any nonzero value = read
format = "sarif"
wordlist = "./parameters.txt"
discovery_budget = 300    # seconds
```

Use `--config PATH` to load another config file. `--wordlist PATH` supplies endpoint parameter names, one per line (`#` begins a comment); otherwise the built-in list is used. `--discovery-budget SECONDS` changes only the discovery wall-clock budget, not request timeouts, scope or rate limits. Interrupted scans print a scan ID and save a checkpoint; resume with `riftlock scan --resume SCAN_ID`. Checkpoints may contain target, scope and scan state, so handle them as sensitive data.

### Reports and exit status

Supported `--format` values are `human` (default), `json`, `ndjson`, `sarif`, `html`, `markdown` (`md` alias), and `pdf`. JSON is one array; NDJSON is one object per line. All formats are also accompanied by the automatic HTML report, except `html`, which is itself the primary report. `--show-secrets` can reveal full credential values only in interactive human terminal output; avoid it on shared terminals.

Exit status: `0` clean, `1` findings, `2` scan error or incomplete coverage, `3` scope/authorization refusal. Treat incomplete coverage as a non-clean result.

## Features

- Web application and BaaS security checks
- Automatic discovery and provider selection
- Evidence-based findings and coverage accounting
- Terminal, JSON, NDJSON, SARIF, HTML, Markdown, and PDF reports

## Build and test from source

Requires Rust and Cargo.

```sh
cargo build --workspace
cargo test --workspace
```

## Authorization

Use Riftlock only on systems you own or have explicit written permission to test. Safe-read checks still generate network traffic; destructive probes can change state, trigger defenses, or affect production data. Local/LAN access is not itself proof of authorization.

## License

See [LICENSE](LICENSE).
