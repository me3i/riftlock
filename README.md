# Riftlock

Riftlock is a Rust command-line security assessment tool for web applications and backend-as-a-service (BaaS) deployments. It combines discovery, provider-specific scanners, general web checks, and evidence-oriented reporting in one workspace. Use it only on systems you own or have explicit authorization to test.

## Contents

- [Capabilities](#capabilities)
- [Architecture](#architecture)
- [Requirements and build](#requirements-and-build)
- [Quick start](#quick-start)
- [Commands and options](#commands-and-options)
- [Providers and checks](#providers-and-checks)
- [Configuration and credentials](#configuration-and-credentials)
- [Safety model](#safety-model)
- [Reports and CI](#reports-and-ci)
- [Development and tests](#development-and-tests)
- [Workspace layout](#workspace-layout)
- [License](#license)

## Capabilities

- Discover routes, parameters, API schemas, client-side calls, and linked resources to inform scanner coverage.
- Run focused provider checks or automatically select applicable providers.
- Support passive reconnaissance, safe read-oriented probes, and a separately authorized Godmode preset for high-impact tests.
- Compare responses and validate concrete evidence before presenting an issue as a finding. Reports include scan coverage and areas that could not be tested, not just positive findings.
- Emit terminal, JSON, NDJSON, SARIF, self-contained HTML, Markdown, or PDF reports.
- Resume an interrupted scan from its checkpoint.

Findings are intended to be evidence-based, not a list of unverified heuristics. The implementation uses typed evidence and admission/verification paths to constrain how scanner results become reportable findings. This reduces false positives; it is not a guarantee that every result is correct or that every vulnerability will be found.

## Architecture

A scan generally follows this flow:

1. **CLI and configuration** parse the command, target, scope, depth, output, and optional credentials.
2. **Scope and transport controls** validate destinations and govern HTTP requests, rate limits, response-size handling, and session tiers.
3. **Discovery** gathers routes and useful artifacts such as API descriptions, parameters, and client-side endpoints.
4. **Scanner selection and engines** choose applicable checks, run them with bounded execution, and verify ambiguous results.
5. **Evidence and reporting** aggregate admitted findings, coverage, and untested surfaces into the selected report format.

The workspace is split into small Rust crates. See [Workspace layout](#workspace-layout) for the responsibilities of each package.

## Requirements and build

- Rust toolchain with Cargo (the workspace uses Rust 2021).
- For a static Linux musl release, the `x86_64-unknown-linux-musl` target and a compatible linker such as `musl-gcc`.

Build and test locally:

```sh
cargo build --workspace
cargo test --workspace
```

Build an optimized host binary:

```sh
cargo build --release -p riftlock-cli
./target/release/riftlock --help
```

## Quick start

A safe default scan uses read depth and human-readable terminal output:

```sh
riftlock scan https://your-authorized-target.example
```

Run one provider explicitly and save a SARIF report:

```sh
riftlock scan https://your-authorized-target.example \
  --provider supabase \
  --depth read \
  --format sarif \
  --output riftlock.sarif
```

Pass a scope file when testing a lab or when the assessment needs explicit scope configuration:

```sh
riftlock scan https://lab.example \
  --scope-file scope.yaml \
  --provider auto
```

The `riftlock` executable is produced under `target/` by Cargo; it is not installed globally by this repository.

### From source

```sh
git clone <repository-url>
cd <repository-directory>
cargo build --workspace
cargo test --workspace
```

To install the CLI into Cargo's user binary directory, run `cargo install --path crates/cli` from the workspace root. Ensure that directory is on your `PATH`.

## Commands and options

### `riftlock scan [URL]`

Runs the scanner pipeline with full control over providers, scan depth, scope, credentials, and output. If the URL is omitted, a `target` may be supplied in `riftlock.toml`.

Common options:

| Option | Purpose |
|---|---|
| `--provider <NAME>` | Select a provider or use `auto` to run providers that accept the target. |
| `--depth normal\|read` | Choose passive reconnaissance (`normal`) or safe active checks (`read`, default). |
| `--godmode` | Select the all-probes preset for an authorized assessment. This is a separate flag, not a `--depth` value. |
| `--scope <ORIGINS>` | Comma-separated allowed origins. By default, the target's own origin is in scope. |
| `--scope-file <PATH>` | Load explicit target and authorization settings from a scope YAML file. |
| `--allow-private true` | Permit private/internal destinations, such as a local lab. Use only when authorized. |
| `--bearer <TOKEN>` / `--cookie <VALUE>` | Provide a default authorization header or cookie for requests. |
| `--format <FORMAT>` | Choose `human`, `json`, `ndjson`, `sarif`, `html`, `markdown` (also `md`), or `pdf`. |
| `--output <PATH>` | Write the formatted report to a file. Required for PDF output. |
| `--quiet` | Suppress lifecycle progress and the final report. |
| `--config <PATH>` | Load defaults from a TOML file instead of the implicit `./riftlock.toml`. |
| `--wordlist <PATH>` | Provide parameter names for endpoint fuzzing; one name per line, with `#` comments. |
| `--discovery-budget <SECONDS>` | Set the discovery wall-clock budget (default 300 seconds). This changes discovery only. |
| `--resume <SCAN_ID>` | Resume from a scan checkpoint. Target and scan settings are loaded from that checkpoint; format/output can still be selected. |

Use `riftlock scan --help` for the complete, version-specific option list.

### `riftlock audit <URL>`

Runs all applicable scanners at read depth by default and produces a SARIF report. It can be used as a simple CI entry point. A scope file may authorize escalation to write depth; `--godmode` explicitly selects the Godmode preset and still requires authorization.

```sh
riftlock audit https://your-authorized-target.example
riftlock audit https://lab.example --scope-file scope.yaml --godmode
```

### `riftlock fingerprint <URL>`

Passively examines a page and its client-side resources for exposed Supabase key material. This command is intended for fingerprinting and does not run the active provider scan pipeline.

```sh
riftlock fingerprint https://your-authorized-target.example
```

### Exit status

Completed scans return `0` for no reportable findings, `1` when findings are reported, and `2` for an incomplete scan or operational error. Scope/authorization aborts may return `3`. The `audit` command has its own outcome path; validate its behavior before using it as an automated release gate.

## Providers and checks

The `auto` provider mode asks each provider whether it applies to the target. The following provider names are accepted by `scan` (availability depends on target technology and the evidence each check can validate):

| Provider | Focus |
|---|---|
| `supabase` | Supabase REST, storage, RPC, exposed keys, and authorization differences. |
| `firebase` | Firebase Realtime Database and Firestore access/rules. |
| `appwrite` | Appwrite collection access and authorization. |
| `nextjs` | Next.js server-action and related application surfaces. |
| `clerk` | Clerk-related authentication surfaces. |
| `cache` | Cache-deception and cache behavior checks. |
| `path` | Path normalization and route access checks. |
| `graphql` | GraphQL query behavior, batching, and alias-related limits. |
| `ssrf` | Server-side request behavior on discovered parameters. |
| `race` | Concurrency behavior for selected operations. |
| `signedurl` | Signed-URL path and traversal behavior. |
| `prototype` | Prototype-pollution behavior in JSON-facing surfaces. |
| `smuggling` | HTTP request-smuggling behavior. |
| `websocket` | WebSocket/realtime authorization behavior. |
| `oauth` | OAuth redirect and state-handling behavior. |
| `sse` | Server-sent-event authorization behavior. |
| `clientside` | Client-side source and security checks. |
| `supplychain` | Client-side dependency and supply-chain checks. |
| `llm` | LLM application checks. |
| `grpc` | gRPC service checks. |
| `generic` | General web checks, including selected injection and error-signature probes. |
| `spa` | Browser-driven single-page application discovery and DOM analysis. Requires Chromium. |
| `openapi` | Checks endpoints described by OpenAPI/Swagger documents. |
| `auth` | Authentication-matrix checks when operator-provided credentials are available. |
| `misconfig` | Common web configuration checks. |
| `infra` | Infrastructure and transport configuration checks. |

Discovery can enrich checks with routes, API descriptions, client-side endpoints, and parameter candidates. Some providers or checks may be skipped when their prerequisites are absent; review coverage and untested-surface output when interpreting a clean result.

## Configuration and credentials

### `riftlock.toml`

When present in the working directory, `./riftlock.toml` supplies scan defaults. Use `--config <PATH>` to select another file. CLI arguments take precedence over file values. Supported fields are:

```toml
# Optional defaults; omit fields you do not need.
target = "https://your-authorized-target.example"
depth = 2
format = "human"
allow_private = false
wordlist = "./params.txt"
discovery_budget = 300
```

The `depth` field is numeric in the current configuration model; the CLI's named depth options are `normal` and `read`. An explicit config path must point to a readable, valid TOML file.

### Scope file

A scope file can describe the authorized target and, when applicable, explicitly authorize destructive/write probes. Keep authorization details accurate and specific to the target. Example:

```yaml
target: https://lab.example
max_depth: write
allow_destructive: true
authorized_by: <authorized-person>
authorized_at: <ISO-8601 timestamp>
```

Without scope-file authorization for destructive tests, Godmode requires interactive confirmation. Do not use Godmode on production systems unless the owner has explicitly authorized those exact tests.

### Environment variables

| Variable | Purpose |
|---|---|
| `RIFTLOCK_SESSION_GUEST` | Guest-tier cookie/session data for differential checks. |
| `RIFTLOCK_SESSION_USER_A` | User A session; also used by browser discovery where supported. |
| `RIFTLOCK_SESSION_USER_B` | User B session for cross-user authorization checks. |
| `RIFTLOCK_SESSION_ADMIN` | Administrator session for privileged-tier comparisons. |
| `RIFTLOCK_USER_A_EMAIL` / `RIFTLOCK_USER_A_PASS` | Credentials for the authentication provider's login flow. If unset, that flow is skipped. |
| `RIFTLOCK_SB_LOW` / `RIFTLOCK_SB_ADMIN` / `RIFTLOCK_SB_HIGH` | Supabase keys used for tiered authorization comparisons. |

Session tiers are optional; absent credentials are skipped rather than guessed. Treat environment variables, scope files, checkpoints, and reports as potentially sensitive because they can identify targets or contain assessment details.

## Safety model

Riftlock is intended for authorized testing. Its controls include:

- **Scope validation:** requests are checked against allowed origins before being sent. Redirects are not followed by the HTTP client, preventing an automatic redirect from bypassing scope checks.
- **Private-address opt-in:** private/internal targets require the explicit `--allow-private true` option.
- **Separate high-impact mode:** `normal` is passive-oriented; `read` is the default safe active tier; Godmode enables high-impact/destructive probe classes and is never the implicit default.
- **Destructive-test authorization:** Godmode requires the normal scope authorization path: an authorizing scope file or interactive confirmation. Use a dedicated lab whenever possible.
- **Bounded execution:** provider work, request pacing, response bodies, and discovery have limits. Raising the discovery budget does not change request timeouts, scope, rate limits, or engine budgets.
- **Evidence handling:** ambiguous responses are verified or left inconclusive rather than automatically promoted to confirmed findings. Secrets are masked in reports by default; `--show-secrets` is restricted to interactive terminal output.

No automated scanner can prove that a target is safe. A clean report means only that the enabled checks did not establish reportable findings within the tested surface and constraints.

## Reports and CI

Output formats:

- `human` — terminal report.
- `json` — one machine-readable JSON document.
- `ndjson` — newline-delimited events suitable for streaming/log processing.
- `sarif` — SARIF 2.1.0 for code-scanning integrations.
- `html` — self-contained HTML report.
- `markdown` / `md` — Markdown report.
- `pdf` — PDF file; pass `--output` because binary data must not be written as terminal text.

Examples:

```sh
riftlock scan https://staging.example --format json --output report.json
riftlock scan https://staging.example --format ndjson > scan.ndjson
riftlock scan https://staging.example --format html --output report.html
riftlock scan https://staging.example --format sarif --output report.sarif
```

For a GitHub Actions workflow, build and test the project before running a scan. Point any scan step at a staging or lab target for which the workflow has explicit authorization, store credentials as protected secrets, and upload the SARIF output with the GitHub Code Scanning upload action. Never put production credentials or private target details into a public workflow or report artifact.

## Development and tests

Run the full workspace tests with:

```sh
cargo test --workspace
```

Run tests for an individual package or test name with Cargo's standard selectors, for example:

```sh
cargo test -p riftlock-report
cargo test -p riftlock-cli problem_counts_distinguish_groups_from_findings
```

The workspace includes unit tests and integration tests. HTTP-facing integration tests use controlled local fixtures; they do not require a production target. Keep tests in the repository: they document expected behavior and protect scope, reporting, and scanner regressions.

Format Rust code with:

```sh
cargo fmt --all
cargo fmt --all -- --check
```

Do not run active scans as part of ordinary development verification unless the target is explicitly authorized. The build and test commands above do not scan external targets.

## Workspace layout

| Path / crate | Responsibility |
|---|---|
| `crates/cli` (`riftlock`) | CLI commands, argument/config handling, orchestration, checkpoint/resume, and output selection. |
| `crates/core` | Shared types and controls: scope, HTTP transport, sessions, evidence, proof admission, coverage, rate limiting, and verification primitives. |
| `crates/discovery` | Route, schema, parameter, AST, and crawler-based discovery. |
| `crates/engine` | Scanner routing and shared execution/verification machinery. |
| `crates/fingerprint` | Passive fingerprinting, including exposed client-side key material. |
| `crates/report` | Shared report summaries and human/machine exporters: JSON, NDJSON, SARIF, HTML, Markdown, and PDF. |
| `crates/scanners/*` | Focused scanner crates, one per provider or vulnerability area listed above. |

## License

The workspace declares `MIT OR Apache-2.0`. See the repository's license files or package metadata for the applicable license text.
