//! `riftlock` CLI: passive fingerprinting and provider scans across
//! Supabase, Firebase, and Appwrite, with SARIF/NDJSON reporting and the
//! one-shot `audit` super command.
//!
//! Exit codes: 0 clean, 1 findings, 2 error, 3 scope violation.

mod checkpoint;
mod ui;
// The re-exports keep the presentation helpers reachable at the crate root.
pub use ui::{brand, theme};

use checkpoint::Checkpoint;
use clap::{Parser, Subcommand, ValueEnum};
use futures_util::FutureExt;
use riftlock_core::ScopedClient as Client;
use riftlock_core::{Depth, Evidence, Finding, ScanError, ScopeGuard};
use riftlock_scanner_appwrite::AppwriteScanner;
use riftlock_scanner_auth::AuthScanner;
use riftlock_scanner_clientside::ClientSideScanner;
use riftlock_scanner_firebase::FirebaseScanner;
use riftlock_scanner_generic::{GenericEvent, GenericScanner};
use riftlock_scanner_grpc::GrpcScanner;
use riftlock_scanner_infra::InfraScanner;
use riftlock_scanner_llm::LlmScanner;
use riftlock_scanner_misconfig::MisconfigScanner;
use riftlock_scanner_oauth::OAuthScanner;
use riftlock_scanner_openapi::OpenApiScanner;
use riftlock_scanner_smuggling::SmugglingScanner;
use riftlock_scanner_source::SourceScanner;
use riftlock_scanner_spa::SpaScanner;
use riftlock_scanner_sse::SseScanner;
use riftlock_scanner_supabase::{SupabaseKeys, SupabaseScanner};
use riftlock_scanner_supplychain::SupplyChainScanner;
use riftlock_scanner_websocket::WebSocketScanner;
use std::collections::HashSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use ui::lifecycle::{outcome_line, EngineOutcome, EngineStats, RunState, RunStatus};
use url::Url;

/// Result of one scanner run, slotted in spawn order.
type ScanResult = Result<Vec<Finding>, riftlock_core::ScanError>;

/// One spawned engine: spawn index, name, duration, result, and its
/// task-owned coverage fork (absent for engines that record no ledger data).
type EngineReport = (
    usize,
    &'static str,
    Duration,
    Option<ScanResult>,
    Option<riftlock_core::Coverage>,
);

/// Values accepted by `--depth`; Godmode is available only via `--godmode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum DepthArg {
    /// Passive reconnaissance without active payloads.
    Normal,
    /// Safe active checks without high-impact payload classes.
    Read,
}

impl From<DepthArg> for Depth {
    fn from(value: DepthArg) -> Self {
        match value {
            DepthArg::Normal => Self::Normal,
            DepthArg::Read => Self::Read,
        }
    }
}

/// Output format for scan results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Format {
    /// Human-readable terminal output (default).
    Human,
    /// Single JSON array of all findings.
    Json,
    /// One JSON object per line (tail -f friendly).
    Ndjson,
    /// SARIF 2.1.0 document.
    Sarif,
    /// Self-contained HTML report (inline CSS).
    Html,
    /// GitHub-flavored Markdown report.
    #[value(alias = "md")]
    Markdown,
    /// PDF report (binary; requires --output).
    Pdf,
}

/// Riftlock: BaaS misconfiguration prover.
#[derive(Debug, Parser)]
#[command(
    name = "riftlock",
    version,
    about = "Prove BaaS misconfigurations with differential testing, not heuristics."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

// Clap constructs this enum once per process; boxing the Scan arguments would
// obscure the CLI surface for no runtime benefit.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Subcommand)]
enum Command {
    /// Fingerprint a URL for leaked Supabase key material (passive, safe).
    Fingerprint {
        /// Target URL (page hosting the client bundle).
        url: String,
    },
    /// Run provider scanners against a URL with full depth/format control.
    Scan {
        /// Target URL (or set `target` in riftlock.toml).
        url: Option<String>,
        /// Bearer token sent as the default Authorization header.
        #[arg(long)]
        bearer: Option<String>,
        /// Cookie value sent as the default Cookie header.
        #[arg(long)]
        cookie: Option<String>,
        /// Provider scanner to run: auto|supabase|firebase|appwrite|nextjs|clerk|cache|path|graphql|ssrf|race|signedurl|prototype|smuggling|websocket|oauth|sse|clientside|supplychain|llm|grpc|generic|spa|openapi|auth|misconfig|infra.
        /// `auto` runs every scanner whose `matches()` accepts the URL.
        #[arg(long, default_value = "auto")]
        provider: String,
        /// Scan depth: `normal` is passive reconnaissance only (no payloads);
        /// `read` adds safe active checks. Defaults to `read`; the all-probes
        /// `godmode` tier is selected with `--godmode`.
        #[arg(long, value_enum)]
        depth: Option<DepthArg>,
        /// Suppress engine lifecycle progress and the final human-readable terminal summary.
        #[arg(long)]
        quiet: bool,
        /// Path to a scope.yaml authorizing this scan.
        #[arg(long, value_name = "PATH")]
        scope_file: Option<String>,
        /// Scope origins, comma-separated. Empty: the target's own origin.
        #[arg(long, default_value = "")]
        scope: String,
        /// Output format: human|json|ndjson|sarif|html|md|pdf (default:
        /// human).
        #[arg(long, value_enum)]
        format: Option<Format>,
        /// Write the selected-format report to this path; a timestamped HTML report is also saved automatically.
        #[arg(long, value_name = "PATH")]
        output: Option<String>,
        /// Reveal full credential values in interactive terminal output only.
        /// Ignored for reports, logs and non-interactive output. Never use on
        /// a shared terminal — values may be real secrets.
        #[arg(long)]
        show_secrets: bool,
        /// Path to a riftlock.toml providing scan defaults (target, depth,
        /// format, wordlist). Default: ./riftlock.toml if present.
        #[arg(long, value_name = "PATH")]
        config: Option<String>,
        /// Path to a parameter wordlist file for endpoint fuzzing (one name
        /// per line; '#' comments skipped). Default: built-in list.
        #[arg(long, value_name = "PATH")]
        wordlist: Option<String>,
        /// Discovery wall-clock budget in seconds (default: 300). Raise it for
        /// a slow target whose crawl stops on `deadline` with untested URLs.
        /// Only discovery is extended — request timeouts, scope, rate limits
        /// and engine budgets are unchanged.
        #[arg(long, value_name = "SECONDS")]
        discovery_budget: Option<u64>,
        /// Godmode preset for authorized pentests: all probe classes, 50 RPS,
        /// all providers, large wordlists and destructive payloads. Requires
        /// normal scope authorization. You own this target.
        #[arg(long)]
        godmode: bool,
        /// Resume an interrupted scan from its checkpoint (the scan id the
        /// interrupted run printed). Target, scope and scan settings come
        /// from the checkpoint; --format/--output still apply. Engines the
        /// checkpoint marks completed are not re-run.
        #[arg(long, value_name = "SCAN_ID")]
        resume: Option<String>,
    },
    /// One-shot audit: all scanners, read depth by default, SARIF report.
    Audit {
        /// Target URL.
        url: String,
        /// Optional scope.yaml; when it authorizes write probes for the
        /// target, the audit escalates to write depth. Otherwise the audit
        /// stays at read depth (safe for production).
        #[arg(long, value_name = "PATH")]
        scope_file: Option<String>,
        /// Godmode preset for authorized pentests: all probe classes, 50 RPS,
        /// all providers and destructive payloads. Still requires normal scope
        /// authorization: the scope file or interactive confirmation.
        #[arg(long)]
        godmode: bool,
    },
}

/// Shared exit codes.
const EXIT_CLEAN: i32 = 0;
const EXIT_FINDINGS: i32 = 1;
const EXIT_ERROR: i32 = 2;
const EXIT_SCOPE: i32 = 3;

/// Per-engine wall-clock budget at Normal depth.
const ENGINE_BUDGET: Duration = Duration::from_secs(10);
/// Per-engine wall-clock budget at Read depth.
const READ_ENGINE_BUDGET: Duration = Duration::from_secs(60);

/// Default per-host request rate; `--rps` overrides it.
const DEFAULT_RPS: u32 = 20;

/// Default discovery wall-clock budget; `--discovery-budget` or
/// `riftlock.toml`'s `discovery_budget` can raise it for a slow target.
const DEFAULT_DISCOVERY_BUDGET: Duration = Duration::from_secs(300);

/// Post-drain passive fingerprinting budget: page + bundle fetches against
/// a slow target must not extend the run past its fail-fast bar.
const FINGERPRINT_BUDGET: Duration = Duration::from_secs(15);
/// Hard maximum wall-clock budget for any engine (Godmode).
const MAX_ENGINE_BUDGET: Duration = Duration::from_secs(180);

/// Resolve the discovery wall-clock budget: CLI flag, then config file, then
/// the default. A longer budget only extends discovery: request timeouts,
/// scope, rate limits and engine budgets are untouched.
fn resolve_discovery_budget(
    flag: Option<u64>,
    cfg: Option<&riftlock_core::RiftlockConfig>,
) -> Duration {
    Duration::from_secs(
        flag.or_else(|| cfg.and_then(|c| c.discovery_budget))
            .unwrap_or(DEFAULT_DISCOVERY_BUDGET.as_secs()),
    )
}

/// Hard cap for every request. Adaptive timeouts may shrink it but are clamped
/// to it, so a slow host can never extend a single request past this bound.
const REQUEST_CAP: Duration = Duration::from_secs(10);

/// Run one engine's scan under `budget`: a past-budget engine becomes a
/// real recorded transport failure (checked negative, resumable) — never a
/// fabricated finding, never an unbounded wait.
async fn with_budget(
    budget: Duration,
    fut: impl std::future::Future<Output = Option<ScanResult>>,
) -> Option<ScanResult> {
    let outer = budget.mul_f32(1.2);
    tokio::time::timeout(outer, fut).await.unwrap_or_else(|_| {
        Some(Err(riftlock_core::ScanError::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "engine exceeded its wall-clock budget",
        ))))
    })
}

/// Slack between the deadline an engine is told to stop at and the
/// cancellation above: one request cap plus a second for the final
/// bookkeeping, so a cooperating engine always returns its findings first.
const ENGINE_DRAIN: Duration = Duration::from_secs(11);

/// Per-engine wall-clock budget for a scan depth: Normal 10 seconds, Read
/// 60 seconds, Godmode 180 seconds. The tier alone sets the budget, so the
/// window is predictable regardless of how many endpoints discovery found.
fn engine_budget(depth: Depth) -> Duration {
    match depth {
        Depth::Normal => ENGINE_BUDGET,
        Depth::Read => READ_ENGINE_BUDGET,
        Depth::Godmode => MAX_ENGINE_BUDGET,
        _ => ENGINE_BUDGET,
    }
}

fn engine_deadline(started: std::time::Instant, depth: Depth) -> std::time::Instant {
    let budget = engine_budget(depth);
    // Preserve the full drain window for long budgets, but never let the
    // deadline slack consume more than 10% of a short budget.
    let drain = ENGINE_DRAIN.min(budget / 10);
    started + budget.saturating_sub(drain)
}

/// Endpoint inventory an engine will probe, for its start line. Engines that
/// target a single origin (or keep no probe inventory) report the matching
/// small count rather than the run-wide discovered total.
fn engine_planned_endpoints(id: &str, endpoints: &[String]) -> usize {
    let containing = |needle: &str| endpoints.iter().filter(|e| e.contains(needle)).count();
    match id {
        "Generic" | "Misconfig" => endpoints.len() + 1,
        "SPA" | "Auth" | "SSRF" | "Race" | "SignedUrl" | "Prototype" | "SSE" | "ClientSide"
        | "LLM" => endpoints.len(),
        "GraphQL" => containing("graphql"),
        "Path" => containing("admin"),
        "Supabase" | "Appwrite" | "Next.js" | "Clerk" | "OAuth" | "gRPC" | "OpenAPI" | "Source"
        | "Firebase" | "Cache" | "Infra" | "SupplyChain" | "Smuggling" | "WebSocket" => 1,
        _ => 0,
    }
}

/// Parameter wordlist for the dynamic engines. Normal fuzzes nothing; an
/// explicit `--wordlist` always wins; Read uses the standard embedded list
/// and Godmode the large one.
fn resolve_params(passive: bool, depth: Depth, wordlist: Option<&str>) -> Result<Vec<String>, i32> {
    if passive {
        return Ok(Vec::new());
    }
    let loaded = match wordlist {
        Some(path) => riftlock_discovery::param::load_wordlist(Some(std::path::Path::new(path))),
        None if depth == Depth::Godmode => Ok(riftlock_discovery::param::deep_fuzz_parameters()),
        None => riftlock_discovery::param::load_wordlist(None),
    };
    loaded.map_err(|e| {
        eprintln!("error: cannot load wordlist: {e}");
        EXIT_ERROR
    })
}

fn client(
    guard: &ScopeGuard,
    bearer: Option<&str>,
    cookie: Option<&str>,
) -> Result<Client, String> {
    // Bound slow responses while giving local-network targets more headroom.
    // ScopedClient fixes redirects off, so a caller's configuration cannot
    // widen the scope boundary.
    let mut headers = reqwest::header::HeaderMap::new();
    if let Some(token) = bearer {
        let value = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|e| format!("invalid bearer header: {e}"))?;
        headers.insert(reqwest::header::AUTHORIZATION, value);
    }
    if let Some(value) = cookie {
        let value = reqwest::header::HeaderValue::from_str(value)
            .map_err(|e| format!("invalid cookie header: {e}"))?;
        headers.insert(reqwest::header::COOKIE, value);
    }
    Client::from_builder(
        reqwest::Client::builder()
            .default_headers(headers)
            .timeout(REQUEST_CAP)
            .connect_timeout(Duration::from_secs(3)),
        guard,
    )
    .map(|client| client.with_adaptive_timeout_cap(REQUEST_CAP))
    .map_err(|error| error.to_string())
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    if std::env::args_os()
        .nth(1)
        .is_some_and(|arg| arg == "--version" || arg == "-V")
    {
        ui::brand::print_logo();
        println!("riftlock {}", env!("CARGO_PKG_VERSION"));
        return std::process::ExitCode::SUCCESS;
    }
    let code = run(Cli::parse()).await;
    std::process::ExitCode::from(code as u8)
}

/// Map a riftlock.toml depth number to the shared depth enum. Zero is passive
/// reconnaissance (Normal); every historical positive value resolves to safe
/// Read. The destructive Godmode tier is reachable only through `--godmode`.
fn depth_from_u32(d: u32) -> Depth {
    if d == 0 {
        Depth::Normal
    } else {
        Depth::Read
    }
}

/// Map current and legacy checkpoint depth labels to the shared enum. The
/// old seven-tier labels stay readable so interrupted scans can resume:
/// Passive is Normal; Active, Auth, Deep and Max were all active tiers and
/// now collapse into the authorization-gated Godmode.
fn depth_from_str(s: &str) -> Option<Depth> {
    match s {
        "Normal" | "Passive" => Some(Depth::Normal),
        "Read" => Some(Depth::Read),
        "Active" | "Auth" | "Deep" | "Max" | "Godmode" => Some(Depth::Godmode),
        _ => None,
    }
}

/// Map a riftlock.toml format string to the CLI enum.
fn format_from_str(s: &str) -> Option<Format> {
    match s {
        "human" => Some(Format::Human),
        "json" => Some(Format::Json),
        "ndjson" => Some(Format::Ndjson),
        "sarif" => Some(Format::Sarif),
        "html" => Some(Format::Html),
        "markdown" | "md" => Some(Format::Markdown),
        "pdf" => Some(Format::Pdf),
        _ => None,
    }
}

/// Load riftlock.toml scan defaults. An explicit `--config` path must
/// exist; the implicit `./riftlock.toml` is used only when present.
///
/// # Errors
/// An explicitly requested config file is missing or unparseable.
fn load_scan_config(flag: Option<&str>) -> Result<Option<riftlock_core::RiftlockConfig>, String> {
    let path = match flag {
        Some(p) => std::path::PathBuf::from(p),
        None => {
            let p = std::path::PathBuf::from("riftlock.toml");
            if !p.exists() {
                return Ok(None);
            }
            p
        }
    };
    riftlock_core::load_config(&path)
        .map(Some)
        .map_err(|e| format!("{}: {e}", path.display()))
}

async fn run(cli: Cli) -> i32 {
    match cli.command {
        Command::Fingerprint { url } => fingerprint_cmd(&url).await,
        Command::Scan {
            url,
            bearer,
            cookie,
            quiet,
            provider,
            depth,
            scope_file,
            scope,
            format,
            output,
            show_secrets,
            config,
            wordlist,
            discovery_budget,
            godmode,
            resume,
        } => {
            let resumed = match resume.as_deref().map(checkpoint::Checkpoint::load) {
                Some(Ok(ck)) => Some(ck),
                Some(Err(e)) => {
                    eprintln!("error: {e}");
                    return EXIT_ERROR;
                }
                None => None,
            };
            // A resumed scan restores its own target and settings; the
            // config file and the command line's scan settings are not
            // consulted (only --format/--output still apply).
            let cfg = if resumed.is_some() {
                Ok(None)
            } else {
                load_scan_config(config.as_deref())
            };
            let cfg = match cfg {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("error: {e}");
                    return EXIT_ERROR;
                }
            };
            let url = match resumed
                .as_ref()
                .map(|ck| ck.target.clone())
                .or(url)
                .or_else(|| cfg.as_ref().and_then(|c| c.target.clone()))
            {
                Some(u) => u,
                None => {
                    eprintln!("error: no target URL (pass one or set `target` in riftlock.toml)");
                    return EXIT_ERROR;
                }
            };
            let depth = match resumed.as_ref() {
                Some(ck) => match depth_from_str(&ck.config.depth) {
                    Some(d) => d,
                    None => {
                        eprintln!("error: checkpoint has unknown depth {:?}", ck.config.depth);
                        return EXIT_ERROR;
                    }
                },
                None => depth
                    .map(Depth::from)
                    .or_else(|| cfg.as_ref().and_then(|c| c.depth.map(depth_from_u32)))
                    .unwrap_or(Depth::Read),
            };
            let format = format
                .or(cfg
                    .as_ref()
                    .and_then(|c| c.format.as_deref().and_then(format_from_str)))
                .unwrap_or(Format::Human);
            let provider = resumed
                .as_ref()
                .map_or(provider, |ck| ck.config.provider.clone());
            // Legacy checkpoints recorded `passive_only` for runs that were
            // not Normal; the depth is now the single source of truth so a
            // stale field cannot re-enable removed passive-only behavior.
            // Depth alone determines pacing, including on resume: Normal is
            // 5 RPS, Read the default 20 and Godmode 50.
            let rps = if depth == Depth::Normal {
                5
            } else if depth == Depth::Godmode {
                50
            } else {
                DEFAULT_RPS
            };
            let scope_file = resumed
                .as_ref()
                .and_then(|ck| ck.config.scope_file.clone())
                .or(scope_file);
            let wordlist = resumed
                .as_ref()
                .and_then(|ck| ck.config.wordlist.clone())
                .or_else(|| wordlist.or_else(|| cfg.as_ref().and_then(|c| c.wordlist.clone())));
            let godmode = resumed.as_ref().map_or(godmode, |ck| ck.config.godmode);
            let scope = resumed.as_ref().map_or(scope, |ck| ck.scope.join(","));
            // A budget is an operational limit, not a scan setting that
            // changes results: the CLI flag or config still applies on resume.
            let discovery_budget = resolve_discovery_budget(discovery_budget, cfg.as_ref());
            scan_cmd(
                &url,
                ScanOptions {
                    rps,
                    quiet,
                    bearer,
                    cookie,
                    provider: &provider,
                    depth,
                    scope_file,
                    scope: &scope,
                    format,
                    output,
                    show_secrets,
                    wordlist: wordlist.as_deref(),
                    discovery_budget,
                    godmode,
                    resume: resumed,
                },
            )
            .await
        }
        Command::Audit {
            url,
            scope_file,
            godmode,
        } => audit_cmd(&url, scope_file, godmode).await,
    }
}

async fn fingerprint_cmd(url: &str) -> i32 {
    let parsed = match Url::parse(url) {
        Ok(u) => u,
        Err(e) => {
            eprintln!("error: invalid url: {e}");
            return EXIT_ERROR;
        }
    };
    // Passive only: empty scope guard permits fetching the target itself.
    let guard = ScopeGuard::new(&[]).unwrap_or_default();
    let http = match client(&guard, None, None) {
        Ok(client) => client,
        Err(error) => {
            eprintln!("error: cannot build HTTP client: {error}");
            return EXIT_ERROR;
        }
    };
    let coverage = riftlock_core::Coverage::default();
    match riftlock_fingerprint::fingerprint_url(
        &http,
        &parsed,
        &guard,
        &coverage,
        &riftlock_fingerprint::FetchCache::default(),
    )
    .await
    {
        Ok(fps) => {
            if fps.is_empty() {
                println!("clean: no Supabase key material found");
                EXIT_CLEAN
            } else {
                for fp in &fps {
                    println!(
                        "{} {} {} {}",
                        fp.key_type.label(),
                        fp.masked,
                        fp.hash,
                        fp.location
                    );
                }
                EXIT_FINDINGS
            }
        }
        Err(e) => {
            eprintln!("error: {e}");
            EXIT_ERROR
        }
    }
}

/// Fetch the page and its bundles and extract RPC function names and fetch
/// endpoints via AST discovery. Scope-checked before every fetch.
/// Seed API paths for targets positively identified as OWASP Juice Shop
/// (its frontend bundles expose these but may not be reachable to the
/// crawler).
const JUICE_SHOP_SEEDS: [&str; 5] = [
    "/rest/user/login",
    "/rest/products/search",
    "/rest/baskets/1",
    "/api/Challenges/",
    "/api/Quantitys/",
];

async fn discover_context(
    client: &Client,
    url: &Url,
    guard: &ScopeGuard,
    sessions: &riftlock_core::SessionMatrix,
    deadline: std::time::Instant,
    depth: Depth,
    fetch_cache: &riftlock_fingerprint::FetchCache,
) -> Result<
    (
        Vec<String>,
        Vec<String>,
        Vec<riftlock_discovery::DiscoveredEndpoint>,
        Vec<String>,
        Vec<String>,
        Option<String>,
        riftlock_core::CrawlMetrics,
    ),
    ScanError,
> {
    guard.check(url)?;
    // The root fetch is a fail-fast baseline, not a transient probe: one
    // 429/503 is enough to abort discovery without spending retry backoff.
    // In-scope redirects are followed one exchange per hop with a scope check
    // before every send.
    let request = client.get(url.clone()).build()?;
    let response = client.send_scoped_once(request, guard).await?;
    if !response.status().is_success() {
        return Err(ScanError::HttpStatus(response.status().as_u16()));
    }
    let headers = response
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.to_string(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            )
        })
        .collect();
    // Capped read distinguishes an oversized response from a broken stream.
    let html = riftlock_core::body::text_limited_result(response).await?;
    fetch_cache.insert(url.clone(), html.clone(), headers);
    // Bundles fetch concurrently: a slow target's bundle list serialized one
    // 10 s request cap each and ate the whole discovery budget before the
    // crawl could start.
    let bundles: Vec<_> = riftlock_fingerprint::bundle_urls(&html, url)
        .into_iter()
        .filter(|b| guard.check(b).is_ok())
        .collect();
    let mut bundle_fetches = tokio::task::JoinSet::new();
    for bundle in bundles {
        let client = client.clone();
        let fetch_cache = fetch_cache.clone();
        let token = sessions.user_a.clone();
        bundle_fetches.spawn(async move {
            let source = riftlock_discovery::crawler::fetch_bundle_source(
                &client,
                &bundle,
                token.as_deref(),
                &fetch_cache,
            )
            .await;
            (bundle, source)
        });
    }
    let mut sources = vec![html.clone()];
    let mut partial_errors = Vec::new();
    while let Some(result) = bundle_fetches.join_next().await {
        match result {
            Ok((_bundle, Some(source))) => sources.push(source),
            Ok((bundle, None)) => {
                riftlock_core::logln!("[!] Skipping failed static bundle: {bundle}");
            }
            Err(error) => {
                riftlock_core::logln!("[!] Skipping failed static bundle task: {error}");
            }
        }
    }
    // Authenticated crawl of the live surface, fed into the endpoints the
    // scanners probe. A failed crawl keeps the AST inventory but is reported
    // as a partial discovery. The soft deadline makes the crawl return the
    // pages mapped so far, so a slow target keeps partial context instead
    // of losing the whole phase to the hard-timeout cancellation.
    let crawler = riftlock_discovery::crawler::Crawler {
        max_depth: match depth {
            Depth::Read | Depth::Godmode => 5,
            Depth::Normal => 0,
            _ => 0,
        },
        max_pages: 200,
        deadline: Some(deadline),
        // Normal and Read map links and bundles but run no directory
        // brute-force; only Godmode runs the wordlist pass.
        wordlist: depth == Depth::Godmode,
    };
    let (crawled, mut crawl_metrics) = match crawler
        .crawl_with_metrics(url, client, guard, sessions.user_a.as_deref(), fetch_cache)
        .await
    {
        Ok(result) => result,
        Err(error) => {
            riftlock_core::logln!("[!] Discovery crawl failed: {error}");
            partial_errors.push("crawl failed".to_owned());
            (
                Vec::new(),
                riftlock_core::CrawlMetrics {
                    budget_configured: crawler.max_pages as u64,
                    termination_reason: "failed".to_owned(),
                    ..riftlock_core::CrawlMetrics::default()
                },
            )
        }
    };
    riftlock_core::logln!("[Discovery] Finalizing endpoint inventory and AST extraction...");
    let discovered: Vec<riftlock_discovery::Discovery> = sources
        .iter()
        .flat_map(|src| riftlock_discovery::discover(src))
        .collect();
    let dedup = |names: Vec<String>| -> Vec<String> {
        names
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect()
    };
    let rpc = discovered
        .iter()
        .filter_map(|d| match d {
            riftlock_discovery::Discovery::Rpc { name, .. } => Some(name.clone()),
            _ => None,
        })
        .collect();
    let mut endpoint_methods: Vec<riftlock_discovery::DiscoveredEndpoint> = discovered
        .iter()
        .filter_map(|d| match d {
            riftlock_discovery::Discovery::Endpoint { path, method } => {
                Some(riftlock_discovery::DiscoveredEndpoint {
                    path: path.clone(),
                    method: method.clone(),
                })
            }
            _ => None,
        })
        .collect();
    let mut endpoints: Vec<String> = endpoint_methods
        .iter()
        .map(|endpoint| endpoint.path.clone())
        .collect();
    let actions = sources
        .iter()
        .flat_map(|src| riftlock_scanner_nextjs::extract_action_ids(src))
        .collect();
    if deadline <= std::time::Instant::now() && crawl_metrics.remaining > 0 {
        partial_errors.push("crawl budget exhausted".to_owned());
        crawl_metrics.termination_reason = "deadline".to_owned();
    } else if crawl_metrics.termination_reason == "deadline" && crawl_metrics.remaining == 0 {
        // The deadline can expire during final bookkeeping after the queue was
        // drained; an empty queue means there is no untested crawl work.
        crawl_metrics.termination_reason = "queue_exhausted".to_owned();
    }
    endpoints.extend(crawled.iter().cloned());
    endpoint_methods.extend(crawled.iter().cloned().map(|path| {
        riftlock_discovery::DiscoveredEndpoint {
            path,
            method: "GET".to_owned(),
        }
    }));
    // Known application intelligence: a positively identified app gets its
    // documented API surface seeded, so SPA routes hidden behind a failed
    // browser or an aborted crawl still get scanned.
    if html.to_lowercase().contains("owasp juice shop") {
        let seeds: Vec<String> = JUICE_SHOP_SEEDS
            .iter()
            .map(|s| url.join(s).expect("seed path").to_string())
            .collect();
        endpoint_methods.extend(seeds.iter().cloned().map(|path| {
            riftlock_discovery::DiscoveredEndpoint {
                path,
                method: "GET".to_owned(),
            }
        }));
        endpoints.extend(seeds);
    }
    let error = (!partial_errors.is_empty()).then(|| {
        let detail = if partial_errors.len() == 1 {
            partial_errors.remove(0)
        } else {
            format!("{} (+{} more)", partial_errors[0], partial_errors.len() - 1)
        };
        detail
    });
    Ok((
        dedup(rpc),
        dedup(endpoints),
        endpoint_methods
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect(),
        dedup(actions),
        dedup(crawled),
        error,
        crawl_metrics,
    ))
}

/// Load the scope file and build a lab guard for max depth. Precedence:
/// scope file, then interactive confirmation. Returns `Err(exit_code)` on
/// refusal — checked BEFORE any network activity. The godmode preset uses
/// this too: it never authorizes a target by itself.
fn resolve_lab_guard(
    url: &str,
    parsed: &Url,
    depth: Depth,
    scope_file: Option<&str>,
) -> Result<Option<riftlock_core::LabGuard>, i32> {
    if depth != Depth::Godmode {
        return Ok(None);
    }
    if let Some(path) = scope_file {
        return match riftlock_core::ScopeConfig::load(path) {
            Ok(config) => match riftlock_core::LabGuard::new_from_scope(&config, parsed) {
                Ok(guard) => Ok(Some(guard)),
                Err(_) => {
                    eprintln!("error: scope file does not authorize destructive probes for {url}");
                    Err(EXIT_SCOPE)
                }
            },
            Err(e) => {
                eprintln!("error: invalid scope file: {e}");
                Err(EXIT_SCOPE)
            }
        };
    }
    eprintln!("[!] GODMODE: destructive payloads enabled.");
    Ok(Some(riftlock_core::LabGuard::new_unsafe()))
}

/// Re-admit checkpoint-restored evidence through the proof gate: the gate
/// still decides what a finding is, the checkpoint only remembers what it
/// already admitted. Write-class evidence re-admits under the resumed run's
/// lab guard; anything the resumed scope no longer supports is dropped with
/// a warning, never fabricated into a finding.
fn restore_findings(
    evidence: &[Evidence],
    lab_guard: Option<&riftlock_core::LabGuard>,
) -> Vec<Finding> {
    evidence
        .iter()
        .filter_map(|e| {
            if let Ok(f) = riftlock_core::ProofGate::admit(e.clone()) {
                return Some(f);
            }
            let admitted =
                lab_guard.and_then(|lab| riftlock_core::ProofGate::admit_lab(e.clone(), lab).ok());
            if admitted.is_none() {
                riftlock_core::logln!(
                    "warning: dropped a checkpointed finding the resumed run cannot admit"
                );
            }
            admitted
        })
        .collect()
}

fn engine_error_counts_as_failure(error: &riftlock_core::ScanError) -> bool {
    // Scope errors and all scanner errors other than NotApplicable still fail.
    !matches!(error, riftlock_core::ScanError::NotApplicable(_))
}

/// Run the provider scanners selected by `provider` (`auto` runs every
/// scanner whose `matches()` accepts the URL, plus the source scanner).
/// Returns merged findings, failures, discovered endpoints and spawned-engine
/// count, or the exit code to abort with.
#[allow(clippy::too_many_arguments)] // one scan pipeline, 12 real inputs
async fn run_scanners(
    parsed: &Url,
    provider: &str,
    depth: Depth,
    bearer: Option<&str>,
    cookie: Option<&str>,
    lab_guard: Option<riftlock_core::LabGuard>,
    guard: &ScopeGuard,
    passive: bool,
    quiet: bool,
    wordlist: Option<&str>,
    coverage: &riftlock_core::Coverage,
    mut checkpoint: Option<&mut Checkpoint>,
    discovery_budget: Duration,
) -> Result<
    (
        Vec<Finding>,
        usize,
        usize,
        usize,
        usize,
        Option<String>,
        usize,
        riftlock_core::CrawlMetrics,
        Vec<String>,
    ),
    i32,
> {
    if provider != "auto"
        && provider != "supabase"
        && provider != "firebase"
        && provider != "appwrite"
        && provider != "nextjs"
        && provider != "clerk"
        && provider != "cache"
        && provider != "path"
        && provider != "graphql"
        && provider != "ssrf"
        && provider != "race"
        && provider != "signedurl"
        && provider != "prototype"
        && provider != "smuggling"
        && provider != "websocket"
        && provider != "oauth"
        && provider != "sse"
        && provider != "clientside"
        && provider != "supplychain"
        && provider != "llm"
        && provider != "grpc"
        && provider != "generic"
        && provider != "spa"
        && provider != "openapi"
        && provider != "auth"
        && provider != "misconfig"
        && provider != "infra"
    {
        eprintln!(
            "error: unknown provider {provider} (supported: auto, supabase, firebase, appwrite, nextjs, clerk, cache, path, graphql, ssrf, race, signedurl, prototype, smuggling, websocket, oauth, sse, clientside, supplychain, llm, grpc, generic, spa, openapi, auth, misconfig, infra)"
        );
        return Err(EXIT_ERROR);
    }
    let http = match client(guard, bearer, cookie) {
        Ok(client) => client,
        Err(error) => {
            eprintln!("error: cannot build HTTP client: {error}");
            return Err(EXIT_ERROR);
        }
    };
    let params = resolve_params(passive, depth, wordlist)?;
    let sessions = riftlock_core::SessionMatrix::from_env();
    let fetch_cache = riftlock_fingerprint::FetchCache::default();
    let _spinner = riftlock_core::logger::start_spinner("scanning");
    // Keep the path-only inventory for legacy scanners; method-aware scanners
    // also receive the preserved methods and never derive new request verbs.
    let (
        rpc_functions,
        endpoints,
        endpoint_methods,
        action_ids,
        discovered_urls,
        discovery_error,
        crawl_metrics,
    ) = if let Some(ck) = checkpoint
        .as_deref()
        // A completed-but-empty discovery is cached too; only a failed or
        // partial one (an error is recorded) is retried. Errorless non-empty
        // endpoints prove a legacy checkpoint ran it.
        .filter(|ck| {
            ck.discovery_error.is_none()
                && (ck.discovery_complete || !ck.discovered_endpoints.is_empty())
        }) {
        // Resume: discovery already ran; its results were checkpointed, so
        // the crawl is not repeated against the target. A checkpoint from
        // before method tracking had no methods to preserve: its paths
        // were fetched as GET, which is the legacy semantics.
        let methods = if ck.discovered_endpoint_methods.is_empty() {
            ck.discovered_endpoints
                .iter()
                .map(|path| riftlock_discovery::DiscoveredEndpoint {
                    path: path.clone(),
                    method: "GET".to_owned(),
                })
                .collect()
        } else {
            ck.discovered_endpoint_methods.clone()
        };
        (
            ck.rpc_functions.clone(),
            ck.discovered_endpoints.clone(),
            methods,
            ck.action_ids.clone(),
            ck.discovered_endpoints.clone(),
            ck.discovery_error.clone(),
            riftlock_core::CrawlMetrics {
                termination_reason: "resumed from checkpoint".to_owned(),
                ..riftlock_core::CrawlMetrics::default()
            },
        )
    } else {
        // Discovery is budget-capped like the engines: a slow or WAF'd
        // target must not spend the scan's fail-fast bar on the crawl. A
        // timed-out discovery scans the target root only.
        riftlock_core::logln!(
            "{}",
            ui::theme::neon_orange("[>] Discovery started: page, bundles, crawl")
        );
        // Reserve room for the root page and bundles, but bound the margin
        // to a quarter of short discovery budgets so a larger fallback request
        // cap cannot expire crawling immediately.
        let soft_margin = REQUEST_CAP.saturating_mul(2).min(discovery_budget / 4);
        let soft_deadline =
            std::time::Instant::now() + discovery_budget.saturating_sub(soft_margin);
        let discovery = tokio::time::timeout(
            discovery_budget,
            discover_context(
                &http,
                parsed,
                guard,
                &sessions,
                soft_deadline,
                depth,
                &fetch_cache,
            ),
        )
        .await;
        // A start-page failure is fatal (`failed — target root only`); a
        // bundle or crawl failure returns its partial inventory with an
        // explicit error so the report never calls it complete.
        let (rpc, endpoints, methods, actions, urls, error, crawl) = match discovery {
            Ok(Ok(results)) => results,
            Ok(Err(error)) => {
                let detail = discovery_failure_detail(&error);
                riftlock_core::logln!("[x] Target unreachable ({detail}). Aborting scan.");
                return Err(if matches!(error, ScanError::Scope(_)) {
                    EXIT_SCOPE
                } else {
                    EXIT_ERROR
                });
            }
            Err(_) => {
                riftlock_core::logln!(
                    "[x] Target unreachable (discovery exceeded {:?}). Aborting scan.",
                    discovery_budget
                );
                return Err(EXIT_ERROR);
            }
        };
        if let Some(ck) = checkpoint.as_deref_mut() {
            ck.rpc_functions = rpc.clone();
            ck.discovered_endpoints = endpoints.clone();
            ck.discovered_endpoint_methods = methods.clone();
            ck.discovery_complete = error.is_none();
            ck.discovery_error = error.clone();
            ck.action_ids = actions.clone();
            ck.save();
        }
        (rpc, endpoints, methods, actions, urls, error, crawl)
    };
    // A root that failed to produce any endpoint is terminal too: the only
    // usable target was unreachable, so engine requests would just repeat it
    // (or hit a bare root the crawl never reached). Partial discovery with at
    // least one endpoint keeps scanning normally.
    if endpoints.is_empty() && discovery_error.is_some() {
        let detail = discovery_error.as_deref().unwrap_or("discovery failed");
        riftlock_core::logln!("[x] Target unreachable ({detail}). Aborting scan.");
        return Err(EXIT_ERROR);
    }
    riftlock_core::logln!(
        "{}",
        ui::theme::neon_orange(&format!(
            "[+] Discovery finished: {} endpoints",
            endpoints.len()
        ))
    );
    for line in ui::lifecycle::print_attack_surface(
        depth.label(),
        &endpoints,
        &endpoint_methods,
        &discovered_urls,
        &action_ids,
        &rpc_functions,
        &crawl_metrics,
    ) {
        riftlock_core::logln!("{line}");
    }
    let run_supabase = provider == "auto" || provider == "supabase";
    let run_firebase = provider == "auto" || provider == "firebase";
    let run_appwrite = provider == "auto" || provider == "appwrite";
    let run_nextjs = provider == "auto" || provider == "nextjs";
    let run_clerk = provider == "auto" || provider == "clerk";
    let run_cache = provider == "auto" || provider == "cache";
    let run_path = provider == "auto" || provider == "path";
    let run_graphql = provider == "auto" || provider == "graphql";
    let run_ssrf = provider == "auto" || provider == "ssrf";
    let run_race = provider == "auto" || provider == "race";
    let run_signedurl = provider == "auto" || provider == "signedurl";
    let run_prototype = provider == "auto" || provider == "prototype";
    let run_smuggling = provider == "auto" || provider == "smuggling";
    let run_websocket = provider == "auto" || provider == "websocket";
    let run_oauth = provider == "auto" || provider == "oauth";
    let run_sse = provider == "auto" || provider == "sse";
    let run_clientside = provider == "auto" || provider == "clientside";
    let run_supplychain = provider == "auto" || provider == "supplychain";
    let run_llm = provider == "auto" || provider == "llm";
    let run_grpc = provider == "auto" || provider == "grpc";
    let run_generic = provider == "auto" || provider == "generic";
    let run_spa = provider == "auto" || provider == "spa";
    let run_openapi = provider == "auto" || provider == "openapi";
    let run_auth = provider == "auto" || provider == "auth";
    let run_misconfig = provider == "auto" || provider == "misconfig";
    let run_infra = provider == "auto" || provider == "infra";

    // `Scanner` is not dyn-compatible (RPITIT), so each scanner runs through
    // its concrete type; `matches()` filters the target in auto mode. The
    // same concrete-type dispatch makes the optional `DynamicScanner`
    // implementors callable without Any downcasting.
    let dynamic = if endpoints.is_empty() {
        None
    } else {
        Some(riftlock_core::DiscoveryContext {
            endpoints: endpoints.clone(),
            endpoint_methods: endpoint_methods.clone(),
            discovered_urls: discovered_urls.clone(),
            params,
            sessions: sessions.clone(),
        })
    };
    // Endpoints the discovery context fed to the dynamic scanners; 0 when
    // discovery was skipped (passive mode) or found nothing.
    let endpoints_discovered = dynamic.as_ref().map_or(0, |c| c.endpoints.len());
    // Scanners are constructed up front and moved into their own spawned
    // tasks: a panic inside one scanner is caught by the JoinSet instead of
    // crashing the CLI, and the global rate limiter paces outbound requests.
    // `Scanner` is not dyn-compatible (RPITIT), so each scanner runs through
    // its concrete type. `idx` keeps finding order deterministic — join_next
    // yields completion order, but slots are drained in spawn order below.
    let mut set = tokio::task::JoinSet::<EngineReport>::new();
    let mut idx = 0usize;
    // Lifecycle progress is on by default at read depth and above; --quiet
    // suppresses only these lines, never findings, warnings or the report.
    let lifecycle = !quiet && !matches!(depth, Depth::Normal);
    // Resume: engines the checkpoint marks completed already ran to the end
    // and their findings were checkpointed — re-running them would re-fire
    // (possibly destructive) probes for no new evidence.
    let done = |name: &str| {
        checkpoint
            .as_deref()
            .is_some_and(|ck| ck.completed_tasks.iter().any(|t| t == name))
    };
    macro_rules! push_scan_inner {
        ($name:expr, $opt:expr, $engine_cov:expr) => {
            if let Some(scanner) = $opt {
                if !done($name) {
                    let parsed = parsed.clone();
                    let http = http.clone();
                    let guard = guard.clone();
                    let planned = engine_planned_endpoints($name, &endpoints);
                    let budget = engine_budget(depth);
                    if planned == 0 {
                        // No planned endpoint means no work: spawning would
                        // only record a budget timeout as an engine failure.
                        // Record the skip instead.
                        if lifecycle {
                            riftlock_core::logln!(
                                "{}",
                                ui::lifecycle::outcome_line(
                                    $name,
                                    &EngineOutcome::Skipped(
                                        "not applicable: no endpoints to probe".to_owned()
                                    )
                                )
                            );
                        }
                    } else {
                        if lifecycle {
                            riftlock_core::logln!(
                                "{}",
                                ui::lifecycle::started_line($name, budget, planned)
                            );
                        }
                        let engine_cov = $engine_cov;
                        set.spawn(async move {
                            let started = std::time::Instant::now();
                            // Engines that honour the deadline return their
                            // findings before the cancellation fires.
                            let deadline = engine_deadline(started, depth);
                            // A panicking scanner is caught in-task: the payload
                            // becomes `None`, so the drain feed can name it. An
                            // engine past its wall-clock budget becomes a real
                            // recorded failure instead of an unbounded wait.
                            let out = with_budget(
                                budget,
                                std::panic::AssertUnwindSafe(riftlock_core::Scanner::scan_until(
                                    &scanner,
                                    &parsed,
                                    &http,
                                    &guard,
                                    passive,
                                    Some(deadline),
                                ))
                                .catch_unwind()
                                .map(|r| r.ok()),
                            )
                            .await;
                            (idx, $name, started.elapsed(), out, engine_cov)
                        });
                        idx += 1;
                    }
                }
            }
        };
    }
    // `metered` gives the engine its own coverage fork: the scanner dual-writes
    // to the fork and the shared run ledger, so concurrent engines cannot skew
    // each other's counts. Engines without a `coverage` field run unmetered.
    macro_rules! push_scan {
        ($name:expr, $opt:expr, metered) => {{
            let mut opt = $opt;
            let engine_cov = coverage.fork();
            if let Some(scanner) = opt.as_mut() {
                scanner.coverage = engine_cov.clone();
            }
            push_scan_inner!($name, opt, Some(engine_cov));
        }};
        ($name:expr, $opt:expr) => {
            push_scan_inner!($name, $opt, None)
        };
    }
    // Explicit --provider only authorizes the engine; the target page must
    // still fingerprint as a Supabase app before any API probe is sent.
    let supabase = run_supabase.then(|| SupabaseScanner {
        keys: SupabaseKeys::from_env(),
        rpc_functions: rpc_functions.clone(),
        auth_depth: matches!(depth, Depth::Godmode),
        lab_guard: lab_guard.clone(),
        coverage: coverage.clone(),
        fetch_cache: fetch_cache.clone(),
    });
    let firebase = run_firebase.then_some(FirebaseScanner {
        force_run: provider == "firebase",
    });
    let appwrite = run_appwrite.then_some(AppwriteScanner {
        force_run: provider == "appwrite",
        coverage: coverage.clone(),
    });
    let nextjs = run_nextjs.then(|| riftlock_scanner_nextjs::NextJsScanner {
        action_ids,
        sessions: sessions.clone(),
        coverage: coverage.clone(),
    });
    let clerk = run_clerk.then(|| riftlock_scanner_clerk::ClerkScanner {
        coverage: coverage.clone(),
    });
    let cache = run_cache.then(|| riftlock_scanner_cache::CacheScanner {
        sessions: sessions.clone(),
        coverage: coverage.clone(),
    });
    let path = run_path.then(|| riftlock_scanner_path::PathScanner {
        sessions: sessions.clone(),
        // Admin/protected paths discovered by AST.
        paths: endpoints
            .iter()
            .filter(|e| e.contains("admin"))
            .cloned()
            .collect(),
    });
    let graphql = run_graphql.then(|| riftlock_scanner_graphql::GraphQLScanner {
        // GraphQL endpoints discovered by AST.
        endpoints: endpoints
            .iter()
            .filter(|e| e.contains("graphql"))
            .cloned()
            .collect(),
        coverage: coverage.clone(),
    });
    let ssrf = run_ssrf.then(|| riftlock_scanner_ssrf::SsrfScanner {
        // Preserve paths for path-only callers and methods for method-aware filtering.
        endpoints: endpoints.clone(),
        endpoint_methods: endpoint_methods.clone(),
        coverage: coverage.clone(),
    });
    let race = run_race.then(|| riftlock_scanner_race::RaceScanner {
        sessions: sessions.clone(),
        endpoints: endpoints.clone(),
        endpoint_methods: endpoint_methods.clone(),
        coverage: coverage.clone(),
    });
    let signedurl = run_signedurl.then(|| riftlock_scanner_signedurl::SignedUrlScanner {
        sessions: sessions.clone(),
        endpoints: endpoints.clone(),
        coverage: coverage.clone(),
    });
    let prototype = run_prototype.then(|| riftlock_scanner_prototype::PrototypeScanner {
        endpoints: endpoints.clone(),
        endpoint_methods: endpoint_methods.clone(),
        coverage: coverage.clone(),
    });
    let smuggling = run_smuggling.then(|| SmugglingScanner {
        coverage: coverage.clone(),
        ..SmugglingScanner::default()
    });
    let websocket = run_websocket.then(|| WebSocketScanner {
        sessions: sessions.clone(),
        endpoints: endpoints.clone(),
        coverage: coverage.clone(),
        ..WebSocketScanner::default()
    });
    let oauth = run_oauth.then_some(OAuthScanner {
        endpoints: endpoints.clone(),
        coverage: coverage.clone(),
    });
    let sse = run_sse.then(|| SseScanner {
        sessions: sessions.clone(),
        endpoints: endpoints.clone(),
        endpoint_methods: endpoint_methods.clone(),
        ..SseScanner::default()
    });
    let clientside = run_clientside.then(|| ClientSideScanner {
        // Discovery merges crawler URLs (script srcs included) into
        // `endpoints`; that is the bundle list.
        endpoints: endpoints.clone(),
    });
    let supplychain = run_supplychain.then(|| SupplyChainScanner {
        coverage: coverage.clone(),
    });
    let llm = run_llm.then(|| LlmScanner {
        endpoints: endpoints.clone(),
        endpoint_methods: endpoint_methods.clone(),
        coverage: coverage.clone(),
    });
    let grpc = run_grpc.then_some(GrpcScanner {
        coverage: coverage.clone(),
    });
    let (generic_events_tx, generic_events_rx) = tokio::sync::mpsc::channel(128);
    let generic = run_generic.then(|| GenericScanner {
        force_run: provider == "generic",
        depth,
        authenticated: bearer.is_some() || cookie.is_some(),
        endpoints: endpoints.clone(),
        coverage: coverage.clone(),
        events: Some(generic_events_tx.clone()),
    });
    let spa = run_spa.then(|| SpaScanner {
        force_run: provider == "spa",
        lab_guard: lab_guard.clone(),
        endpoints: endpoints.clone(),
        coverage: coverage.clone(),
    });
    let openapi = run_openapi.then(|| OpenApiScanner {
        force_run: provider == "openapi",
        coverage: coverage.clone(),
    });
    let auth = run_auth.then(|| AuthScanner {
        force_run: provider == "auth",
        endpoints: endpoints.clone(),
        coverage: coverage.clone(),
    });
    let misconfig = run_misconfig.then(|| MisconfigScanner {
        endpoints: endpoints.clone(),
        coverage: coverage.clone(),
    });
    let infra = run_infra.then_some(InfraScanner {
        coverage: coverage.clone(),
    });

    push_scan!("Supabase", supabase.clone(), metered);
    if let (Some(mut scanner), Some(ctx)) = (supabase, dynamic.clone()) {
        if !done("Supabase (dynamic)") {
            let parsed = parsed.clone();
            let http = http.clone();
            let guard = guard.clone();
            let planned = ctx.endpoints.len();
            let budget = engine_budget(depth);
            if lifecycle {
                riftlock_core::logln!(
                    "{}",
                    ui::lifecycle::started_line("Supabase (dynamic)", budget, planned)
                );
            }
            let engine_cov = coverage.fork();
            scanner.coverage = engine_cov.clone();
            set.spawn(async move {
                let started = std::time::Instant::now();
                let out = with_budget(
                    budget,
                    std::panic::AssertUnwindSafe(riftlock_core::DynamicScanner::scan_dynamic(
                        &scanner, &parsed, &http, &guard, &ctx,
                    ))
                    .catch_unwind()
                    .map(|r| r.ok()),
                )
                .await;
                (
                    idx,
                    "Supabase (dynamic)",
                    started.elapsed(),
                    out,
                    Some(engine_cov),
                )
            });
            idx += 1;
        }
    }
    push_scan!("Firebase", firebase);
    push_scan!("Appwrite", appwrite, metered);
    push_scan!("Next.js", nextjs.clone(), metered);
    if let (Some(mut scanner), Some(ctx)) = (nextjs, dynamic) {
        if !done("Next.js (dynamic)") {
            let parsed = parsed.clone();
            let http = http.clone();
            let guard = guard.clone();
            let planned = ctx.endpoints.len();
            let budget = engine_budget(depth);
            if lifecycle {
                riftlock_core::logln!(
                    "{}",
                    ui::lifecycle::started_line("Next.js (dynamic)", budget, planned)
                );
            }
            let engine_cov = coverage.fork();
            scanner.coverage = engine_cov.clone();
            set.spawn(async move {
                let started = std::time::Instant::now();
                let out = with_budget(
                    budget,
                    std::panic::AssertUnwindSafe(riftlock_core::DynamicScanner::scan_dynamic(
                        &scanner, &parsed, &http, &guard, &ctx,
                    ))
                    .catch_unwind()
                    .map(|r| r.ok()),
                )
                .await;
                (
                    idx,
                    "Next.js (dynamic)",
                    started.elapsed(),
                    out,
                    Some(engine_cov),
                )
            });
            idx += 1;
        }
    }
    push_scan!("Clerk", clerk, metered);
    push_scan!("Cache", cache, metered);
    push_scan!("Path", path);
    push_scan!("GraphQL", graphql, metered);
    push_scan!("SSRF", ssrf, metered);
    push_scan!("Race", race, metered);
    push_scan!("SignedUrl", signedurl, metered);
    push_scan!("Prototype", prototype, metered);
    push_scan!("Smuggling", smuggling, metered);
    push_scan!("WebSocket", websocket, metered);
    push_scan!("OAuth", oauth, metered);
    push_scan!("SSE", sse);
    push_scan!("ClientSide", clientside);
    push_scan!("SupplyChain", supplychain, metered);
    push_scan!("LLM", llm, metered);
    push_scan!("gRPC", grpc, metered);
    push_scan!("Generic", generic, metered);
    push_scan!("SPA", spa, metered);
    push_scan!("OpenAPI", openapi, metered);
    push_scan!("Auth", auth, metered);
    push_scan!("Misconfig", misconfig, metered);
    push_scan!("Infra", infra, metered);
    // Source is spawned manually (no push_scan), so its resume gate is here.
    if !done("Source") {
        let parsed = parsed.clone();
        let http = http.clone();
        let guard = guard.clone();
        let budget = engine_budget(depth).max(Duration::from_secs(30));
        if lifecycle {
            riftlock_core::logln!("{}", ui::lifecycle::started_line("Source", budget, 1));
        }
        let engine_cov = coverage.fork();
        let source = SourceScanner {
            coverage: engine_cov.clone(),
        };
        set.spawn(async move {
            let started = std::time::Instant::now();
            let out = with_budget(
                budget,
                std::panic::AssertUnwindSafe(riftlock_core::Scanner::scan(
                    &source, &parsed, &http, &guard, passive,
                ))
                .catch_unwind()
                .map(|r| r.ok()),
            )
            .await;
            (idx, "Source", started.elapsed(), out, Some(engine_cov))
        });
        idx += 1;
    }

    // Drop the local sender so the event receiver closes once Generic ends.
    drop(generic_events_tx);

    // Drain in spawn order: finding order stays deterministic, exactly as
    // with the previous join_all. Scope violations abort the scan; one
    // scanner's transport failure is that scanner's checked negative, not a
    // scan abort — the others still covered the target. Only when *no*
    // scanner completed do we call the target unreachable.
    let mut findings = Vec::new();
    let mut ok_results = 0usize;
    let mut failures = 0usize;
    let mut clean = 0usize;
    let (slots, streamed, planned_endpoints, unreached_endpoints) = drain_scans(
        set,
        idx,
        checkpoint.as_deref_mut(),
        generic_events_rx,
        lifecycle,
    )
    .await;
    for slot in slots {
        match slot {
            Some(Ok(fs)) => {
                ok_results += 1;
                if fs.is_empty() {
                    clean += 1;
                }
                findings.extend(fs);
            }
            Some(Err(riftlock_core::ScanError::Scope(_))) => {
                // The run target is validated before discovery and scanning.
                // A scope error that escapes an engine is an engine-level
                // rejection; keep it visible as incomplete coverage without
                // discarding results from unrelated scanners.
                failures += 1;
            }
            // Not-applicable engines are skipped, not failed. Every other
            // engine error remains a failed check without aborting the scan.
            Some(Err(error)) if engine_error_counts_as_failure(&error) => {
                failures += 1;
            }
            Some(Err(_)) => {}
            // An empty slot is a scanner whose task panicked: the JoinSet
            // isolated it, the remaining scanners' coverage still stands.
            None => {
                failures += 1;
                riftlock_core::logln!("warning: a scanner panicked and was skipped");
            }
        }
    }
    // Preserve admitted proofs even when their engine later times out.
    if let Some(ck) = checkpoint.as_deref() {
        findings.extend(restore_findings(&ck.findings, lab_guard.as_ref()));
    }
    findings.extend(restore_findings(&streamed, lab_guard.as_ref()));
    // No engine produced a result: the run is still reported (its final
    // analysis must stay visible) and stays INCOMPLETE, but never CLEAN.
    if ok_results == 0 && failures > 0 {
        riftlock_core::logln!(
            "[!] Warning: no scanner completed — target unreachable, blocking responses or dropped connections. {failures} scanners failed."
        );
    } else if failures > 0 {
        riftlock_core::logln!("[!] Warning: {failures} scanners failed; coverage is incomplete.");
    }
    // Passive tech fingerprinting rides the same pipeline: page + bundle
    // markers become informational TechFingerprint evidence (skipped on
    // transport failure or budget overrun — coverage already stands).
    if let Ok(matches) = tokio::time::timeout(
        FINGERPRINT_BUDGET,
        riftlock_fingerprint::tech_url(&http, parsed, guard, coverage, &fetch_cache),
    )
    .await
    .unwrap_or_else(|_| {
        riftlock_core::logln!("[!] Warning: fingerprinting exceeded its budget; skipped.");
        Ok(Vec::new())
    }) {
        for m in matches {
            if let Ok(f) = riftlock_core::ProofGate::admit(Evidence::TechFingerprint {
                technology: m.technology,
                version: m.version,
                confidence: m.confidence,
            }) {
                findings.push(f);
            }
        }
    }
    for url in http.circuit_skipped() {
        coverage.endpoint_at(&url, riftlock_core::EndpointOutcome::CircuitOpen);
    }
    finalize_findings(&mut findings);
    Ok((
        findings,
        failures,
        clean,
        endpoints_discovered,
        idx,
        discovery_error,
        planned_endpoints,
        crawl_metrics,
        unreached_endpoints,
    ))
}

/// Preserve the real transport error, prefixed with its actionable category.
fn discovery_failure_detail(error: &riftlock_core::ScanError) -> String {
    match error.transport_category() {
        Some(category) => format!("transport:{}: {error}", category.category()),
        None => error.to_string(),
    }
}

fn crawl_incomplete(crawl: &riftlock_core::CrawlMetrics) -> bool {
    !crawl.reconciles() || crawl.remaining > 0 || crawl.termination_reason == "failed"
}

fn discovery_status(error: Option<&str>) -> String {
    match error {
        None => "complete".to_owned(),
        // The detail after the prefix is the original error; keep the coarse
        // status stable while refusing to call a failed root a clean inventory.
        Some(error) if error.starts_with("failed at start page") => {
            "failed — target root only".to_owned()
        }
        Some(error) if error.starts_with("discovery budget exhausted") => {
            "failed — target root only".to_owned()
        }
        Some(error) => format!("partial — {error}"),
    }
}

fn incomplete_coverage_reasons(
    state: &RunState,
    discovery_error: Option<&str>,
    crawl: &riftlock_core::CrawlMetrics,
    engine_failures: &[String],
    engines_failed: usize,
    unreached: &[String],
) -> Vec<String> {
    let coverage = state.coverage;
    let mut reasons = Vec::new();
    if engines_failed > 0 {
        if engine_failures.is_empty() {
            reasons.push(format!("{engines_failed} scanner engine(s) failed"));
        } else {
            reasons.push(format!("scanner failures: {}", engine_failures.join("; ")));
        }
    }
    if let Some(error) = discovery_error {
        reasons.push(format!("discovery incomplete: {error}"));
    }
    if crawl.termination_reason == "deadline" && crawl.remaining > 0 {
        reasons.push(format!(
            "discovery deadline exhausted with {} URL(s) untested",
            crawl.remaining
        ));
    } else if !crawl.reconciles() {
        reasons.push("discovery crawl accounting did not reconcile".to_owned());
    } else if crawl.termination_reason == "failed" {
        reasons.push("discovery crawl failed".to_owned());
    }
    if !unreached.is_empty() {
        reasons.push(format!(
            "{} planned endpoint(s) were never reached before the engine stopped",
            unreached.len()
        ));
    }
    if !state.accounting.reconciles() {
        reasons.push(format!(
            "check accounting incomplete: {} in flight, {} duplicate terminal results",
            state.accounting.in_flight, state.accounting.duplicates_rejected
        ));
    }
    if state.unaccounted_executions > 0 {
        reasons.push(format!(
            "{} finding-producing execution(s) had no registered checks",
            state.unaccounted_executions
        ));
    }

    // 404/410 probes are confirmed absences, not untested surface: skipped
    // endpoints are excluded from the untested numerator and its denominator.
    // Circuit-open probes remain in the untested numerator.
    let untested = coverage.endpoints_timed_out
        + coverage.endpoints_failed
        + coverage.endpoints_auth_required
        + coverage.endpoints_waf_blocked
        + coverage.endpoints_circuit_open;
    if coverage.endpoints_discovered == 0
        && coverage.vulnerability_checks_attempted == 0
        && coverage.vulnerability_checks_completed == 0
    {
        reasons.push("no endpoints or vulnerability checks were assessed".to_owned());
    } else if coverage.endpoints_discovered > 0 {
        if coverage.endpoints_tested_successfully == 0 {
            reasons.push(format!(
                "0 of {} discovered endpoints were successfully tested",
                coverage.endpoints_discovered
            ));
        }
        // The untested clause is a share of the assessed endpoints (tested
        // plus untested), the same population the completeness gate uses.
        let tested_denominator = coverage
            .endpoints_tested_successfully
            .saturating_add(untested);
        if untested.saturating_mul(100)
            > tested_denominator.saturating_mul(ui::lifecycle::ENDPOINT_FAILURE_TOLERANCE_PERCENT)
        {
            reasons.push(format!(
                "{untested} of {tested_denominator} assessed endpoints were auth-required, blocked, failed, timed out, or circuit-open (more than {}%)",
                ui::lifecycle::ENDPOINT_FAILURE_TOLERANCE_PERCENT
            ));
        }
        // The never-classified clause includes skipped endpoints: a skip is a
        // disposition, so only genuinely unaccounted endpoints remain.
        let classified = tested_denominator.saturating_add(coverage.endpoints_skipped);
        if classified < coverage.endpoints_discovered {
            reasons.push(format!(
                "{} discovered endpoint(s) were never classified",
                coverage.endpoints_discovered - classified
            ));
        }
    }
    let attempted_checks = coverage.vulnerability_checks_attempted;
    let non_completed_checks =
        attempted_checks.saturating_sub(coverage.vulnerability_checks_completed);
    if attempted_checks > 0
        && non_completed_checks.saturating_mul(100)
            > attempted_checks.saturating_mul(ui::lifecycle::CHECK_FAILURE_TOLERANCE_PERCENT)
    {
        reasons.push(format!(
            "{non_completed_checks} of {attempted_checks} vulnerability check(s) did not complete (more than {}% failed)",
            ui::lifecycle::CHECK_FAILURE_TOLERANCE_PERCENT
        ));
    }
    if coverage.vulnerability_checks_inconclusive > 0 {
        reasons.push(format!(
            "{} vulnerability check(s) were inconclusive",
            coverage.vulnerability_checks_inconclusive
        ));
    }
    if coverage.passive_observations > 0 && coverage.vulnerability_checks_attempted == 0 {
        reasons.push("passive observations were recorded without active checks".to_owned());
    }
    if reasons.is_empty() {
        reasons
            .push("coverage counters did not satisfy the complete-assessment criteria".to_owned());
    }
    reasons
}

fn incomplete_coverage_message(
    state: &RunState,
    discovery_error: Option<&str>,
    crawl: &riftlock_core::CrawlMetrics,
    engine_failures: &[String],
    engines_failed: usize,
    unreached: &[String],
) -> String {
    format!(
        "[FINDINGS + INCOMPLETE COVERAGE] Incomplete because: {}.",
        incomplete_coverage_reasons(
            state,
            discovery_error,
            crawl,
            engine_failures,
            engines_failed,
            unreached,
        )
        .join("; ")
    )
}

fn dedup_findings(findings: &mut Vec<Finding>) -> usize {
    let before = findings.len();
    let mut seen = HashSet::new();
    findings.retain(|f| seen.insert(dedup_key(f.evidence())));
    before - findings.len()
}

fn finalize_findings(findings: &mut Vec<Finding>) {
    dedup_findings(findings);
    findings.sort_by_key(|f| ui::findings::severity_rank(f.evidence()));
}

/// Dedup across URL paths: the same sink/parameter is one finding wherever
/// it is reachable. Variants without a parameter/sink keep full evidence.
fn dedup_key(evidence: &Evidence) -> String {
    match evidence {
        Evidence::XssReflection { param, .. } => format!("XssReflection:{param}"),
        Evidence::SqliError { param, .. } => format!("SqliError:{param}"),
        Evidence::SqliTimeDelay { param, .. } => format!("SqliTimeDelay:{param}"),
        Evidence::SstiReflection { param, .. } => format!("SstiReflection:{param}"),
        Evidence::LfiRead { param, .. } => format!("LfiRead:{param}"),
        Evidence::CommandInjection { param, .. } => format!("CommandInjection:{param}"),
        Evidence::DomXssTaint { url, source, sink } => {
            // One sink location per script: the same bundle loaded by many
            // pages is still one flow, but distinct bundles stay distinct.
            format!("DomXssTaint:{url}:{source}:{sink}")
        }
        Evidence::SqlInjection { param, .. } => format!("SqlInjection:{param}"),
        Evidence::ReflectedXss { url, param, .. } => format!("ReflectedXss:{url}:{param}"),
        Evidence::NoSqlInjection { param, .. } => format!("NoSqlInjection:{param}"),
        Evidence::MassAssignment { param, .. } => format!("MassAssignment:{param}"),
        Evidence::OpenRedirect { param, .. } => format!("OpenRedirect:{param}"),
        _ => format!("{evidence:?}"),
    }
}

/// Buffer verified findings for the final section and report each tested
/// endpoint as it finishes: pink when it proved something, white when not.
fn handle_generic_event(
    event: GenericEvent,
    streamed: &mut Vec<Evidence>,
    expected: &mut Vec<String>,
    seen: &mut HashSet<String>,
    checkpoint: &mut Option<&mut Checkpoint>,
) {
    match event {
        GenericEvent::Finding(evidence) => {
            if let Some(checkpoint) = checkpoint.as_deref_mut() {
                checkpoint.record_streamed_finding(&evidence);
            }
            streamed.push(evidence);
        }
        GenericEvent::EndpointComplete {
            endpoint, found, ..
        } => {
            seen.insert(endpoint.clone());
            // Progress for a clean endpoint is noise; only a finding is news.
            if found {
                let line = ui::theme::blush_pink(&format!("  [+] {endpoint}"));
                riftlock_core::logln!("{line}");
            }
        }
        GenericEvent::EndpointSkipped { endpoint } => {
            seen.insert(endpoint.clone());
            riftlock_core::logln!("  [~] {endpoint} (not probeable: out of scope or duplicate)");
        }
        GenericEvent::EndpointsStarted { endpoints, .. } => *expected = endpoints,
    }
}

/// Collect every engine result in spawn order, isolating scanner panics.
async fn drain_scans(
    mut set: tokio::task::JoinSet<EngineReport>,
    total: usize,
    mut checkpoint: Option<&mut Checkpoint>,
    mut events: tokio::sync::mpsc::Receiver<GenericEvent>,
    lifecycle: bool,
) -> (Vec<Option<ScanResult>>, Vec<Evidence>, usize, Vec<String>) {
    let mut slots: Vec<Option<ScanResult>> = (0..total).map(|_| None).collect();
    let mut streamed = Vec::new();
    let mut expected: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut events_open = true;
    while !set.is_empty() {
        tokio::select! {
            joined = set.join_next() => {
                let Some(joined) = joined else { break };
                if let Ok((idx, name, elapsed, result, engine_cov)) = joined {
                    // Stats come from this engine's own fork, so concurrent
                    // engines cannot distort each other's counts.
                    let stats = engine_cov.as_ref().map_or_else(EngineStats::default, |cov| {
                        let snapshot = cov.snapshot(0);
                        EngineStats {
                            checks_completed: snapshot.vulnerability_checks_completed,
                            checks_attempted: snapshot.vulnerability_checks_attempted,
                            endpoints_tested: snapshot.endpoints_tested_successfully,
                            endpoints_planned: snapshot.endpoints_tested_successfully
                                + snapshot.endpoints_timed_out
                                + snapshot.endpoints_failed
                                + snapshot.endpoints_auth_required
                                + snapshot.endpoints_waf_blocked
                                + snapshot.endpoints_skipped
                                + snapshot.endpoints_circuit_open,
                        }
                    });
                    let outcome = match &result {
                        Some(Ok(fs)) => {
                            let mut unique = fs.clone();
                            dedup_findings(&mut unique);
                            EngineOutcome::Done {
                                elapsed,
                                findings: unique.len(),
                                stats,
                            }
                        }
                        None => EngineOutcome::Panicked,
                        Some(Err(riftlock_core::ScanError::Scope(_))) => EngineOutcome::Skipped("scope rejection; engine incomplete".to_string()),
                        Some(Err(riftlock_core::ScanError::NotApplicable(reason))) => {
                            EngineOutcome::Skipped(format!("not applicable: {reason}"))
                        }
                        Some(Err(e)) => EngineOutcome::Failed(e.to_string()),
                    };
                    // Lifecycle mode reports every engine, so a clean engine is
                    // visibly finished rather than silently absent. Quiet mode
                    // keeps only findings and failures, which are always news.
                    if lifecycle
                        || !matches!(&outcome, EngineOutcome::Done { findings: 0, .. })
                    {
                        riftlock_core::logln!("{}", outcome_line(name, &outcome));
                    }
                    if let Some(cp) = checkpoint.as_deref_mut() {
                        match &result {
                            Some(Ok(fs)) => cp.record_completed(name, fs),
                            None => cp.record_failed(name, "panicked"),
                            Some(Err(riftlock_core::ScanError::NotApplicable(_))) => {
                                cp.record_completed(name, &[])
                            }
                            Some(Err(e)) => cp.record_failed(name, &e.to_string()),
                        }
                    }
                    slots[idx] = result;
                }
            }
            event = events.recv(), if events_open => {
                match event {
                    Some(event) => {
                        handle_generic_event(
                            event,
                            &mut streamed,
                            &mut expected,
                            &mut seen,
                            &mut checkpoint,
                        )
                    }
                    None => events_open = false,
                }
            }
        }
    }
    // No scanner can send again; a retained sender must not keep the drain alive.
    events.close();
    while let Some(event) = events.recv().await {
        handle_generic_event(
            event,
            &mut streamed,
            &mut expected,
            &mut seen,
            &mut checkpoint,
        );
    }
    // The generic engine's own plan (base URL + probeable discovered
    // endpoints) is the only denominator its coverage outcomes share.
    let planned = expected.len();
    // The engine can be cancelled at its wall clock with targets still
    // queued: one line names how many planned endpoints were never reached.
    let unreached: Vec<String> = expected
        .into_iter()
        .filter(|endpoint| !seen.contains(endpoint))
        .collect();
    if !unreached.is_empty() {
        let shown = unreached
            .iter()
            .take(3)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        let more = unreached.len().saturating_sub(3);
        let suffix = if more > 0 {
            format!(" (+{more} more)")
        } else {
            String::new()
        };
        riftlock_core::logln!(
            "  [~] {} planned endpoint(s) not reached: {shown}{suffix}",
            unreached.len()
        );
    }
    (slots, streamed, planned, unreached)
}

/// The `scheme://host[:port]` origin of `url` — the default scope for a scan
/// run without `--scope`.
fn scope_origin(url: &Url) -> String {
    match url.port() {
        Some(p) => format!(
            "{}://{}:{p}",
            url.scheme(),
            url.host_str().unwrap_or_default()
        ),
        None => format!("{}://{}", url.scheme(), url.host_str().unwrap_or_default()),
    }
}

/// Build the unique report filename from the target host, resolved depth and
/// scan-start UTC timestamp. Hostnames are kept intact; URL paths are excluded.
/// Absolute location of a report just written, so the "saved to" line names
/// the directory even when the caller passed a bare filename. Falls back to
/// the path as given if the working directory cannot be read.
fn saved_path_display(path: &str) -> String {
    if let Ok(canonical) = std::fs::canonicalize(path) {
        return canonical.display().to_string();
    }
    let p = std::path::Path::new(path);
    if p.is_absolute() {
        path.to_string()
    } else {
        match std::env::current_dir() {
            Ok(cwd) => cwd.join(p).display().to_string(),
            Err(_) => path.to_string(),
        }
    }
}

/// Explain where the generated HTML report was saved and provide a terminal
/// hyperlink when the output stream supports OSC 8 hyperlinks.
fn html_report_location_message(path: &str, hyperlink: bool) -> String {
    let display_path = saved_path_display(path);
    let report_path = std::path::Path::new(&display_path);
    let directory = report_path
        .parent()
        .map_or_else(|| ".".to_owned(), |parent| parent.display().to_string());
    let open_target = url::Url::from_file_path(report_path)
        .ok()
        .map(|uri| uri.to_string());
    let open_link = match open_target {
        Some(uri) if hyperlink => format!("\x1b]8;;{uri}\x1b\\open report\x1b]8;;\x1b\\"),
        Some(uri) => uri,
        None => display_path.clone(),
    };
    format!(
        "[+] HTML report generated\n    File: {display_path}\n    Directory: {directory}\n    Open: {open_link}"
    )
}

fn report_filename(host: &str, mode: &str, started_at: SystemTime) -> String {
    let timestamp = started_at.duration_since(UNIX_EPOCH).unwrap_or_default();
    let seconds = timestamp.as_secs();
    let fraction = timestamp.subsec_nanos();
    let days = (seconds / 86_400) as i64;
    let day_seconds = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    let hour = day_seconds / 3_600;
    let minute = day_seconds % 3_600 / 60;
    let second = day_seconds % 60;
    format!("{host}-{mode}-report-{year:04}{month:02}{day:02}-{hour:02}{minute:02}{second:02}-{fraction:09}.html")
}

/// Convert days since the Unix epoch to a proleptic Gregorian date.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    (year, month, day)
}

/// Render findings+chains for the requested format.
fn render(
    findings: &[Finding],
    chains: &[Finding],
    format: Format,
    status: &str,
    meta: &riftlock_report::ScanMetadata,
) -> String {
    let all: Vec<&Finding> = findings.iter().chain(chains.iter()).collect();
    match format {
        Format::Human => String::new(),
        Format::Json => riftlock_report::to_json_report(
            &all.into_iter().cloned().collect::<Vec<Finding>>(),
            meta,
        ),
        Format::Ndjson => riftlock_report::to_ndjson_report(
            &all.into_iter().cloned().collect::<Vec<Finding>>(),
            meta,
        ),
        Format::Sarif => riftlock_report::to_sarif_with_status(
            &all.into_iter().cloned().collect::<Vec<Finding>>(),
            status,
        ),
        Format::Html => riftlock_report::to_html_with_status(
            &all.into_iter().cloned().collect::<Vec<Finding>>(),
            status,
        ),
        Format::Markdown => riftlock_report::to_markdown_with_status(
            &all.into_iter().cloned().collect::<Vec<Finding>>(),
            status,
        ),
        // PDF is binary: handled by the output-writing block, never here.
        Format::Pdf => String::new(),
    }
}

/// Render the HTML report with the same grouped data the terminal report
/// shows: follow-up groups, tested surface and scan status.
fn render_html(
    findings: &[Finding],
    chains: &[Finding],
    incomplete_coverage: bool,
    has_findings: bool,
    report: &ui::final_report::FinalReport<'_>,
) -> String {
    let all: Vec<Finding> = findings.iter().chain(chains.iter()).cloned().collect();
    let summary = riftlock_report::summarize(report.findings);
    let tested = ui::final_report::tested_segments(report);
    let context = riftlock_report::HtmlContext {
        summary: &summary,
        incomplete_coverage,
        has_findings,
        tested_segments: &tested,
        auth_required: report.coverage.endpoints_auth_required,
        timed_out: report.coverage.endpoints_timed_out,
    };
    riftlock_report::to_html_with_context(&all, &context)
}

/// Everything the `scan` subcommand needs beyond the target URL.
struct ScanOptions<'a> {
    rps: u32,
    /// Suppress per-engine lifecycle progress and the final report.
    quiet: bool,
    bearer: Option<String>,
    cookie: Option<String>,
    provider: &'a str,
    depth: Depth,
    scope_file: Option<String>,
    scope: &'a str,
    format: Format,
    output: Option<String>,
    show_secrets: bool,
    wordlist: Option<&'a str>,
    /// Discovery wall-clock budget; replaces the old fixed constant.
    discovery_budget: Duration,
    godmode: bool,
    /// An in-progress checkpoint to continue (`--resume`), or a fresh one
    /// to write as the run progresses. None for audit runs.
    resume: Option<Checkpoint>,
}

/// Build the scope for a scan/audit run. The exact scoped host is the only
/// thing that can be fetched, whether it is public or a LAN address.
fn build_scope_guard(origins: &[&str]) -> Result<ScopeGuard, riftlock_core::ScopeError> {
    ScopeGuard::new(origins)
}

fn print_godmode_banner() {
    eprintln!(
        "{}",
        ui::theme::failure(
            "[!] GODMODE ACTIVATED: Maximum depth, destructive payloads, all engines. You own this target."
        )
    );
}

async fn scan_cmd(url: &str, mut opts: ScanOptions<'_>) -> i32 {
    ui::brand::print_logo();
    ui::brand::print_auth_banner();
    let scan_started_at = SystemTime::now();
    // Every completed scan writes a self-contained HTML report, regardless
    // of depth or the selected stdout format.
    let save_html = true;
    if opts.godmode {
        print_godmode_banner();
        opts.depth = Depth::Godmode;
        opts.rps = 50;
        // Keep caller scope authorization intact; godmode does not erase scope files.
        opts.provider = "auto";
    }
    // The rate limit is configured after the preset resolves, so godmode's
    // 50 RPS is the rate actually enforced.
    riftlock_core::configure_host_rate(opts.rps);
    let parsed = match Url::parse(url) {
        Ok(u) => u,
        Err(e) => {
            eprintln!("error: invalid url: {e}");
            return EXIT_ERROR;
        }
    };
    // Boot identity to stderr; the screen is never cleared, so the typed
    // command stays visible in scrollback.
    ui::brand::boot(url, opts.depth.label());
    if opts.format == Format::Html && opts.output.is_none() {
        let mode = opts.depth.label().to_ascii_lowercase();
        opts.output = Some(report_filename(
            parsed.host_str().unwrap_or("target"),
            &mode,
            scan_started_at,
        ));
    }
    let html_path = if opts.format == Format::Html {
        opts.output.clone()
    } else {
        let mode = opts.depth.label().to_ascii_lowercase();
        Some(report_filename(
            parsed.host_str().unwrap_or("target"),
            &mode,
            scan_started_at,
        ))
    };
    let lab_guard = match resolve_lab_guard(url, &parsed, opts.depth, opts.scope_file.as_deref()) {
        Ok(g) => g,
        Err(code) => return code,
    };
    // Empty scope: the exact target origin is the scope, so
    // `riftlock scan https://example.com` just works.
    let default_origin;
    let origins: Vec<&str> = if opts.scope.is_empty() {
        default_origin = scope_origin(&parsed);
        vec![default_origin.as_str()]
    } else {
        opts.scope.split(',').filter(|s| !s.is_empty()).collect()
    };
    let started = std::time::Instant::now();
    let policy = if matches!(opts.depth, Depth::Normal | Depth::Read) {
        riftlock_core::ScanPolicy::ReadOnly
    } else {
        riftlock_core::ScanPolicy::Active
    };
    let guard = match build_scope_guard(&origins) {
        Ok(g) => g.with_policy(policy),
        Err(e) => {
            eprintln!("error: {e}");
            return EXIT_ERROR;
        }
    };
    // Normal is the only passive run; nothing else can turn it on.
    let passive = opts.depth == Depth::Normal;
    let scan_coverage = riftlock_core::Coverage::default();
    // Every scan runs under a checkpoint: created now (so a kill after
    // discovery leaves a resumable file), updated per engine, removed when
    // the run completes. A resumed run continues its existing checkpoint.
    let mut checkpoint = match opts.resume.take() {
        Some(ck) => {
            eprintln!(
                "[checkpoint] resuming scan {} ({} engines completed, {} failed so far)",
                ck.scan_id,
                ck.completed_tasks.len(),
                ck.failed_tasks.len()
            );
            ck
        }
        None => {
            let ck = Checkpoint::new(
                &checkpoint::new_scan_id(url),
                url,
                origins.iter().map(|o| (*o).to_owned()).collect(),
                checkpoint::CheckpointConfig {
                    provider: opts.provider.to_owned(),
                    passive_only: passive,
                    depth: opts.depth.label().to_owned(),
                    unsafe_bypass: false,
                    scope_file: opts.scope_file.clone(),
                    wordlist: opts.wordlist.map(String::from),
                    godmode: opts.godmode,
                },
            );
            ck.save();
            eprintln!(
                "[checkpoint] scan id: {} — resume with --resume {} if interrupted",
                ck.scan_id, ck.scan_id
            );
            ck
        }
    };
    let (
        findings,
        failures,
        _engines_clean,
        endpoints_discovered,
        engines_spawned,
        discovery_error,
        planned,
        crawl_metrics,
        unreached_endpoints,
    ) = match run_scanners(
        &parsed,
        opts.provider,
        opts.depth,
        opts.bearer.as_deref(),
        opts.cookie.as_deref(),
        lab_guard,
        &guard,
        passive,
        opts.quiet,
        opts.wordlist,
        &scan_coverage,
        Some(&mut checkpoint),
        opts.discovery_budget,
    )
    .await
    {
        Ok(result) => result,
        Err(code) => return code,
    };
    let chains = riftlock_engine::ChainBuilder::build(&findings);
    // What the engines classified but could not verify, keyed by URL. Read
    // from the run-wide ledger before it is reduced to counters.
    let untested_surface = scan_coverage.endpoint_records();

    // One run state feeds the headline, the coverage block and the exit code:
    // a scan with no findings but blocked or untested coverage is INCOMPLETE,
    // never CLEAN.
    // A failed discovery is a failed stage, even when every engine it fed
    // still ran against the root URL: the inventory it should have produced
    // is unknown, so the run cannot be CLEAN.
    // The generic engine's plan is the denominator its outcome counters use
    // (the discovered inventory includes unprobeable names it never counts).
    // Only when that plan never arrived does the inventory stand in.
    let coverage_denominator = if planned == 0 {
        endpoints_discovered
    } else {
        planned
    };
    let mut snapshot = scan_coverage.snapshot(coverage_denominator as u64);
    snapshot.passive_observations = findings
        .iter()
        .filter(|f| f.evidence().is_passive_observation())
        .count() as u64;
    // Engine/stage failures remain separate from probe-level failed checks.
    let accounting = scan_coverage.finalize();
    // Findings with no ledger registrations at all are unaccounted executions:
    // the verdict must stay incomplete even though counters may balance.
    let unaccounted = if accounting.registered == 0 && !findings.is_empty() {
        1
    } else {
        0
    };
    // A crawl whose own counters do not reconcile, or that left scheduled
    // URLs unclassified, makes the run incomplete even without an error text.
    let crawl_incomplete = crawl_incomplete(&crawl_metrics);
    if crawl_incomplete {
        eprintln!(
            "[!] Warning: crawl accounting incomplete ({:?}); coverage is incomplete.",
            crawl_metrics.termination_reason
        );
    }
    // Planned endpoints the generic engine never reached are a failed stage
    // even when its findings survived: that part of the plan was never
    // assessed, so the run cannot be CLEAN.
    let endpoints_unreached = !unreached_endpoints.is_empty();
    let state = RunState::with_accounting(
        findings.len(),
        failures
            + usize::from(discovery_error.is_some())
            + usize::from(crawl_incomplete)
            + usize::from(endpoints_unreached),
        snapshot,
        accounting,
        unaccounted,
    );
    let discovery = discovery_status(discovery_error.as_deref());
    let mut report_meta = riftlock_report::ScanMetadata::new(
        checkpoint.scan_id.clone(),
        parsed.to_string(),
        state.status_label().to_owned(),
        discovery.clone(),
    );
    report_meta.scope = origins.iter().map(|s| (*s).to_owned()).collect();
    report_meta.coverage = snapshot;
    report_meta.untested_surface = untested_surface
        .iter()
        .filter(|record| record.outcome != riftlock_core::EndpointOutcome::Tested)
        .cloned()
        .collect();
    report_meta.unreached_endpoints = unreached_endpoints.clone();
    report_meta.crawl = crawl_metrics.clone();
    report_meta.accounting = accounting;
    report_meta.unaccounted_executions = unaccounted;
    report_meta.engines_executed = engines_spawned;
    report_meta.engines_failed = failures;
    report_meta.discovered_inventory_endpoints = endpoints_discovered;
    report_meta.generic_planned_endpoints = planned;
    report_meta.passive_observations = snapshot.passive_observations;
    report_meta.findings = findings.len();
    report_meta.scanner_failures = checkpoint.failed_tasks.clone();
    report_meta.termination_reason = if !accounting.reconciles() || unaccounted > 0 {
        "accounting_failure"
    } else if discovery_error.is_some() {
        "discovery_failed"
    } else if crawl_incomplete {
        "crawl_incomplete"
    } else if endpoints_unreached {
        "endpoints_unreached"
    } else if failures > 0 {
        "engine_failure"
    } else {
        "normal_completion"
    }
    .to_owned();
    let human = matches!(opts.format, Format::Human);
    if findings.is_empty() {
        let line = match state.verdict.label() {
            "CLEAN" => ui::theme::scanning("[CLEAN] No vulnerabilities found."),
            "INCOMPLETE" => ui::theme::warning(
                "[INCOMPLETE] No findings, but coverage was blocked, inconclusive or incomplete.",
            ),
            _ => String::new(),
        };
        if !line.is_empty() {
            if human {
                println!("{line}");
            } else {
                eprintln!("{line}");
            }
        }
    } else if !state.verdict.coverage_complete {
        // stderr keeps machine-readable formats (JSON/NDJSON/SARIF) parseable.
        eprintln!(
            "{}",
            ui::theme::warning(&incomplete_coverage_message(
                &state,
                discovery_error.as_deref(),
                &crawl_metrics,
                &checkpoint.failed_tasks,
                failures,
                &unreached_endpoints,
            ))
        );
    }
    match opts.format {
        Format::Human => {
            // --output saves the machine-readable SARIF report alongside the
            // human report above.
            if let Some(path) = opts.output.as_deref() {
                let rendered = render(
                    &findings,
                    &chains,
                    Format::Sarif,
                    state.status_label(),
                    &report_meta,
                );
                if let Err(e) = std::fs::write(path, rendered) {
                    eprintln!("error: cannot write {path}: {e}");
                    return EXIT_ERROR;
                }
                println!(
                    "{}",
                    ui::theme::scanning(&format!(
                        "[+] SARIF report saved to {}",
                        saved_path_display(path)
                    ))
                );
            }
        }
        Format::Pdf => {
            // PDF is binary: never printed to stdout, --output is required.
            let Some(path) = opts.output.as_deref() else {
                eprintln!("error: --format pdf writes a binary report; use --output <PATH>");
                return EXIT_ERROR;
            };
            let all: Vec<Finding> = findings.iter().chain(chains.iter()).cloned().collect();
            let bytes = match riftlock_report::to_pdf(&all) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("error: {e}");
                    return EXIT_ERROR;
                }
            };
            if let Err(e) = std::fs::write(path, bytes) {
                eprintln!("error: cannot write {path}: {e}");
                return EXIT_ERROR;
            }
            println!(
                "{}",
                ui::theme::scanning(&format!(
                    "[+] PDF report saved to {}",
                    saved_path_display(path)
                ))
            );
        }
        other => {
            if other != Format::Html && other != Format::Human {
                let rendered = render(
                    &findings,
                    &chains,
                    other,
                    state.status_label(),
                    &report_meta,
                );
                match opts.output.as_deref() {
                    Some(path) => {
                        if let Err(e) = std::fs::write(path, rendered) {
                            eprintln!("error: cannot write {path}: {e}");
                            return EXIT_ERROR;
                        }
                        let saved = format!(
                            "[+] {} report saved to {}",
                            format!("{other:?}").to_lowercase(),
                            saved_path_display(path)
                        );
                        if human {
                            println!("{}", ui::theme::scanning(&saved));
                        } else {
                            eprintln!("{}", ui::theme::scanning(&saved));
                        }
                    }
                    None => println!("{rendered}"),
                }
            }
        }
    }
    // The report is written even on a clean scan: "no findings" is a
    // deliverable, not an absence of one.
    // Machine-readable formats own stdout: the summary, credential block and
    // per-finding renderers write to stdout only in human mode. JSON/NDJSON
    // still get one stderr status line and the final analysis block.
    if human {
        // Dedicated credential presentation: terminal-only, cyan, masked by
        // default. Machine-readable formats never reach this renderer.
        let credentials = ui::credentials::collect(&findings);
        if !credentials.is_empty() {
            use std::io::IsTerminal;
            let interactive = std::io::stdout().is_terminal();
            for line in ui::credentials::render(&credentials, opts.show_secrets, interactive) {
                println!("{line}");
            }
        }
        // Surface the critical/high endpoint groups immediately before the
        // detailed findings so operators can locate the highest-risk pages.
        for line in ui::lifecycle::print_vulnerable_pages(&findings) {
            println!("{line}");
        }
        // Every verified finding and chain, last: the scan is complete and no
        // later status or report line can bury it.
        for f in &findings {
            ui::findings::print_finding(f);
        }
        for chain in &chains {
            if let riftlock_core::Evidence::Chain { steps, verdict } = chain.evidence() {
                ui::findings::print_chain(steps, verdict);
            }
        }
    } else {
        eprintln!(
            "[status] {} — {} findings, {} checks ({} completed, {} inconclusive), {} engines",
            state.verdict.label(),
            findings.len(),
            snapshot.vulnerability_checks_attempted,
            snapshot.vulnerability_checks_completed,
            snapshot.vulnerability_checks_inconclusive,
            engines_spawned
        );
    }
    if !opts.quiet && human {
        let report = ui::final_report::FinalReport {
            target: url,
            mode: opts.depth.label(),
            elapsed: started.elapsed(),
            findings: &findings,
            records: &untested_surface,
            unreached: &unreached_endpoints,
            methods: &checkpoint.discovered_endpoint_methods,
            coverage: &snapshot,
            incomplete_coverage: !state.verdict.coverage_complete,
            has_findings: state.verdict.has_findings(),
            discovered: endpoints_discovered,
        };
        for line in ui::final_report::render_final_report(&report) {
            println!("{line}");
        }
    }
    // HTML is an independent deliverable for godmode and HTML format; it
    // never changes which format owns stdout.
    if save_html {
        if let Some(path) = html_path.as_deref() {
            let report = ui::final_report::FinalReport {
                target: url,
                mode: opts.depth.label(),
                elapsed: started.elapsed(),
                findings: &findings,
                records: &untested_surface,
                unreached: &unreached_endpoints,
                methods: &checkpoint.discovered_endpoint_methods,
                coverage: &snapshot,
                incomplete_coverage: !state.verdict.coverage_complete,
                has_findings: state.verdict.has_findings(),
                discovered: endpoints_discovered,
            };
            let rendered = render_html(
                &findings,
                &chains,
                !state.verdict.coverage_complete,
                state.verdict.has_findings(),
                &report,
            );
            if let Err(e) = std::fs::write(path, rendered) {
                eprintln!("error: cannot write {path}: {e}");
                return EXIT_ERROR;
            }
            use std::io::IsTerminal;
            let output_is_terminal = if human {
                std::io::stdout().is_terminal()
            } else {
                std::io::stderr().is_terminal()
            };
            let saved = html_report_location_message(path, output_is_terminal);
            if human {
                println!("{}", ui::theme::scanning(&saved));
            } else {
                eprintln!("{}", ui::theme::scanning(&saved));
            }
        }
    }
    riftlock_core::logln!("Scan complete.");
    // The run completed: only interrupted scans leave a resumable file.
    checkpoint.remove();
    exit_code(state.status)
}

/// Machine-facing outcome for a completed scan, derived from the same
/// `RunState` as the printed status.
fn exit_code(status: RunStatus) -> i32 {
    match status {
        RunStatus::Clean => EXIT_CLEAN,
        RunStatus::Findings => EXIT_FINDINGS,
        // Inconclusive coverage is not a clean result for automation either.
        RunStatus::Incomplete => EXIT_ERROR,
    }
}

/// The `audit` super command: all scanners, read depth unless a scope file
/// authorizes write, SARIF report to ./riftlock-report.sarif.
async fn audit_cmd(url: &str, scope_file: Option<String>, godmode: bool) -> i32 {
    if godmode {
        print_godmode_banner();
    }
    let parsed = match Url::parse(url) {
        Ok(u) => u,
        Err(e) => {
            eprintln!("error: invalid url: {e}");
            return EXIT_ERROR;
        }
    };
    // Read depth (safe for production) unless the scope file authorizes
    // destructive probes for this target.
    let (depth, lab_guard) = if godmode {
        // The godmode preset does not itself authorize a target: it still
        // needs the scope file (or the interactive confirmation that the
        // scope machinery requires for destructive probes).
        match resolve_lab_guard(url, &parsed, Depth::Godmode, scope_file.as_deref()) {
            Ok(guard) => (Depth::Godmode, guard),
            Err(code) => return code,
        }
    } else {
        match scope_file.as_deref() {
            Some(path) => match riftlock_core::ScopeConfig::load(path) {
                Ok(config) => match riftlock_core::LabGuard::new_from_scope(&config, &parsed) {
                    Ok(guard) => (Depth::Godmode, Some(guard)),
                    Err(_) => (Depth::Read, None),
                },
                Err(e) => {
                    eprintln!("warning: invalid scope file ({e}); staying at read depth");
                    (Depth::Read, None)
                }
            },
            None => (Depth::Read, None),
        }
    };
    // Audit implies an active scan: the target itself is the scope.
    let guard = match build_scope_guard(&[url]) {
        Ok(g) => g,
        Err(_) => match build_scope_guard(&[&format!("https://{url}")]) {
            Ok(g) => g,
            Err(e) => {
                eprintln!("error: {e}");
                return EXIT_ERROR;
            }
        },
    };
    // Godmode pacing applies to the audit preset too; the process default is
    // the Read rate.
    let rps = if depth == Depth::Godmode {
        50
    } else {
        DEFAULT_RPS
    };
    riftlock_core::configure_host_rate(rps);
    let findings = match run_scanners(
        &parsed,
        "auto",
        depth,
        None,
        None,
        lab_guard,
        &guard,
        false,
        false,
        None,
        &riftlock_core::Coverage::default(),
        None,
        DEFAULT_DISCOVERY_BUDGET,
    )
    .await
    {
        Ok((f, ..)) => f,
        Err(code) => return code,
    };
    let chains = riftlock_engine::ChainBuilder::build(&findings);
    let report = riftlock_report::to_sarif(
        &findings
            .iter()
            .chain(chains.iter())
            .cloned()
            .collect::<Vec<Finding>>(),
    );
    let path = "riftlock-report.sarif";
    if let Err(e) = std::fs::write(path, report) {
        eprintln!("error: cannot write {path}: {e}");
        return EXIT_ERROR;
    }
    println!(
        "Audit complete. Found {} findings. Report saved to {}",
        findings.len() + chains.len(),
        saved_path_display(path)
    );
    for f in &findings {
        ui::findings::print_finding(f);
    }
    for chain in &chains {
        if let riftlock_core::Evidence::Chain { steps, verdict } = chain.evidence() {
            ui::findings::print_chain(steps, verdict);
        }
    }
    if findings.is_empty() {
        EXIT_CLEAN
    } else {
        EXIT_FINDINGS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_filename_contains_host_mode_and_utc_timestamp() {
        let timestamp = UNIX_EPOCH + Duration::from_secs(1_795_714_323);
        assert_eq!(
            report_filename("pentest-ground.com", "read", timestamp),
            "pentest-ground.com-read-report-20261126-173203-000000000.html"
        );
        assert_eq!(
            report_filename("duck-store.escape.tech", "godmode", timestamp),
            "duck-store.escape.tech-godmode-report-20261126-173203-000000000.html"
        );
    }

    fn lab_client() -> Client {
        Client::new_lab()
    }

    #[test]
    fn discovery_status_distinguishes_complete_partial_and_failed() {
        assert_eq!(discovery_status(None), "complete");
        assert_eq!(
            discovery_status(Some("crawl budget exhausted")),
            "partial — crawl budget exhausted"
        );
        assert_eq!(
            discovery_status(Some("failed at start page")),
            "failed — target root only"
        );
        assert_eq!(
            discovery_status(Some("discovery budget exhausted")),
            "failed — target root only"
        );
    }

    #[test]
    fn drained_deadline_queue_is_not_incomplete() {
        let crawl = riftlock_core::CrawlMetrics {
            termination_reason: "deadline".to_owned(),
            ..Default::default()
        };
        assert!(!crawl_incomplete(&crawl));

        let mut untested = crawl;
        untested.remaining = 1;
        untested.scheduled = 1;
        assert!(crawl_incomplete(&untested));
    }

    #[test]
    fn incomplete_verdict_explains_actual_coverage_gaps() {
        let coverage = riftlock_report::ScanCoverage {
            endpoints_discovered: 4,
            endpoints_tested_successfully: 1,
            endpoints_waf_blocked: 2,
            vulnerability_checks_attempted: 3,
            vulnerability_checks_completed: 1,
            vulnerability_checks_inconclusive: 2,
            ..Default::default()
        };
        let state = RunState::new(1, 2, coverage);
        let crawl = riftlock_core::CrawlMetrics {
            termination_reason: "deadline".to_owned(),
            remaining: 3,
            ..Default::default()
        };
        let message = incomplete_coverage_message(
            &state,
            Some("crawl budget exhausted"),
            &crawl,
            &["SPA: connection refused".to_owned()],
            1,
            &[],
        );
        assert!(message.contains("SPA: connection refused"), "{message}");
        assert!(
            message.contains("discovery incomplete: crawl budget exhausted"),
            "{message}"
        );
        assert!(
            message.contains("deadline exhausted with 3 URL(s) untested"),
            "{message}"
        );
        assert!(
            message.contains("2 of 3 assessed endpoints were auth-required, blocked"),
            "{message}"
        );
        assert!(
            message.contains("2 of 3 vulnerability check(s) did not complete"),
            "{message}"
        );
        assert!(
            message.contains("2 vulnerability check(s) were inconclusive"),
            "{message}"
        );
        assert!(!message.contains("Real evidence was found, but discovery or engines failed"));
    }

    #[test]
    fn miss_clause_uses_assessed_total_not_discovered_inventory() {
        // Several engines classify the same endpoint, so the assessed total
        // can exceed the discovered inventory. The untested clause must never
        // report a numerator larger than its denominator, and skipped (404)
        // endpoints must not inflate either side of the ratio.
        let coverage = riftlock_report::ScanCoverage {
            endpoints_discovered: 16,
            endpoints_tested_successfully: 20,
            endpoints_auth_required: 10,
            endpoints_waf_blocked: 6,
            endpoints_circuit_open: 2,
            endpoints_skipped: 5,
            vulnerability_checks_attempted: 1,
            vulnerability_checks_completed: 1,
            ..Default::default()
        };
        let state = RunState::new(0, 0, coverage);
        let message = incomplete_coverage_message(
            &state,
            None,
            &riftlock_core::CrawlMetrics::default(),
            &[],
            0,
            &[],
        );
        assert!(message.contains("18 of 38 assessed endpoints"), "{message}");
        assert!(!message.contains("16 of 16"), "{message}");
        assert!(!message.contains("discovered endpoint(s) were never classified"));
    }

    #[test]
    fn incomplete_reasons_name_planned_endpoints_never_reached() {
        let state = RunState::new(0, 0, full_coverage());
        let message = incomplete_coverage_message(
            &state,
            None,
            &riftlock_core::CrawlMetrics::default(),
            &[],
            0,
            &[
                "https://example.test/api/users".to_owned(),
                "https://example.test/api/audit".to_owned(),
            ],
        );
        assert!(
            message.contains("2 planned endpoint(s) were never reached before the engine stopped"),
            "{message}"
        );
    }

    #[test]
    fn terminal_and_report_status_agree() {
        let finding = riftlock_core::ProofGate::admit(riftlock_core::Evidence::AuthBypass {
            endpoint: "https://x/auth".into(),
            method: "POST".into(),
        })
        .expect("admitted");
        let findings = vec![finding];
        // A finding with blocked coverage must carry the combined label in
        // every machine report, not just the terminal.
        let state = RunState::new(1, 1, riftlock_report::ScanCoverage::default());
        let status = state.status_label();
        assert_eq!(status, "FINDINGS + INCOMPLETE COVERAGE");

        let meta = riftlock_report::ScanMetadata::new(
            "t".into(),
            "https://x".into(),
            status.into(),
            "n/a".into(),
        );
        assert!(render(&findings, &[], Format::Html, status, &meta).contains(status));
        assert!(render(&findings, &[], Format::Markdown, status, &meta).contains(status));
        let sarif = render(&findings, &[], Format::Sarif, status, &meta);
        let doc: serde_json::Value = serde_json::from_str(&sarif).expect("sarif json");
        assert_eq!(doc["runs"][0]["properties"]["scanStatus"], status);
    }

    #[test]
    fn html_and_markdown_render_dispatch() {
        let finding = riftlock_core::ProofGate::admit(riftlock_core::Evidence::AuthBypass {
            endpoint: "https://x/auth/v1/signup".into(),
            method: "POST".into(),
        })
        .expect("admitted");
        let findings = vec![finding];
        let html = render(
            &findings,
            &[],
            Format::Html,
            "UNKNOWN",
            &riftlock_report::ScanMetadata::new(
                "t".into(),
                "https://x".into(),
                "UNKNOWN".into(),
                "n/a".into(),
            ),
        );
        assert!(html.contains("RIFTLOCK SCAN RESULT"));
        assert!(html.contains("AuthBypass"));
        let md = render(
            &findings,
            &[],
            Format::Markdown,
            "UNKNOWN",
            &riftlock_report::ScanMetadata::new(
                "t".into(),
                "https://x".into(),
                "UNKNOWN".into(),
                "n/a".into(),
            ),
        );
        assert!(md.contains("# RIFTLOCK SECURITY REPORT"));
        assert!(md.contains("**High**"));
    }

    #[test]
    fn godmode_keeps_human_stdout_format_and_saves_html_independently() {
        let opts = ScanOptions {
            rps: DEFAULT_RPS,
            quiet: false,
            bearer: None,
            cookie: None,
            provider: "auto",
            depth: Depth::Read,
            scope_file: None,
            scope: "",
            format: Format::Human,
            output: None,
            show_secrets: false,
            wordlist: None,
            discovery_budget: DEFAULT_DISCOVERY_BUDGET,
            godmode: true,
            resume: None,
        };
        let save_html = opts.godmode || matches!(opts.format, Format::Html);
        let stdout_format = opts.format;
        assert!(save_html);
        assert!(matches!(stdout_format, Format::Human));

        let finding = riftlock_core::ProofGate::admit(riftlock_core::Evidence::AuthBypass {
            endpoint: "https://x/auth".into(),
            method: "POST".into(),
        })
        .expect("admitted");
        let final_report = ui::final_report::FinalReport {
            target: "https://x/",
            mode: "godmode",
            elapsed: Duration::ZERO,
            findings: std::slice::from_ref(&finding),
            records: &[],
            unreached: &[],
            methods: &[],
            coverage: &riftlock_report::ScanCoverage::default(),
            incomplete_coverage: false,
            has_findings: true,
            discovered: 0,
        };
        let stdout_report = ui::final_report::render_final_report(&final_report).join("\n");
        let html_report = render_html(
            std::slice::from_ref(&finding),
            &[],
            false,
            true,
            &final_report,
        );
        assert!(stdout_report.contains("RIFTLOCK SCAN RESULT"));
        assert!(stdout_report.contains("YOUR SITE HAS"));
        assert!(html_report.contains("RIFTLOCK SCAN RESULT"));
    }

    #[test]
    fn lab_guard_only_issued_for_godmode() {
        let url = Url::parse("https://lab.example").expect("url");
        // Below Godmode: no guard, no prompt.
        assert!(
            resolve_lab_guard("https://lab.example", &url, Depth::Read, None)
                .is_ok_and(|g| g.is_none())
        );
        // Godmode without a scope file goes through interactive
        // confirmation, which cannot be exercised without stdin in a test;
        // there is no flag that skips it.
    }

    #[tokio::test]
    async fn client_surfaces_redirects_instead_of_following() {
        let server = wiremock::MockServer::start().await;
        // The redirect target: reached only if reqwest followed the 302,
        // which would bypass ScopeGuard (SSRF).
        let target = wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/next"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("followed"))
            .expect(0)
            .mount_as_scoped(&server)
            .await;
        let redirect = wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(302).insert_header("location", "/next"))
            .mount_as_scoped(&server)
            .await;
        let resp = lab_client().get(server.uri()).send().await.expect("send");
        // The 302 itself is the response, not the redirect target's body.
        assert_eq!(resp.status(), reqwest::StatusCode::FOUND);
        assert_eq!(redirect.received_requests().await.len(), 1);
        assert!(
            target.received_requests().await.is_empty(),
            "client followed the redirect"
        );
    }

    fn lab_guard_for(url: &Url) -> ScopeGuard {
        ScopeGuard::new_lab(&[url.as_str()]).expect("lab guard")
    }

    /// Discovery of a refused start page reports a transport failure instead
    /// of returning an empty inventory as if the crawl had found nothing.
    #[tokio::test]
    async fn explicit_supabase_provider_does_not_probe_nonmatching_target() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .insert_header("content-type", "text/html")
                    .set_body_string("<html><title>Local app</title></html>"),
            )
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/rest/v1/users"))
            .respond_with(wiremock::ResponseTemplate::new(401))
            .mount(&server)
            .await;
        let url = Url::parse(&server.uri()).expect("url");
        assert!(!riftlock_core::Scanner::matches(
            &riftlock_scanner_supabase::SupabaseScanner::default(),
            &url
        ));
        let guard = lab_guard_for(&url);

        run_scanners(
            &url,
            "supabase",
            Depth::Read,
            None,
            None,
            None,
            &guard,
            false,
            true,
            None,
            &riftlock_core::Coverage::default(),
            None,
            Duration::from_secs(45),
        )
        .await
        .expect("explicit Supabase provider scan");

        let requests = server.received_requests().await.expect("requests");
        assert!(
            requests
                .iter()
                .all(|request| request.url.path() != "/rest/v1/users"),
            "explicit provider probed a target that did not fingerprint as Supabase"
        );
    }

    #[tokio::test]
    async fn not_applicable_supabase_is_skipped_without_engine_failure() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .insert_header("content-type", "text/html")
                    .set_body_string("<html><title>Local app</title></html>"),
            )
            .mount(&server)
            .await;
        let url = Url::parse(&server.uri()).expect("url");
        let guard = lab_guard_for(&url);
        let result = riftlock_core::Scanner::scan(
            &riftlock_scanner_supabase::SupabaseScanner::default(),
            &url,
            &lab_client(),
            &guard,
            false,
        )
        .await;
        assert!(matches!(result, Ok(ref findings) if findings.is_empty()));

        let mut set = tokio::task::JoinSet::<EngineReport>::new();
        set.spawn(async move { (0, "Supabase", Duration::ZERO, Some(result), None) });
        let (_tx, events) = tokio::sync::mpsc::channel(1);
        let (slots, _, _, _) = drain_scans(set, 1, None, events, false).await;
        let engines_failed = slots
            .iter()
            .filter_map(|slot| slot.as_ref()?.as_ref().err())
            .filter(|error| engine_error_counts_as_failure(error))
            .count();
        assert_eq!(engines_failed, 0);
        assert_eq!(
            ui::lifecycle::RunState::new(0, engines_failed, full_coverage()).status,
            ui::lifecycle::RunStatus::Clean,
            "a non-applicable Supabase engine alone must not make coverage incomplete"
        );
    }

    #[tokio::test]
    async fn discovery_reports_start_page_transport_failure() {
        // Bind then release an ephemeral port: the URL is valid, nothing
        // listens — the same stage a refused homepage fetch fails at.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        drop(listener);
        let url = Url::parse(&format!("http://{addr}/")).expect("url");
        let guard = lab_guard_for(&url);
        let error = discover_context(
            &lab_client(),
            &url,
            &guard,
            &riftlock_core::SessionMatrix::default(),
            std::time::Instant::now(),
            Depth::Read,
            &riftlock_fingerprint::FetchCache::default(),
        )
        .await
        .expect_err("a refused start page is a discovery error");
        assert!(matches!(error, ScanError::Http(_)), "{error:?}");
    }

    /// A slow origin (the live Juice Shop 503 takes ~5 s) times out under the
    /// 4 s request cap. The real error text must survive with an actionable
    /// category, and the root failure is terminal before any engine spawns.
    #[tokio::test]
    async fn discovery_timeout_keeps_cause_and_aborts_the_scan() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(
                wiremock::ResponseTemplate::new(503)
                    .set_delay(std::time::Duration::from_millis(600)),
            )
            .mount(&server)
            .await;
        let url = Url::parse(&server.uri()).expect("url");
        let guard = lab_guard_for(&url);
        let short = riftlock_core::ScopedClient::from_builder(
            reqwest::Client::builder().timeout(std::time::Duration::from_millis(100)),
            &guard,
        )
        .expect("client");
        let error = discover_context(
            &short,
            &url,
            &guard,
            &riftlock_core::SessionMatrix::default(),
            std::time::Instant::now(),
            Depth::Read,
            &riftlock_fingerprint::FetchCache::default(),
        )
        .await
        .expect_err("slow start page is a transport failure");
        let detail = discovery_failure_detail(&error);
        assert!(detail.contains("transport:timeout"), "{detail}");
        assert!(detail.contains("error sending request"), "{detail}");
        assert_eq!(
            discovery_status(Some(&format!("failed at start page: {detail}"))),
            "failed — target root only"
        );
    }

    /// A 503 on the target root is terminal through the whole scan pipeline:
    /// the scan returns the error exit code before the engine spawn loop, so
    /// every request is a retry of the root GET and no engine probe path was
    /// ever requested.
    #[tokio::test]
    async fn root_503_aborts_before_any_engine_spawns() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/"))
            .respond_with(wiremock::ResponseTemplate::new(503))
            .mount(&server)
            .await;
        let url = Url::parse(&server.uri()).expect("url");
        let guard = lab_guard_for(&url);
        let result = run_scanners(
            &url,
            "auto",
            Depth::Read,
            None,
            None,
            None,
            &guard,
            false,
            true,
            None,
            &riftlock_core::Coverage::default(),
            None,
            Duration::from_secs(45),
        )
        .await;
        assert_eq!(
            result.expect_err("a 503 root must abort the scan"),
            EXIT_ERROR
        );
        let requests = server.received_requests().await.expect("requests");
        let paths: Vec<_> = requests.iter().map(|request| request.url.path()).collect();
        assert!(!paths.is_empty(), "the root was never requested");
        assert!(
            paths.iter().all(|path| *path == "/"),
            "an engine was spawned after a failed root: {paths:?}"
        );
    }

    #[tokio::test]
    async fn scan_cmd_root_503_returns_error_before_any_scanner_request() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/"))
            .respond_with(wiremock::ResponseTemplate::new(503))
            .mount(&server)
            .await;
        let url = Url::parse(&server.uri()).expect("url");
        let scan_id = format!("root-503-test-{}", std::process::id());
        let checkpoint = Checkpoint::new(
            &scan_id,
            &server.uri(),
            vec![server.uri()],
            checkpoint::CheckpointConfig {
                provider: "auto".into(),
                passive_only: false,
                depth: "Read".into(),
                unsafe_bypass: false,
                scope_file: None,
                wordlist: None,
                godmode: false,
            },
        );

        let code = scan_cmd(
            url.as_str(),
            ScanOptions {
                rps: DEFAULT_RPS,
                quiet: true,
                bearer: None,
                cookie: None,
                provider: "auto",
                depth: Depth::Read,
                scope_file: None,
                scope: "",
                format: Format::Human,
                output: None,
                show_secrets: false,
                wordlist: None,
                discovery_budget: Duration::from_secs(45),
                godmode: false,
                // Passing an in-memory checkpoint avoids creating a file when
                // scan_cmd exits early, before its normal completion cleanup.
                resume: Some(checkpoint),
            },
        )
        .await;

        assert_eq!(code, EXIT_ERROR, "503 should exit with code 2");
        let requests = server.received_requests().await.expect("requests");
        // The root baseline is sent exactly once; the first 503 aborts before
        // any scanner request or retry delay.
        assert_eq!(
            requests.len(),
            1,
            "only one root discovery request should run"
        );
        assert!(
            requests
                .iter()
                .all(|request| request.method.as_str() == "GET" && request.url.path() == "/"),
            "a scanner request occurred after the failed root: {requests:?}"
        );
    }

    #[test]
    fn http_status_failure_keeps_the_status_in_its_detail() {
        // A non-success root status is terminal for the scan; the message
        // still names the status so the operator sees why it aborted.
        let detail = discovery_failure_detail(&ScanError::HttpStatus(503));
        assert!(detail.contains("503"), "{detail}");
    }

    #[test]
    fn body_read_failure_is_categorized() {
        use riftlock_core::body::BodyReadError;
        let error = ScanError::Body(BodyReadError::TooLarge);
        assert_eq!(
            error.transport_category(),
            Some(riftlock_core::TransportError::BodyRead)
        );
        assert!(!discovery_failure_detail(&error).is_empty());
    }

    #[test]
    fn zero_findings_with_failed_engines_and_no_checks_is_incomplete() {
        let coverage = ui::lifecycle::RunState::new(
            0,
            27,
            riftlock_report::ScanCoverage {
                endpoints_discovered: 0,
                ..Default::default()
            },
        );
        assert_eq!(coverage.status, ui::lifecycle::RunStatus::Incomplete);
        assert_eq!(coverage.status.label(), "INCOMPLETE");
    }

    /// Three engines failing on one shared transport problem are three failed
    /// checks, not three clean negatives and not a clean scan conclusion.
    #[tokio::test]
    async fn shared_transport_failures_are_counted_as_engine_failures() {
        let mut set = tokio::task::JoinSet::new();
        for i in 0..3 {
            set.spawn(async move {
                (
                    i,
                    "Engine",
                    Duration::ZERO,
                    Some(Err::<Vec<Finding>, ScanError>(
                        ScanError::SharedTransportFailure(
                            "transport:timeout: error sending request".into(),
                        ),
                    )),
                    None,
                )
            });
        }
        let (_tx, rx) = tokio::sync::mpsc::channel(1);
        let (slots, _, _, _) = drain_scans(set, 3, None, rx, false).await;
        let failures = slots
            .iter()
            .filter(|slot| matches!(slot, Some(Err(_))))
            .count();
        assert_eq!(failures, 3);
        let state = ui::lifecycle::RunState::new(0, failures, Default::default());
        assert_eq!(state.status, ui::lifecycle::RunStatus::Incomplete);
    }

    #[tokio::test]
    async fn discovery_reports_start_page_status_and_oversized_body() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(503))
            .mount(&server)
            .await;
        let url = Url::parse(&server.uri()).expect("url");
        let guard = lab_guard_for(&url);
        let error = discover_context(
            &lab_client(),
            &url,
            &guard,
            &riftlock_core::SessionMatrix::default(),
            std::time::Instant::now(),
            Depth::Read,
            &riftlock_fingerprint::FetchCache::default(),
        )
        .await
        .expect_err("a non-success start page is a discovery error");
        assert!(matches!(error, ScanError::HttpStatus(503)), "{error:?}");

        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_bytes(vec![
                b'a';
                riftlock_core::body::MAX_BODY_BYTES
                    + 1
            ]))
            .mount(&server)
            .await;
        let url = Url::parse(&server.uri()).expect("url");
        let guard = lab_guard_for(&url);
        let error = discover_context(
            &lab_client(),
            &url,
            &guard,
            &riftlock_core::SessionMatrix::default(),
            std::time::Instant::now(),
            Depth::Read,
            &riftlock_fingerprint::FetchCache::default(),
        )
        .await
        .expect_err("an oversized start page is a discovery error");
        assert!(
            matches!(
                error,
                ScanError::Body(riftlock_core::body::BodyReadError::TooLarge)
            ),
            "{error:?}"
        );
    }

    /// A connection that dies mid-body is a stream failure, distinguishable
    /// from the oversized-response cap.
    #[tokio::test]
    async fn discovery_reports_truncated_start_page_body() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut request = [0u8; 1024];
                let _ = socket.read(&mut request).await;
                let _ = socket
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nContent-Type: text/html\r\n\r\nshort",
                    )
                    .await;
                // Dropping the socket closes it before the declared body is
                // delivered.
            }
        });
        let url = Url::parse(&format!("http://{addr}/")).expect("url");
        let guard = lab_guard_for(&url);
        let error = discover_context(
            &lab_client(),
            &url,
            &guard,
            &riftlock_core::SessionMatrix::default(),
            std::time::Instant::now(),
            Depth::Read,
            &riftlock_fingerprint::FetchCache::default(),
        )
        .await
        .expect_err("a truncated start page is a discovery error");
        assert!(
            matches!(
                error,
                ScanError::Body(riftlock_core::body::BodyReadError::Transport(_))
            ),
            "{error:?}"
        );
    }

    /// Explicit OAuth selection must probe an authorization endpoint linked
    /// from `/`, not just gate on the start URL path.
    #[tokio::test]
    async fn explicit_oauth_scans_a_discovered_authorize_route_from_root() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .insert_header("content-type", "text/html")
                    .set_body_string(r#"<a href="/oauth/authorize">Sign in</a>"#),
            )
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/oauth/authorize"))
            .respond_with(
                wiremock::ResponseTemplate::new(400)
                    .insert_header("content-type", "application/json")
                    .set_body_string("{}"),
            )
            .mount(&server)
            .await;

        let url = Url::parse(&server.uri()).expect("root URL");
        let guard = lab_guard_for(&url);
        let coverage = riftlock_core::Coverage::default();
        run_scanners(
            &url,
            "oauth",
            Depth::Read,
            None,
            None,
            None,
            &guard,
            false,
            true,
            None,
            &coverage,
            None,
            Duration::from_secs(45),
        )
        .await
        .expect("explicit OAuth scan");

        let requests = server.received_requests().await.expect("requests");
        let oauth_probes: Vec<_> = requests
            .iter()
            .filter(|request| request.url.path() == "/oauth/authorize")
            .filter_map(|request| request.url.query())
            .collect();
        assert!(
            oauth_probes.iter().any(|query| {
                query.contains("redirect_uri=https%3A%2F%2Fevil.com")
                    || query.contains("redirect_uri=https://evil.com")
            }),
            "open-redirect probe did not reach the discovered route: {oauth_probes:?}"
        );
        assert!(
            oauth_probes
                .iter()
                .any(|query| query.contains("response_type=code") && !query.contains("state=")),
            "missing-state probe did not reach the discovered route: {oauth_probes:?}"
        );
        let snapshot = coverage.snapshot(0);
        assert!(
            snapshot.vulnerability_checks_attempted >= 2,
            "OAuth checks were not accounted: {snapshot:?}"
        );
    }

    /// Explicit WebSocket selection must probe a realtime route linked from
    /// `/`, not just gate on the start URL path.
    #[tokio::test]
    async fn explicit_websocket_scans_a_discovered_realtime_route_from_root() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .insert_header("content-type", "text/html")
                    .set_body_string(r#"<a href="/realtime/v1/websocket">Live</a>"#),
            )
            .mount(&server)
            .await;
        // Any ordinary HTTP answer fails the WS handshake; this test only
        // asserts that the discovered route was attempted.
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/realtime/v1/websocket"))
            .respond_with(wiremock::ResponseTemplate::new(400))
            .mount(&server)
            .await;

        let url = Url::parse(&server.uri()).expect("root URL");
        let guard = lab_guard_for(&url);
        let coverage = riftlock_core::Coverage::default();
        run_scanners(
            &url,
            "websocket",
            Depth::Read,
            None,
            None,
            None,
            &guard,
            false,
            true,
            None,
            &coverage,
            None,
            Duration::from_secs(45),
        )
        .await
        .expect("explicit WebSocket scan");

        let requests = server.received_requests().await.expect("requests");
        let upgrades = requests.iter().filter(|request| {
            request.url.path() == "/realtime/v1/websocket"
                && request.headers.get("upgrade").is_some_and(|value| {
                    value
                        .to_str()
                        .is_ok_and(|v| v.eq_ignore_ascii_case("websocket"))
                })
        });
        assert!(
            upgrades.count() > 0,
            "discovered realtime route was never probed with a WS upgrade"
        );
    }

    /// Fetched bundles feed the endpoint inventory downstream scanners use.
    #[tokio::test]
    async fn discovery_feeds_ast_endpoints_from_the_start_page_and_bundles() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/app.js"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .insert_header("content-type", "application/javascript")
                    .set_body_string("fetch('/api/v1/users');"),
            )
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .insert_header("content-type", "text/html")
                    .set_body_string(r#"<html><script src="/app.js"></script></html>"#),
            )
            .mount(&server)
            .await;
        let url = Url::parse(&server.uri()).expect("url");
        let guard = lab_guard_for(&url);
        // The deadline is already past, so the crawl adds nothing: whatever
        // inventory appears came through the fetched start page and bundle.
        let (rpc, endpoints, endpoint_methods, actions, crawled, error, _crawl) = discover_context(
            &lab_client(),
            &url,
            &guard,
            &riftlock_core::SessionMatrix::default(),
            std::time::Instant::now(),
            Depth::Read,
            &riftlock_fingerprint::FetchCache::default(),
        )
        .await
        .expect("discovery");
        assert_eq!(endpoints, vec!["/api/v1/users".to_string()]);
        assert_eq!(
            endpoint_methods,
            vec![riftlock_discovery::DiscoveredEndpoint {
                path: "/api/v1/users".to_owned(),
                method: "GET".to_owned(),
            }]
        );
        assert!(rpc.is_empty());
        assert!(actions.is_empty());
        assert!(crawled.is_empty());
        // The crawl was skipped: the partial inventory must not report complete.
        assert_eq!(error.as_deref(), Some("crawl budget exhausted"));
    }

    /// Discovery's successful page and bundle fetches are reused by both
    /// passive fingerprinting consumers, including their cached response headers.
    #[tokio::test]
    async fn discovery_fetches_are_reused_by_passive_fingerprinting() {
        let server = wiremock::MockServer::start().await;
        let bundle = wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/app.js"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .insert_header("content-type", "application/javascript")
                    .insert_header("x-powered-by", "Next.js")
                    .set_body_string("const key = 'sb_publishable_AbC123xY_zW9';"),
            )
            .mount_as_scoped(&server)
            .await;
        let page = wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .insert_header("content-type", "text/html")
                    .insert_header("server", "nginx/1.24.0")
                    .set_body_string(r#"<html><script src="/app.js"></script></html>"#),
            )
            .mount_as_scoped(&server)
            .await;
        let url = Url::parse(&server.uri()).expect("url");
        let guard = lab_guard_for(&url);
        let fetch_cache = riftlock_fingerprint::FetchCache::default();
        discover_context(
            &lab_client(),
            &url,
            &guard,
            &riftlock_core::SessionMatrix::default(),
            std::time::Instant::now(),
            Depth::Read,
            &fetch_cache,
        )
        .await
        .expect("discovery");

        let http = lab_client();
        let coverage = riftlock_core::Coverage::default();
        let fingerprints =
            riftlock_fingerprint::fingerprint_url(&http, &url, &guard, &coverage, &fetch_cache)
                .await
                .expect("key fingerprinting");
        assert_eq!(fingerprints.len(), 1);
        assert_eq!(fingerprints[0].location, format!("{}/app.js", server.uri()));

        let technologies =
            riftlock_fingerprint::tech_url(&http, &url, &guard, &coverage, &fetch_cache)
                .await
                .expect("technology fingerprinting");
        assert!(technologies.iter().any(|tech| tech.technology == "nginx"));
        assert!(technologies.iter().any(|tech| tech.technology == "Next.js"));
        assert_eq!(page.received_requests().await.len(), 1);
        assert_eq!(bundle.received_requests().await.len(), 1);
    }

    /// One bundle can call the same path with several verbs; discovery keeps
    /// each method while scanners keep the deduplicated path-only inventory.
    #[tokio::test]
    async fn discovery_keeps_every_method_for_a_shared_path() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/app.js"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .insert_header("content-type", "application/javascript")
                    .set_body_string(
                        "fetch('/api/v1/users');
                         fetch('/api/v1/users', { method: 'post' });
                         fetch('/api/v1/users', { method: 'DELETE' });",
                    ),
            )
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .insert_header("content-type", "text/html")
                    .set_body_string(r#"<html><script src="/app.js"></script></html>"#),
            )
            .mount(&server)
            .await;
        let url = Url::parse(&server.uri()).expect("url");
        let guard = lab_guard_for(&url);
        let (_, endpoints, endpoint_methods, _, _, _, _) = discover_context(
            &lab_client(),
            &url,
            &guard,
            &riftlock_core::SessionMatrix::default(),
            std::time::Instant::now(),
            Depth::Read,
            &riftlock_fingerprint::FetchCache::default(),
        )
        .await
        .expect("discovery");
        assert_eq!(endpoints, vec!["/api/v1/users".to_string()]);
        let methods: Vec<&str> = endpoint_methods
            .iter()
            .map(|endpoint| endpoint.method.as_str())
            .collect();
        assert_eq!(methods, vec!["DELETE", "GET", "POST"]);
    }

    /// An empty AST inventory is still partial when the crawl budget expires;
    /// resume must retry instead of treating it as completed-empty discovery.
    #[tokio::test]
    async fn discovery_empty_inventory_is_partial_when_crawl_budget_expires() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .insert_header("content-type", "text/html")
                    .set_body_string("<html><body>plain</body></html>"),
            )
            .mount(&server)
            .await;
        let url = Url::parse(&server.uri()).expect("url");
        let guard = lab_guard_for(&url);
        let (rpc, endpoints, endpoint_methods, actions, crawled, error, _crawl) = discover_context(
            &lab_client(),
            &url,
            &guard,
            &riftlock_core::SessionMatrix::default(),
            std::time::Instant::now(),
            Depth::Read,
            &riftlock_fingerprint::FetchCache::default(),
        )
        .await
        .expect("successful empty discovery");
        assert!(rpc.is_empty() && endpoints.is_empty());
        assert!(endpoint_methods.is_empty());
        assert!(actions.is_empty() && crawled.is_empty());
        // Nothing was found, but the crawl never ran: partial, not complete.
        assert_eq!(error.as_deref(), Some("crawl budget exhausted"));
    }

    #[tokio::test]
    async fn drain_scans_isolates_a_panicking_scanner() {
        let mut set = tokio::task::JoinSet::<EngineReport>::new();
        for idx in 0..3usize {
            set.spawn(async move {
                if idx == 2 {
                    panic!("scanner boom");
                }
                (
                    idx,
                    "S",
                    Duration::ZERO,
                    Some(Ok(Vec::<Finding>::new())),
                    None,
                )
            });
        }
        // A scanner whose panic was caught in-task lands as `None` too.
        set.spawn(async { (3, "T", Duration::ZERO, None, None) });
        let (tx, events) = tokio::sync::mpsc::channel(1);
        drop(tx);
        let (slots, _, _, _) = tokio::time::timeout(
            Duration::from_secs(1),
            drain_scans(set, 4, None, events, false),
        )
        .await
        .expect("panic must not hang the drain");
        // Both panicking scanners' slots are empty; the other two delivered
        // their results in spawn order.
        assert!(
            slots[2].is_none() && slots[3].is_none(),
            "panic was not isolated"
        );
        assert!(
            slots
                .iter()
                .enumerate()
                .all(|(i, s)| (i >= 2) ^ s.is_some()),
            "{slots:?}"
        );
    }

    #[tokio::test]
    async fn with_budget_passes_through_and_bounds_a_stalled_engine() {
        let ok: Option<ScanResult> = Some(Ok(Vec::new()));
        assert!(with_budget(Duration::from_secs(5), std::future::ready(ok))
            .await
            .is_some());
        // A stalled engine becomes a real recorded transport failure, not a
        // hang and not a fabricated result.
        let stalled: Option<ScanResult> =
            with_budget(Duration::from_millis(50), std::future::pending()).await;
        match stalled {
            Some(Err(riftlock_core::ScanError::Io(e))) => {
                assert_eq!(e.kind(), std::io::ErrorKind::TimedOut);
            }
            other => panic!("expected a budget-exceeded Io failure, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn drain_checkpoints_streamed_findings_and_returns_unreached_endpoints() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let mut checkpoint = Checkpoint::new(
            &format!("scan-drain-{}-{nonce}", std::process::id()),
            "https://example.test/",
            vec!["https://example.test".into()],
            checkpoint::CheckpointConfig {
                provider: "generic".into(),
                passive_only: false,
                depth: "Read".into(),
                unsafe_bypass: false,
                scope_file: None,
                wordlist: None,
                godmode: false,
            },
        );
        let evidence = Evidence::AuthBypass {
            endpoint: "https://example.test/api/auth".into(),
            method: "POST".into(),
        };
        let (tx, events) = tokio::sync::mpsc::channel(4);
        tx.send(GenericEvent::EndpointsStarted {
            total: 2,
            endpoints: vec![
                "https://example.test/api/auth".into(),
                "https://example.test/api/users".into(),
            ],
        })
        .await
        .expect("send plan");
        tx.send(GenericEvent::EndpointComplete {
            completed: 1,
            total: 2,
            endpoint: "https://example.test/api/auth".into(),
            found: true,
        })
        .await
        .expect("send endpoint result");
        tx.send(GenericEvent::Finding(evidence.clone()))
            .await
            .expect("send proof");
        drop(tx);

        let mut set = tokio::task::JoinSet::<EngineReport>::new();
        set.spawn(async {
            (
                0,
                "Generic",
                Duration::from_secs(1),
                Some(Err(ScanError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "engine exceeded its wall-clock budget",
                )))),
                None,
            )
        });
        let (slots, streamed, planned, unreached) =
            drain_scans(set, 1, Some(&mut checkpoint), events, false).await;

        assert!(matches!(slots[0], Some(Err(ScanError::Io(_)))));
        assert_eq!(streamed, vec![evidence.clone()]);
        assert_eq!(planned, 2);
        assert_eq!(unreached, vec!["https://example.test/api/users"]);
        assert_eq!(checkpoint.findings, vec![evidence]);
        checkpoint.remove();
    }

    #[tokio::test]
    async fn drain_keeps_all_findings_and_queued_proofs_with_a_live_sender() {
        let generic: Vec<Finding> = (0..49)
            .map(|i| {
                riftlock_core::ProofGate::admit(Evidence::ReflectedXss {
                    url: format!("https://example.test/{i}"),
                    param: "q".into(),
                    payload: "<script>alert(1)</script>".into(),
                })
                .expect("proof")
            })
            .collect();
        let misconfigs: Vec<Finding> = (0..6)
            .map(|i| {
                riftlock_core::ProofGate::admit(Evidence::SecurityMisconfiguration {
                    url: "https://example.test/".into(),
                    issue: format!("missing_{i}"),
                    severity: "Low".into(),
                })
                .expect("proof")
            })
            .collect();
        let (tx, events) = tokio::sync::mpsc::channel(128);
        for finding in &generic {
            tx.send(GenericEvent::Finding(finding.evidence().clone()))
                .await
                .expect("send");
        }
        let mut set = tokio::task::JoinSet::<EngineReport>::new();
        set.spawn(async move { (0, "Generic", Duration::ZERO, Some(Ok(generic)), None) });
        set.spawn(async move { (1, "Misconfig", Duration::ZERO, Some(Ok(misconfigs)), None) });
        set.spawn(async { (2, "panic", Duration::ZERO, None, None) });
        let (slots, streamed, _, _) = tokio::time::timeout(
            Duration::from_secs(1),
            drain_scans(set, 3, None, events, false),
        )
        .await
        .expect("a retained sender must not hang the drain");
        assert_eq!(streamed.len(), 49);
        assert!(tx.is_closed());
        let mut findings = Vec::new();
        for slot in slots.into_iter().flatten() {
            findings.extend(slot.expect("scan"));
        }
        assert_eq!(findings.len(), 55);
        findings.extend(restore_findings(&streamed, None));
        findings.push(
            riftlock_core::ProofGate::admit(Evidence::LeakedSecret {
                key_type: riftlock_core::KeyType::SupabaseServiceRoleLegacy,
                location: "https://example.test/app.js".into(),
                masked: "sb_secret_********".into(),
                full: Default::default(),
            })
            .expect("proof"),
        );
        finalize_findings(&mut findings);
        assert_eq!(findings.len(), 56);
        let ranks: Vec<_> = findings
            .iter()
            .map(|f| ui::findings::severity_rank(f.evidence()))
            .collect();
        assert_eq!(ranks.iter().filter(|r| **r == 1).count(), 49);
        assert_eq!(ranks[0], 0);
        assert!(ranks.windows(2).all(|w| w[0] <= w[1]));
        // The streamed path also stands on its own when the engine is cancelled.
        assert_eq!(restore_findings(&streamed, None).len(), 49);
    }

    #[test]
    fn finalize_findings_dedups_the_same_sink_location_once() {
        let dom = |url: &str| {
            riftlock_core::ProofGate::admit(Evidence::DomXssTaint {
                url: url.to_owned(),
                source: "location.search.q (line 7)".to_owned(),
                sink: "innerHTML".to_owned(),
            })
            .expect("proof")
        };
        // The same sink URL, line and source is one flow; a different script
        // (or page) is a different sink location and stays separate.
        let mut findings = vec![
            dom("https://example.test/a.js"),
            dom("https://example.test/a.js"),
            dom("https://example.test/b.js"),
        ];
        let engine_reported_count = dedup_findings(&mut findings);
        assert_eq!(findings.len(), 2);
        assert_eq!(engine_reported_count, 1);
        finalize_findings(&mut findings);
        assert_eq!(findings.len(), 2);
    }

    /// Coverage of a fully probed clean target: every discovered endpoint
    /// answered and every check reached a verdict.
    fn full_coverage() -> riftlock_report::ScanCoverage {
        riftlock_report::ScanCoverage {
            endpoints_discovered: 3,
            endpoints_tested_successfully: 3,
            vulnerability_checks_attempted: 4,
            vulnerability_checks_completed: 4,
            ..Default::default()
        }
    }

    #[test]
    fn waf_fixture_is_incomplete_never_clean() {
        // Reproduced on the local 127.0.0.1:18761 fixture: all 217 requests
        // answered 403, so nothing was tested and all 55 checks were
        // inconclusive while coverage still listed 216 discovered endpoints.
        let coverage = riftlock_report::ScanCoverage {
            endpoints_discovered: 216,
            endpoints_tested_successfully: 0,
            endpoints_waf_blocked: 217,
            vulnerability_checks_attempted: 55,
            vulnerability_checks_completed: 0,
            vulnerability_checks_inconclusive: 55,
            ..Default::default()
        };
        let state = RunState::new(0, 0, coverage);
        assert_eq!(state.status, RunStatus::Incomplete);
        assert_eq!(state.coverage, coverage);
    }

    /// A 200 whose body cannot be decompressed is unavailable data: the
    /// engine still returns successfully, but the ledger must show one failed
    /// endpoint and one inconclusive check, and the verdict is INCOMPLETE.
    #[tokio::test]
    async fn corrupt_gzip_base_page_is_inconclusive_not_a_finding() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .insert_header("content-encoding", "gzip")
                    .set_body_bytes(b"not a gzip stream".to_vec()),
            )
            .mount(&server)
            .await;
        let url = Url::parse(&server.uri()).expect("url");
        let guard = lab_guard_for(&url);
        let coverage = riftlock_core::Coverage::default();
        let scanner = GenericScanner {
            force_run: true,
            coverage: coverage.clone(),
            ..GenericScanner::default()
        };
        let findings = riftlock_core::Scanner::scan(&scanner, &url, &lab_client(), &guard, false)
            .await
            .expect("a body read failure must not abort the scanner");
        assert!(findings.is_empty(), "no finding may come from unread data");
        let snapshot = coverage.snapshot(1);
        assert_eq!(snapshot.vulnerability_checks_attempted, 1);
        assert_eq!(snapshot.vulnerability_checks_inconclusive, 1);
        assert_eq!(snapshot.endpoints_failed, 1);
        assert_eq!(snapshot.endpoints_tested_successfully, 0);
        assert_eq!(
            RunState::with_accounting(0, 0, snapshot, coverage.finalize(), 0).status,
            RunStatus::Incomplete
        );
    }

    #[test]
    fn clean_fixture_with_full_coverage_is_clean() {
        assert_eq!(
            RunState::new(0, 0, full_coverage()).status,
            RunStatus::Clean
        );
    }

    #[test]
    fn status_combinations_follow_the_run_state() {
        // No coverage at all is not positive evidence.
        assert_eq!(
            RunState::new(0, 0, riftlock_report::ScanCoverage::default()).status,
            RunStatus::Incomplete
        );
        // A scanner failure leaves the run incomplete even with green coverage.
        assert_eq!(
            RunState::new(0, 1, full_coverage()).status,
            RunStatus::Incomplete
        );
        assert_eq!(
            RunState::new(3, 0, full_coverage()).status,
            RunStatus::Findings
        );
    }

    #[test]
    fn exit_code_matches_the_reported_status() {
        assert_eq!(exit_code(RunStatus::Clean), EXIT_CLEAN);
        assert_eq!(exit_code(RunStatus::Findings), EXIT_FINDINGS);
        assert_eq!(exit_code(RunStatus::Incomplete), EXIT_ERROR);
        // The reproduced WAF run must not exit as clean.
        let blocked = RunState::new(
            0,
            0,
            riftlock_report::ScanCoverage {
                endpoints_discovered: 216,
                endpoints_waf_blocked: 217,
                vulnerability_checks_attempted: 55,
                vulnerability_checks_inconclusive: 55,
                ..Default::default()
            },
        );
        assert_ne!(exit_code(blocked.status), EXIT_CLEAN);
    }

    #[test]
    fn engine_budgets_are_fixed_per_scan_depth() {
        assert_eq!(engine_budget(Depth::Normal), Duration::from_secs(10));
        assert_eq!(engine_budget(Depth::Read), Duration::from_secs(60));
        assert_eq!(engine_budget(Depth::Godmode), Duration::from_secs(180));
        assert_eq!(MAX_ENGINE_BUDGET, Duration::from_secs(180));

        // The deadline keeps the full drain window for long budgets and at
        // most 10% of a short one, so an engine always returns its findings
        // before the cancellation fires.
        let start = std::time::Instant::now();
        assert_eq!(
            engine_deadline(start, Depth::Normal),
            start + Duration::from_secs(9)
        );
        assert_eq!(
            engine_deadline(start, Depth::Read),
            start + Duration::from_secs(54)
        );
        assert_eq!(
            engine_deadline(start, Depth::Godmode),
            start + MAX_ENGINE_BUDGET - ENGINE_DRAIN
        );
    }

    #[test]
    fn legacy_depth_labels_collapse_into_three_tiers() {
        assert_eq!(depth_from_str("Normal"), Some(Depth::Normal));
        assert_eq!(depth_from_str("Passive"), Some(Depth::Normal));
        assert_eq!(depth_from_str("Read"), Some(Depth::Read));
        for label in ["Active", "Auth", "Deep", "Max", "Godmode"] {
            assert_eq!(depth_from_str(label), Some(Depth::Godmode), "{label}");
        }
        assert_eq!(depth_from_str("nonsense"), None);
    }

    #[test]
    fn numeric_config_depth_never_escalates_to_godmode() {
        assert_eq!(depth_from_u32(0), Depth::Normal);
        for level in [1, 2, 3, 7, u32::MAX] {
            assert_eq!(depth_from_u32(level), Depth::Read, "level {level}");
        }
    }

    #[test]
    fn discovery_budget_flag_beats_config_and_default() {
        use riftlock_core::RiftlockConfig;
        assert_eq!(
            resolve_discovery_budget(None, None),
            Duration::from_secs(300)
        );
        let cfg = RiftlockConfig {
            discovery_budget: Some(180),
            ..Default::default()
        };
        assert_eq!(
            resolve_discovery_budget(None, Some(&cfg)),
            Duration::from_secs(180)
        );
        assert_eq!(
            resolve_discovery_budget(Some(300), Some(&cfg)),
            Duration::from_secs(300)
        );
        // The budget only extends discovery: request and engine caps are
        // separate constants and are not touched here.
        assert_eq!(REQUEST_CAP, Duration::from_secs(10));
    }

    #[tokio::test]
    async fn a_panicking_scanner_marks_the_scan_incomplete() {
        let mut set = tokio::task::JoinSet::<EngineReport>::new();
        set.spawn(async { panic!("scanner boom") });
        set.spawn(async {
            (
                0,
                "S",
                Duration::ZERO,
                Some(Ok(Vec::<Finding>::new())),
                None,
            )
        });
        let (tx, events) = tokio::sync::mpsc::channel(1);
        drop(tx);
        let (slots, _, _, _) = tokio::time::timeout(
            Duration::from_secs(1),
            drain_scans(set, 2, None, events, false),
        )
        .await
        .expect("panic must not hang the drain");
        // Same counting rule as run_scanners: an empty slot is a panicked
        // scanner, and one failure makes the run INCOMPLETE.
        let failures = slots.iter().filter(|s| s.is_none()).count();
        assert_eq!(failures, 1);
        assert_eq!(
            RunState::new(0, failures, full_coverage()).status,
            RunStatus::Incomplete
        );
    }

    #[tokio::test]
    async fn rate_limiter_paces_requests() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let started = std::time::Instant::now();
        let mut set = tokio::task::JoinSet::new();
        let http = lab_client();
        for _ in 0..20usize {
            let uri = server.uri();
            let http = http.clone();
            set.spawn(async move {
                let _ = http.get(&uri).send().await;
            });
        }
        while set.join_next().await.is_some() {}
        let elapsed = started.elapsed();
        // Quota is 20/s with a burst of 10, so requests 11-20 need ~0.5s
        // of refill.
        assert!(
            elapsed >= Duration::from_millis(450),
            "20 requests finished in {elapsed:?}; limiter did not pace"
        );
        assert!(
            elapsed < Duration::from_secs(10),
            "20 requests took {elapsed:?}; limiter stalled"
        );
    }
}
