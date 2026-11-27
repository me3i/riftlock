//! Canonicalization of URLs extracted from target content.
//!
//! Extracted attribute values can carry HTML entities and surrounding quotes.
//! Joining such a value directly makes `url` percent-encode the quote into a
//! target-relative path (`/%22https://external/...`), which is both malformed
//! and able to sneak an external URL into the in-scope queue. This module
//! decodes and validates before resolution.

use url::Url;

/// Why an extracted value is not a usable discovered URL.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum UrlError {
    /// The value is empty, malformed, or has no usable host.
    #[error("malformed discovered url")]
    Malformed,
    /// The scheme is not HTTP(S) and cannot be an active scan target.
    #[error("unsupported url scheme")]
    UnsupportedScheme,
}

/// Decode the HTML entities that occur in href/src/action values. Unknown
/// entities are left untouched; a malformed reference is never expanded into
/// a different URL.
fn decode_entities(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(pos) = rest.find('&') {
        out.push_str(&rest[..pos]);
        rest = &rest[pos..];
        let Some(end) = rest.find(';') else {
            out.push_str(rest);
            return out;
        };
        let entity = &rest[1..end];
        let decoded = match entity {
            "amp" => Some('&'),
            "quot" => Some('"'),
            "apos" | "#39" | "#x27" => Some('\''),
            "lt" => Some('<'),
            "gt" => Some('>'),
            _ if entity.starts_with("#x") || entity.starts_with("#X") => {
                u32::from_str_radix(&entity[2..], 16)
                    .ok()
                    .and_then(char::from_u32)
            }
            _ if entity.starts_with('#') => {
                entity[1..].parse::<u32>().ok().and_then(char::from_u32)
            }
            _ => None,
        };
        match decoded {
            Some(ch) => out.push(ch),
            None => out.push_str(&rest[..=end]),
        }
        rest = &rest[end + 1..];
    }
    out.push_str(rest);
    out
}

/// Strip a matching pair of surrounding quote characters, including the
/// percent-encoded form produced by a previously double-quoted value.
fn unquote(value: &str) -> &str {
    let value = value.trim();
    for (open, close) in [('"', '"'), ('\'', '\''), ('`', '`')] {
        if value.len() >= 2 && value.starts_with(open) && value.ends_with(close) {
            return value[open.len_utf8()..value.len() - close.len_utf8()].trim();
        }
    }
    // `%22` at both ends: a quote that was already percent-encoded upstream.
    if value.len() >= 6 && value.starts_with("%22") && value.ends_with("%22") {
        return &value[3..value.len() - 3];
    }
    value
}

/// Canonicalize one extracted value against the source document URL.
///
/// An absolute `scheme:` value is parsed on its own terms — it is never
/// reinterpreted as a relative path. Scope validation is deliberately left to
/// the caller, which owns the `ScopeGuard`.
///
/// # Errors
/// [`UrlError::Malformed`] when nothing usable can be parsed, or
/// [`UrlError::UnsupportedScheme`] for a non-HTTP(S) scheme.
pub fn canonical_url(base: &Url, raw: &str) -> Result<Url, UrlError> {
    let decoded = decode_entities(raw);
    let unquoted = unquote(&decoded);
    // A value double-quoted by an upstream parser can arrive as
    // `/%22https://external/%22`. Decode those quotes, then strip the
    // surrounding pair so the absolute URL is parsed on its own terms.
    let owned = if unquoted.contains("%22") {
        let replaced = unquoted.replace("%22", "\"");
        let trimmed = replaced.trim_start_matches('/').trim();
        if trimmed.len() >= 2 && trimmed.starts_with('"') && trimmed.ends_with('"') {
            trimmed[1..trimmed.len() - 1].to_owned()
        } else {
            replaced
        }
    } else {
        unquoted.to_owned()
    };
    let value = owned.trim();
    if value.is_empty() {
        return Err(UrlError::Malformed);
    }
    // A scheme-looking value must parse as absolute or be rejected; never
    // fall back to base.join and turn an external URL into a local path.
    let mut url = if value.starts_with("//") {
        base.join(value).map_err(|_| UrlError::Malformed)?
    } else if value.contains("://") {
        Url::parse(value).map_err(|_| UrlError::Malformed)?
    } else {
        base.join(value).map_err(|_| UrlError::Malformed)?
    };
    if url.scheme() != "http" && url.scheme() != "https" {
        return Err(UrlError::UnsupportedScheme);
    }
    if url.host_str().is_none_or(str::is_empty) {
        return Err(UrlError::Malformed);
    }
    // Canonical identity: drop the fragment and the default port so two
    // spellings of one resource deduplicate.
    url.set_fragment(None);
    // Only an explicit scheme-default port is redundant; an ephemeral test
    // port must survive canonicalization.
    let default_port = if url.scheme() == "http" { 80 } else { 443 };
    if url.port() == Some(default_port) {
        url.set_port(None).map_err(|_| UrlError::Malformed)?;
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Url {
        Url::parse("https://target.example/app?x=1#frag").unwrap()
    }

    #[test]
    fn quoted_absolute_url_stays_absolute() {
        let url = canonical_url(&base(), "\"https://external.test/a\"").unwrap();
        assert_eq!(url.as_str(), "https://external.test/a");
        assert!(!url.path().contains("%22"));
    }

    #[test]
    fn html_encoded_and_numeric_entities_are_decoded() {
        let url = canonical_url(&base(), "/p?a=1&amp;b=2&#39;x&#x22;").unwrap();
        assert_eq!(url.path(), "/p");
        assert_eq!(url.query(), Some("a=1&b=2%27x%22"));
    }

    #[test]
    fn relative_and_protocol_relative_urls_resolve_against_base() {
        assert_eq!(
            canonical_url(&base(), "/next").unwrap().as_str(),
            "https://target.example/next"
        );
        assert_eq!(
            canonical_url(&base(), "//other.test/x").unwrap().as_str(),
            "https://other.test/x"
        );
    }

    #[test]
    fn fragments_are_removed_and_query_preserved() {
        let url = canonical_url(&base(), "/p?q=1#section").unwrap();
        assert_eq!(url.as_str(), "https://target.example/p?q=1");
        assert_eq!(url.fragment(), None);
    }

    #[test]
    fn default_ports_and_host_case_collide_after_canonicalization() {
        let a = canonical_url(&base(), "https://TARGET.example:443/x").unwrap();
        let b = canonical_url(&base(), "https://target.example/x").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn encoded_quotes_are_stripped_not_turned_into_a_path() {
        let url = canonical_url(&base(), "%22https://github.com/Neo23x0/sigma/%22").unwrap();
        assert_eq!(url.host_str(), Some("github.com"));
        assert!(!url.path().contains("%22"));
    }

    #[test]
    fn malformed_and_unsupported_values_are_rejected() {
        assert_eq!(canonical_url(&base(), ""), Err(UrlError::Malformed));
        assert_eq!(
            canonical_url(&base(), "javascript:alert(1)"),
            Err(UrlError::UnsupportedScheme)
        );
        assert_eq!(
            canonical_url(&base(), "mailto:a@b.test"),
            Err(UrlError::UnsupportedScheme)
        );
        assert!(canonical_url(&base(), "https://").is_err());
    }
}
