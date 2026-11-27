//! Response router: triage of probe responses into known/uncertain classes,
//! deciding whether verification is needed.

/// Triage of an HTTP probe response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Classification {
    /// The response is unambiguous — no verification needed.
    Known,
    /// The response is ambiguous (WAF interstitial, partial content,
    /// multi-choice) — route to a [`crate::verifier::Verifier`].
    Uncertain,
}

/// Classify a probe response by status and body.
///
/// Known: `200` with valid JSON, `401`/`403` (denied), `404` (not found).
/// Uncertain: `200` with HTML or empty body (possible WAF page),
/// `206` partial content, `300` multiple choices.
pub fn classify_response(status: u16, body: &str) -> Classification {
    match status {
        200 => {
            let trimmed = body.trim_start();
            if trimmed.is_empty() || trimmed.starts_with('<') {
                Classification::Uncertain
            } else if serde_json::from_str::<serde_json::Value>(trimmed).is_ok() {
                Classification::Known
            } else {
                Classification::Uncertain
            }
        }
        401 | 403 | 404 => Classification::Known,
        206 | 300 => Classification::Uncertain,
        _ => Classification::Known,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_responses() {
        assert_eq!(
            classify_response(200, r#"{"rows":[]}"#),
            Classification::Known
        );
        assert_eq!(classify_response(200, "[]"), Classification::Known);
        assert_eq!(classify_response(401, ""), Classification::Known);
        assert_eq!(classify_response(403, "forbidden"), Classification::Known);
        assert_eq!(classify_response(404, ""), Classification::Known);
    }

    #[test]
    fn uncertain_responses() {
        assert_eq!(
            classify_response(200, "<html><body>blocked</body></html>"),
            Classification::Uncertain
        );
        assert_eq!(classify_response(200, "  \n"), Classification::Uncertain);
        assert_eq!(
            classify_response(200, "not json at all"),
            Classification::Uncertain
        );
        assert_eq!(classify_response(206, "partial"), Classification::Uncertain);
        assert_eq!(
            classify_response(300, "multiple"),
            Classification::Uncertain
        );
    }
}
