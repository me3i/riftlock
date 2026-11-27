//! Size-capped response body reading: an unbounded `.text()` on a hostile
//! target (e.g. a multi-gigabyte "JS bundle") is an out-of-memory crash.

/// Upper bound on how many response bytes are read into memory.
pub const MAX_BODY_BYTES: usize = 5 * 1024 * 1024;

/// Why a response body could not be read within the configured limit.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BodyReadError {
    /// The body exceeded [`MAX_BODY_BYTES`].
    #[error("response body exceeded the {MAX_BODY_BYTES}-byte cap")]
    TooLarge,
    /// The response stream failed while reading its body.
    #[error("response body read failed: {0}")]
    Transport(#[source] reqwest::Error),
}

/// Read `resp`'s body as UTF-8, capped at [`MAX_BODY_BYTES`].
///
/// # Errors
/// Returns [`BodyReadError::TooLarge`] when the response exceeds the cap or
/// [`BodyReadError::Transport`] when reading its stream fails.
pub async fn text_limited_result(mut resp: reqwest::Response) -> Result<String, BodyReadError> {
    if resp
        .content_length()
        .is_some_and(|len| len > MAX_BODY_BYTES as u64)
    {
        return Err(BodyReadError::TooLarge);
    }
    let mut buf: Vec<u8> = Vec::new();
    loop {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                if buf.len() + chunk.len() > MAX_BODY_BYTES {
                    return Err(BodyReadError::TooLarge);
                }
                buf.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(error) => return Err(BodyReadError::Transport(error)),
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Read a size-capped response body, logging a specific reason on failure.
pub async fn text_limited(resp: reqwest::Response) -> String {
    match text_limited_result(resp).await {
        Ok(text) => text,
        Err(error) => {
            crate::logger::line(&format!("warning: {error}; body skipped"));
            String::new()
        }
    }
}

/// Body markers of a WAF interstitial (challenge page, block page) — a page
/// carrying one of these is the middlebox answering, not the application.
const WAF_MARKERS: [&str; 3] = ["cloudflare", "captcha", "checking your browser"];

/// Whether a response body looks like a WAF challenge/block page rather
/// than application content. Case-insensitive, substring-based on purpose:
/// interstitials vary, and a false positive only costs a warning.
pub fn looks_like_waf(body: &str) -> bool {
    let lower = body.to_lowercase();
    WAF_MARKERS.iter().any(|m| lower.contains(m))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn supported_content_encoding_is_decoded_before_the_cap() {
        // reqwest is built with gzip/brotli/deflate features; a valid gzip
        // body arrives as decoded text, so no response is skipped.
        let gzip = hex_bytes("1f8b08000000000002ffcb48cdc9c95728cf2fca49010085114a0d0b000000");
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-encoding", "gzip")
                    .set_body_bytes(gzip),
            )
            .mount(&server)
            .await;
        let resp = reqwest::Client::new()
            .get(server.uri())
            .send()
            .await
            .expect("response");
        assert_eq!(
            text_limited_result(resp).await.expect("body"),
            "hello world"
        );
    }

    #[tokio::test]
    async fn malformed_content_encoding_is_a_read_failure_not_a_silent_skip() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-encoding", "gzip")
                    .set_body_bytes(b"not a gzip stream".to_vec()),
            )
            .mount(&server)
            .await;
        let client = reqwest::Client::new();
        let resp = client.get(server.uri()).send().await.expect("response");
        assert!(
            matches!(
                text_limited_result(resp).await,
                Err(BodyReadError::Transport(_))
            ),
            "a broken decompressor must surface as a transport error"
        );
        let resp = client.get(server.uri()).send().await.expect("response");
        assert_eq!(text_limited(resp).await, "", "wrapper skips with a warning");
    }

    fn hex_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    #[test]
    fn waf_markers_match_case_insensitively_and_miss_on_plain_html() {
        assert!(looks_like_waf(
            "<html>Checking Your Browser Before Accessing</html>"
        ));
        assert!(looks_like_waf("Attention Required! | Cloudflare"));
        assert!(looks_like_waf("Please complete the CAPTCHA"));
        assert!(!looks_like_waf("<html><body><h1>Shop</h1></body></html>"));
    }

    #[tokio::test]
    async fn small_body_passes_through() {
        let resp = reqwest::Response::from(
            http::Response::builder()
                .body(reqwest::Body::from("hello"))
                .expect("body"),
        );
        assert_eq!(text_limited(resp).await, "hello");
    }

    #[tokio::test]
    async fn content_length_over_cap_aborts_without_reading() {
        // content_length() derives from the body's size hint (on the wire,
        // from the Content-Length header): a body known to be over the cap
        // must abort before a single byte is buffered.
        let resp = reqwest::Response::from(
            http::Response::builder()
                .body(reqwest::Body::from(vec![0u8; MAX_BODY_BYTES + 1]))
                .expect("body"),
        );
        assert_eq!(text_limited(resp).await, "");
    }

    #[tokio::test]
    async fn streamed_body_over_cap_aborts_mid_stream() {
        // Three 2 MiB chunks, no Content-Length: the cap must trip while
        // streaming, before the 6 MiB are buffered.
        let chunk = vec![b'a'; 2 * 1024 * 1024];
        let stream = futures_util::stream::iter(vec![
            Ok::<Vec<u8>, std::io::Error>(chunk.clone()),
            Ok(chunk.clone()),
            Ok(chunk),
        ]);
        let resp = reqwest::Response::from(
            http::Response::builder()
                .body(reqwest::Body::wrap_stream(stream))
                .expect("body"),
        );
        assert_eq!(text_limited(resp).await, "");
    }

    #[tokio::test]
    async fn oversized_body_reports_too_large_for_both_length_and_stream() {
        let declared = reqwest::Response::from(
            http::Response::builder()
                .body(reqwest::Body::from(vec![0u8; MAX_BODY_BYTES + 1]))
                .expect("body"),
        );
        assert!(matches!(
            text_limited_result(declared).await,
            Err(BodyReadError::TooLarge)
        ));
        let chunk = vec![b'a'; 2 * 1024 * 1024];
        let stream = futures_util::stream::iter(vec![
            Ok::<Vec<u8>, std::io::Error>(chunk.clone()),
            Ok(chunk.clone()),
            Ok(chunk),
        ]);
        let streamed = reqwest::Response::from(
            http::Response::builder()
                .body(reqwest::Body::wrap_stream(stream))
                .expect("body"),
        );
        assert!(matches!(
            text_limited_result(streamed).await,
            Err(BodyReadError::TooLarge)
        ));
    }

    #[tokio::test]
    async fn stream_failure_reports_transport_not_oversize() {
        let stream = futures_util::stream::iter(vec![
            Ok::<Vec<u8>, std::io::Error>(b"partial".to_vec()),
            Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "connection reset mid-body",
            )),
        ]);
        let resp = reqwest::Response::from(
            http::Response::builder()
                .body(reqwest::Body::wrap_stream(stream))
                .expect("body"),
        );
        assert!(matches!(
            text_limited_result(resp).await,
            Err(BodyReadError::Transport(_))
        ));
    }

    #[tokio::test]
    async fn streamed_body_under_cap_fully_read() {
        let stream = futures_util::stream::iter(vec![
            Ok::<Vec<u8>, std::io::Error>(b"foo".to_vec()),
            Ok(b"bar".to_vec()),
        ]);
        let resp = reqwest::Response::from(
            http::Response::builder()
                .body(reqwest::Body::wrap_stream(stream))
                .expect("body"),
        );
        assert_eq!(text_limited(resp).await, "foobar");
    }
}
