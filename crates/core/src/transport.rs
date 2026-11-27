//! Actionable categories for transport failures.
//!
//! `reqwest::Error` renders a timeout, a dead origin and a bad certificate
//! almost identically ("error sending request"), which hides the real cause.
//! These categories are derived from the error's structured flags and source
//! chain; the original error text is always kept alongside them.

/// Why an outbound request could not complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TransportError {
    Dns,
    Connect,
    Tls,
    Timeout,
    ConnectionReset,
    /// The peer actively refused a connection: the host is not listening.
    ConnectionRefused,
    BodyRead,
    Redirect,
    Other,
}

impl TransportError {
    /// Stable machine-readable category name.
    #[must_use]
    pub fn category(self) -> &'static str {
        match self {
            Self::Dns => "dns",
            Self::Connect => "connect",
            Self::Tls => "tls",
            Self::Timeout => "timeout",
            Self::ConnectionReset => "connection_reset",
            Self::ConnectionRefused => "connection_refused",
            Self::BodyRead => "body_read",
            Self::Redirect => "redirect",
            Self::Other => "other",
        }
    }

    /// Whether this failure makes further requests to the same host pointless.
    /// Body-read and redirect failures can be path-specific, so they do not
    /// block other engines.
    #[must_use]
    pub fn blocks_host(self) -> bool {
        matches!(
            self,
            Self::Dns
                | Self::Connect
                | Self::Tls
                | Self::Timeout
                | Self::ConnectionReset
                | Self::ConnectionRefused
        )
    }

    /// Whether this failure contributes to the process-wide per-host breaker.
    #[must_use]
    pub fn is_dead_host(self) -> bool {
        matches!(self, Self::ConnectionRefused | Self::Timeout)
    }

    /// Classify the concatenated source chain of a transport error.
    fn from_source_text(text: &str) -> Self {
        let lower = text.to_ascii_lowercase();
        if lower.contains("name or service not known")
            || lower.contains("temporary failure in name resolution")
            || lower.contains("failed to lookup address")
            || lower.contains("dns error")
            || lower.contains("nodename nor servname")
        {
            Self::Dns
        } else if lower.contains("certificate")
            || lower.contains("tls")
            || lower.contains("rustls")
            || lower.contains("handshake")
        {
            Self::Tls
        } else if lower.contains("connection refused")
            || lower.contains("actively refused")
            || lower.contains("errno 111")
        {
            Self::ConnectionRefused
        } else if lower.contains("connection reset")
            || lower.contains("connection closed")
            || lower.contains("broken pipe")
            || lower.contains("host unreachable")
            || lower.contains("network unreachable")
        {
            Self::ConnectionReset
        } else {
            Self::Other
        }
    }

    /// Classify a reqwest error. The timeout check comes first: a connect or
    /// read timeout is a timeout regardless of which stage was waiting.
    #[must_use]
    pub fn from_reqwest(err: &reqwest::Error) -> Self {
        if err.is_timeout() {
            return Self::Timeout;
        }
        let mut text = String::new();
        let mut source = std::error::Error::source(err);
        while let Some(cause) = source {
            text.push_str(&cause.to_string());
            text.push(' ');
            source = cause.source();
        }
        let from_chain = Self::from_source_text(&text);
        if from_chain != Self::Other {
            return from_chain;
        }
        if err.is_connect() {
            return Self::Connect;
        }
        if err.is_body() {
            return Self::BodyRead;
        }
        if err.is_redirect() {
            return Self::Redirect;
        }
        Self::Other
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_chain_classifies_dns_tls_and_reset() {
        assert_eq!(
            TransportError::from_source_text("dns error: failed to lookup address information"),
            TransportError::Dns
        );
        assert_eq!(
            TransportError::from_source_text("invalid peer certificate: unknown issuer"),
            TransportError::Tls
        );
        assert_eq!(
            TransportError::from_source_text("tcp connect error: Connection refused"),
            TransportError::ConnectionRefused
        );
        assert_eq!(
            TransportError::from_source_text("connection reset by peer"),
            TransportError::ConnectionReset
        );
        assert_eq!(
            TransportError::from_source_text("odd failure"),
            TransportError::Other
        );
    }

    #[test]
    fn only_host_blocking_categories_block_other_engines() {
        for cat in [
            TransportError::Dns,
            TransportError::Connect,
            TransportError::Tls,
            TransportError::Timeout,
            TransportError::ConnectionReset,
            TransportError::ConnectionRefused,
        ] {
            assert!(cat.blocks_host(), "{}", cat.category());
        }
        for cat in [
            TransportError::BodyRead,
            TransportError::Redirect,
            TransportError::Other,
        ] {
            assert!(!cat.blocks_host(), "{}", cat.category());
        }
    }

    #[tokio::test]
    async fn live_transport_errors_are_classified() {
        // A resolver that always fails: deterministic DNS failure with no
        // external service or system resolver involved.
        struct FailingDns;
        impl reqwest::dns::Resolve for FailingDns {
            fn resolve(&self, _name: reqwest::dns::Name) -> reqwest::dns::Resolving {
                Box::pin(std::future::ready(Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "failed to lookup address information: Name or service not known",
                )
                .into())))
            }
        }
        let dns_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(3))
            .dns_resolver(std::sync::Arc::new(FailingDns))
            .build()
            .expect("client");
        let dns = dns_client
            .get("http://riftlock-dns-probe.invalid/")
            .send()
            .await
            .expect_err("unresolvable host must fail");
        assert_eq!(TransportError::from_reqwest(&dns), TransportError::Dns);

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(3))
            .build()
            .expect("client");

        // A closed local port: deterministic connection failure.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);
        let conn = client
            .get(format!("http://127.0.0.1:{port}/"))
            .send()
            .await
            .expect_err("closed port must fail");
        assert!(matches!(
            TransportError::from_reqwest(&conn),
            TransportError::Connect
                | TransportError::ConnectionReset
                | TransportError::ConnectionRefused
        ));

        // A delayed local response past a short cap: deterministic timeout.
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::path("/slow"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_delay(std::time::Duration::from_millis(600)),
            )
            .mount(&server)
            .await;
        let fast = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(100))
            .build()
            .expect("client");
        let timed_out = fast
            .get(format!("{}/slow", server.uri()))
            .send()
            .await
            .expect_err("slow response must time out");
        assert_eq!(
            TransportError::from_reqwest(&timed_out),
            TransportError::Timeout
        );
    }
}
