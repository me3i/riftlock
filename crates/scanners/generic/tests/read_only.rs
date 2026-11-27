use riftlock_core::ScopedClient as Client;
use riftlock_core::{ScanPolicy, Scanner, ScopeGuard};
use riftlock_scanner_generic::GenericScanner;
use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A read-only guard still GETs the page and honours OPTIONS, but neither the
/// POST login form nor the OPTIONS→POST pass may put a write on the wire.
#[tokio::test]
async fn read_only_scan_never_sends_a_write_method() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/html")
                .set_body_string(
                    r#"<html><body><form method="POST" action="/login">
                    <input type="text" name="email"><input type="password" name="password">
                    <input type="submit"></form></body></html>"#,
                ),
        )
        .mount(&server)
        .await;
    // The OPTIONS pass observes an advertised POST but must not exercise it.
    Mock::given(method("OPTIONS"))
        .and(path("/api"))
        .respond_with(ResponseTemplate::new(204).insert_header("allow", "GET, POST"))
        .mount(&server)
        .await;
    // Any write that escapes the policy lands here and fails the assertion.
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let url = Url::parse(&server.uri()).expect("url");
    let guard = ScopeGuard::new_lab(&[server.uri().as_str()])
        .expect("guard")
        .with_policy(ScanPolicy::ReadOnly);
    let scanner = GenericScanner {
        force_run: true,
        endpoints: vec![format!("{}/api", server.uri())],
        ..Default::default()
    };
    scanner
        .scan(&url, &Client::new_lab(), &guard, false)
        .await
        .expect("scan");

    let requests = server.received_requests().await.expect("requests");
    let methods: Vec<&str> = requests.iter().map(|r| r.method.as_str()).collect();
    assert!(
        requests
            .iter()
            .all(|r| matches!(r.method.as_str(), "GET" | "HEAD" | "OPTIONS")),
        "read scan wrote: {methods:?}"
    );
}
