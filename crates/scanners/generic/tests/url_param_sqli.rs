use riftlock_core::ScopedClient as Client;
use riftlock_core::{Evidence, Scanner, ScopeGuard};
use riftlock_scanner_generic::GenericScanner;
use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

#[tokio::test]
async fn product_id_quote_is_resent_and_sql_error_is_proved() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/product"))
        .respond_with(|request: &Request| {
            let injected = request
                .url
                .query_pairs()
                .any(|(key, value)| key == "productId" && value == "1'");
            let body = if injected {
                "SQLite: unrecognized token: \"'\""
            } else {
                "product details"
            };
            ResponseTemplate::new(200).set_body_raw(body, "text/html")
        })
        .mount(&server)
        .await;

    let url = Url::parse(&format!("{}/product?productId=1", server.uri())).expect("url");
    let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("guard");
    let scanner = GenericScanner {
        force_run: true,
        ..Default::default()
    };
    let findings = scanner
        .scan(&url, &Client::new_lab(), &guard, false)
        .await
        .expect("scan");

    assert!(findings.iter().any(|finding| matches!(
        finding.evidence(),
        Evidence::SqliError { param, error_signature, .. }
            if param == "productId" && error_signature == "SQLite"
    )));
    let requests = server.received_requests().await.expect("record requests");
    assert!(
        requests.iter().any(|request| {
            request.method.as_str() == "GET"
                && request.url.query().is_some_and(|query| {
                    query.contains("productId=1%27") || query.contains("productId=1'")
                })
        }),
        "missing single-quote re-request: {requests:?}"
    );
}
