use riftlock_core::ScopedClient as Client;
use riftlock_core::{Evidence, Scanner, ScopeGuard};
use riftlock_scanner_generic::GenericScanner;
use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

fn scan_client() -> Client {
    Client::new_lab()
}

#[tokio::test]
async fn boolean_pair_divergence_is_proved() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/product"))
        .respond_with(|request: &Request| {
            let falsy = request
                .url
                .query_pairs()
                .any(|(key, value)| key == "productId" && value == "1 AND 1=2");
            let body = if falsy {
                "no results".to_owned()
            } else {
                "product details page".to_owned()
            };
            // Both halves are 200: only body divergence may prove boolean SQLi.
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
        .scan(&url, &scan_client(), &guard, false)
        .await
        .expect("scan");

    assert!(findings.iter().any(|finding| matches!(
        finding.evidence(),
        Evidence::SqlInjection { param, payload, .. }
            if param == "productId" && payload.contains("1 AND 1=1")
    )));
    let requests = server.received_requests().await.expect("record requests");
    for payload in ["1 AND 1=1", "1 AND 1=2"] {
        assert!(
            requests
                .iter()
                .any(|request| request
                    .url
                    .query()
                    .is_some_and(|query| query.contains(&payload.replace(' ', "%20"))
                        || query.contains(payload))),
            "missing boolean probe {payload}: {requests:?}"
        );
    }
}

#[tokio::test]
async fn login_redirect_is_not_reported_as_broken_access_control() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/admin"))
        .respond_with(ResponseTemplate::new(302).insert_header("location", "/admin/login"))
        .mount(&server)
        .await;

    let url = Url::parse(&format!("{}/admin", server.uri())).expect("url");
    let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("guard");
    let scanner = GenericScanner {
        force_run: true,
        ..Default::default()
    };
    let findings = scanner
        .scan(&url, &scan_client(), &guard, false)
        .await
        .expect("scan");
    assert!(!findings
        .iter()
        .any(|finding| matches!(finding.evidence(), Evidence::BrokenAccessControl { .. })));
}

#[tokio::test]
async fn non_login_redirect_is_not_broken_access_control() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/admin"))
        .respond_with(ResponseTemplate::new(302).insert_header("location", "/public"))
        .mount(&server)
        .await;

    let url = Url::parse(&format!("{}/admin", server.uri())).expect("url");
    let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("guard");
    let scanner = GenericScanner {
        force_run: true,
        ..Default::default()
    };
    let findings = scanner
        .scan(&url, &scan_client(), &guard, false)
        .await
        .expect("scan");
    assert!(!findings
        .iter()
        .any(|finding| matches!(finding.evidence(), Evidence::BrokenAccessControl { .. })));
}

#[tokio::test]
async fn sensitive_http_200_without_marker_is_not_reported() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/admin"))
        .respond_with(ResponseTemplate::new(200).set_body_string("private page"))
        .mount(&server)
        .await;

    let url = Url::parse(&format!("{}/admin", server.uri())).expect("url");
    let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("guard");
    let scanner = GenericScanner {
        force_run: true,
        ..Default::default()
    };
    let findings = scanner
        .scan(&url, &scan_client(), &guard, false)
        .await
        .expect("scan");
    assert!(!findings
        .iter()
        .any(|finding| matches!(finding.evidence(), Evidence::BrokenAccessControl { .. })));
}

#[tokio::test]
async fn sensitive_http_denial_discloses_path_but_never_claims_access() {
    for status in [401u16, 403] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/admin"))
            .respond_with(ResponseTemplate::new(status).set_body_string("private page"))
            .mount(&server)
            .await;

        let url = Url::parse(&format!("{}/admin", server.uri())).expect("url");
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("guard");
        let scanner = GenericScanner {
            force_run: true,
            ..Default::default()
        };
        let findings = scanner
            .scan(&url, &scan_client(), &guard, false)
            .await
            .expect("scan");
        let disclosed: Vec<_> = findings
            .iter()
            .filter_map(|finding| match finding.evidence() {
                Evidence::SensitivePathDisclosed { url, status } => Some((url.clone(), *status)),
                _ => None,
            })
            .collect();
        assert_eq!(disclosed.len(), 1, "HTTP {status}");
        assert_eq!(disclosed[0].1, status);
        assert!(disclosed[0].0.ends_with("/admin"));
        assert!(!findings
            .iter()
            .any(|finding| matches!(finding.evidence(), Evidence::BrokenAccessControl { .. })));
    }
}

#[tokio::test]
async fn anonymous_sensitive_page_is_flagged() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/admin"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/html")
                .set_body_string("<h1>Dashboard</h1><a href=\"/logout\">Log out</a>"),
        )
        .mount(&server)
        .await;

    let url = Url::parse(&format!("{}/admin", server.uri())).expect("url");
    let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("guard");
    let scanner = GenericScanner {
        force_run: true,
        ..Default::default()
    };
    let findings = scanner
        .scan(&url, &scan_client(), &guard, false)
        .await
        .expect("scan");

    assert!(findings.iter().any(|finding| matches!(
        finding.evidence(),
        Evidence::BrokenAccessControl { url, dashboard_marker }
            if url.ends_with("/admin") && !dashboard_marker.is_empty()
    )));
}
