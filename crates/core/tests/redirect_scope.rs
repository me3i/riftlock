//! Controlled local-server proof that a redirect can never leave the scan
//! boundary. The critical assertion in every negative case is that the
//! forbidden destination receives ZERO requests.

use reqwest::{Method, Request, StatusCode};
use riftlock_core::{ScanError, ScanPolicy, ScopeGuard, ScopedClient, MAX_REDIRECT_HOPS};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request as WireRequest, ResponseTemplate};

fn guard_for(uris: &[String]) -> ScopeGuard {
    let refs: Vec<&str> = uris.iter().map(String::as_str).collect();
    ScopeGuard::new_lab(&refs).expect("lab guard")
}

fn redirect(location: &str) -> ResponseTemplate {
    ResponseTemplate::new(StatusCode::FOUND).insert_header("location", location)
}

fn hits(requests: &[WireRequest], p: &str) -> usize {
    requests.iter().filter(|r| r.url.path() == p).count()
}

fn host_hits(requests: &[WireRequest], p: &str, h: &str) -> usize {
    requests
        .iter()
        .filter(|r| {
            r.url.path() == p
                && r.headers
                    .get("host")
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|v| v.starts_with(h))
        })
        .count()
}

#[tokio::test]
async fn in_scope_redirect_is_followed() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/start"))
        .respond_with(redirect("/final"))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/final"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&server)
        .await;
    let guard = guard_for(&[server.uri()]);
    let url = format!("{}/start", server.uri()).parse().unwrap();
    let response = ScopedClient::new_lab()
        .send_scoped(Request::new(Method::GET, url), &guard)
        .await
        .expect("in-scope hop");
    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await.unwrap(), "ok");
    let requests = server.received_requests().await.unwrap();
    assert_eq!(hits(&requests, "/start"), 1);
    assert_eq!(hits(&requests, "/final"), 1);
}

#[tokio::test]
async fn out_of_scope_host_receives_zero_requests() {
    let server = MockServer::start().await;
    let port = server.address().port();
    // Same socket, different host name: the guard is host-scoped, so this is
    // a genuine out-of-scope destination that the mock can still observe.
    let outside = format!("http://localhost:{port}/evil");
    Mock::given(method("GET"))
        .and(path("/start"))
        .respond_with(redirect(&outside))
        .mount(&server)
        .await;
    Mock::given(path("/evil"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    let guard = guard_for(&[format!("http://127.0.0.1:{port}")]);
    let url = format!("http://127.0.0.1:{port}/start").parse().unwrap();
    let err = ScopedClient::new_lab()
        .send_scoped(Request::new(Method::GET, url), &guard)
        .await
        .expect_err("out-of-scope host");
    assert!(matches!(err, ScanError::Scope(_)), "{err:?}");
    let requests = server.received_requests().await.unwrap();
    assert_eq!(hits(&requests, "/start"), 1);
    assert_eq!(
        host_hits(&requests, "/evil", "localhost"),
        0,
        "forbidden host was contacted"
    );
}

#[tokio::test]
async fn different_port_receives_zero_requests_even_when_host_is_in_scope() {
    let origin = MockServer::start().await;
    let outside = MockServer::start().await;
    let location = format!("{}/evil", outside.uri());
    Mock::given(method("GET"))
        .and(path("/start"))
        .respond_with(redirect(&location))
        .mount(&origin)
        .await;
    Mock::given(method("GET"))
        .and(path("/evil"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&outside)
        .await;
    // Both hosts are explicitly in scope: only the port boundary can stop it.
    let guard = guard_for(&[origin.uri(), outside.uri()]);
    let url = format!("{}/start", origin.uri()).parse().unwrap();
    let err = ScopedClient::new_lab()
        .send_scoped(Request::new(Method::GET, url), &guard)
        .await
        .expect_err("port change");
    assert!(
        matches!(err, ScanError::RedirectBoundaryChange(_)),
        "{err:?}"
    );
    assert_eq!(
        outside.received_requests().await.unwrap().len(),
        0,
        "other port was contacted"
    );
}

#[tokio::test]
async fn unsupported_scheme_is_refused_before_any_request() {
    let server = MockServer::start().await;
    let port = server.address().port();
    let location = format!("ftp://127.0.0.1:{port}/evil");
    Mock::given(method("GET"))
        .and(path("/start"))
        .respond_with(redirect(&location))
        .mount(&server)
        .await;
    Mock::given(path("/evil"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    let guard = guard_for(&[format!("http://127.0.0.1:{port}")]);
    let url = format!("http://127.0.0.1:{port}/start").parse().unwrap();
    let err = ScopedClient::new_lab()
        .send_scoped(Request::new(Method::GET, url), &guard)
        .await
        .expect_err("scheme change");
    assert!(
        matches!(err, ScanError::RedirectBoundaryChange(_)),
        "{err:?}"
    );
    assert_eq!(hits(&server.received_requests().await.unwrap(), "/evil"), 0);
}

#[tokio::test]
async fn redirect_loop_is_detected_and_bounded() {
    let server = MockServer::start().await;
    Mock::given(path("/a"))
        .respond_with(redirect("/b"))
        .mount(&server)
        .await;
    Mock::given(path("/b"))
        .respond_with(redirect("/a"))
        .mount(&server)
        .await;
    let guard = guard_for(&[server.uri()]);
    let url = format!("{}/a", server.uri()).parse().unwrap();
    let err = ScopedClient::new_lab()
        .send_scoped(Request::new(Method::GET, url), &guard)
        .await
        .expect_err("loop");
    assert!(matches!(err, ScanError::RedirectLoop(_)), "{err:?}");
    let requests = server.received_requests().await.unwrap();
    // The loop is detected before /a is sent a second time.
    assert_eq!(hits(&requests, "/a"), 1);
    assert_eq!(hits(&requests, "/b"), 1);
    assert!(requests.len() <= 2);
}

#[tokio::test]
async fn excessive_chain_stops_at_the_hop_limit() {
    let server = MockServer::start().await;
    let total = MAX_REDIRECT_HOPS + 3;
    for i in 0..total {
        Mock::given(path(format!("/hop{i}")))
            .respond_with(redirect(&format!("/hop{}", i + 1)))
            .mount(&server)
            .await;
    }
    let guard = guard_for(&[server.uri()]);
    let url = format!("{}/hop0", server.uri()).parse().unwrap();
    let err = ScopedClient::new_lab()
        .send_scoped(Request::new(Method::GET, url), &guard)
        .await
        .expect_err("chain limit");
    assert!(matches!(err, ScanError::TooManyRedirects(_)), "{err:?}");
    let requests = server.received_requests().await.unwrap();
    assert!(
        requests.len() <= MAX_REDIRECT_HOPS + 1,
        "{}",
        requests.len()
    );
    assert_eq!(hits(&requests, &format!("/hop{total}")), 0);
}

#[tokio::test]
async fn see_other_changes_post_to_get() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/submit"))
        .respond_with(
            ResponseTemplate::new(StatusCode::SEE_OTHER).insert_header("location", "/done"),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/done"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    let guard = guard_for(&[server.uri()]);
    let url = format!("{}/submit", server.uri()).parse().unwrap();
    let response = ScopedClient::new_lab()
        .send_scoped(Request::new(Method::POST, url), &guard)
        .await
        .expect("303 followed");
    assert_eq!(response.status(), 200);
    let requests = server.received_requests().await.unwrap();
    assert_eq!(hits(&requests, "/done"), 1);
    assert!(requests
        .iter()
        .any(|r| r.url.path() == "/done" && r.method == Method::GET));
}

#[tokio::test]
async fn read_only_blocks_writes_before_the_first_request() {
    let server = MockServer::start().await;
    Mock::given(path("/write"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    let guard = guard_for(&[server.uri()]).with_policy(ScanPolicy::ReadOnly);
    let url = format!("{}/write", server.uri()).parse().unwrap();
    let err = ScopedClient::new_lab()
        .send_scoped(Request::new(Method::POST, url), &guard)
        .await
        .expect_err("read only write");
    assert!(matches!(err, ScanError::Scope(_)), "{err:?}");
    assert_eq!(server.received_requests().await.unwrap().len(), 0);
}

#[tokio::test]
async fn read_only_allows_in_scope_get_redirect() {
    let server = MockServer::start().await;
    Mock::given(path("/start"))
        .respond_with(redirect("/final"))
        .mount(&server)
        .await;
    Mock::given(path("/final"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    let guard = guard_for(&[server.uri()]).with_policy(ScanPolicy::ReadOnly);
    let url = format!("{}/start", server.uri()).parse().unwrap();
    let response = ScopedClient::new_lab()
        .send_scoped(Request::new(Method::GET, url), &guard)
        .await
        .expect("read-only hop");
    assert_eq!(response.status(), 200);
}

#[tokio::test]
async fn credentials_are_stripped_across_in_scope_origins() {
    let server = MockServer::start().await;
    let port = server.address().port();
    let outside = format!("http://localhost:{port}/final");
    Mock::given(path("/start"))
        .respond_with(redirect(&outside))
        .mount(&server)
        .await;
    Mock::given(path("/final"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    let guard = guard_for(&[
        format!("http://127.0.0.1:{port}"),
        format!("http://localhost:{port}"),
    ]);
    let url = format!("http://127.0.0.1:{port}/start").parse().unwrap();
    let mut request = Request::new(Method::GET, url);
    request
        .headers_mut()
        .insert("authorization", "bearer secret".parse().unwrap());
    request
        .headers_mut()
        .insert("cookie", "sid=secret".parse().unwrap());
    request
        .headers_mut()
        .insert("x-trace", "keep-me".parse().unwrap());
    ScopedClient::new_lab()
        .send_scoped(request, &guard)
        .await
        .expect("cross-origin in-scope hop");
    let requests = server.received_requests().await.unwrap();
    let final_request = requests
        .iter()
        .find(|r| {
            r.url.path() == "/final" && host_hits(&[(*r).clone()], "/final", "localhost") == 1
        })
        .expect("final request");
    assert!(!final_request.headers.contains_key("authorization"));
    assert!(!final_request.headers.contains_key("cookie"));
    assert_eq!(final_request.headers.get("x-trace").unwrap(), "keep-me");
}

#[tokio::test]
async fn caller_redirect_policy_cannot_reopen_the_boundary() {
    // A library caller supplies a builder that explicitly asks reqwest to
    // follow redirects. ScopedClient overrides it, so plain send() surfaces
    // the 302 and the out-of-scope host is never contacted.
    let server = MockServer::start().await;
    let port = server.address().port();
    let outside = format!("http://localhost:{port}/evil");
    Mock::given(path("/start"))
        .respond_with(redirect(&outside))
        .mount(&server)
        .await;
    Mock::given(path("/evil"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    let guard = guard_for(&[format!("http://127.0.0.1:{port}")]);
    let client = ScopedClient::from_builder(
        reqwest::Client::builder().redirect(reqwest::redirect::Policy::limited(10)),
        &guard,
    )
    .expect("client");
    let url: url::Url = format!("http://127.0.0.1:{port}/start").parse().unwrap();
    let response = client.get(url.clone()).send().await.expect("send");
    assert_eq!(response.status(), StatusCode::FOUND);
    assert!(matches!(
        client
            .send_scoped(Request::new(Method::GET, url), &guard)
            .await,
        Err(ScanError::Scope(_))
    ));
    let requests = server.received_requests().await.unwrap();
    assert_eq!(hits(&requests, "/start"), 2);
    assert_eq!(
        host_hits(&requests, "/evil", "localhost"),
        0,
        "caller config bypassed scope"
    );
}
