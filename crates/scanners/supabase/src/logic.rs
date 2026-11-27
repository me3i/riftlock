//! Business-logic probes: race conditions and price manipulation.
//! Lab-only: every call site must hold a [`LabGuard`](riftlock_core::LabGuard).

use crate::ScanError;
use riftlock_core::ScopedClient as Client;
use url::Url;

/// Race-condition probe: fire 5 concurrent POSTs at `endpoint` and report
/// whether more than one succeeded — a control that should be single-shot.
///
/// # Errors
/// Transport failures or invalid URL.
pub async fn probe_race_condition(
    client: &Client,
    base: &Url,
    key: &str,
    endpoint: &str,
) -> Result<bool, ScanError> {
    let url = base.join(endpoint).map_err(|_| ScanError::InvalidUrl)?;
    let send = || {
        let req = client
            .post(url.clone())
            .header("apikey", key)
            .header("Authorization", format!("Bearer {key}"))
            .json(&serde_json::json!({}));
        req.send()
    };
    // Bounded fan-out: 5 fixed requests, not an unbounded join_all.
    let mut set = tokio::task::JoinSet::new();
    for _ in 0..5 {
        let fut = send();
        set.spawn(async move { fut.await.map(|r| r.status().as_u16()).unwrap_or(0) });
    }
    let mut oks = 0;
    while let Some(join) = set.join_next().await {
        if matches!(join, Ok(200)) {
            oks += 1;
        }
    }
    Ok(oks > 1)
}

/// Price-manipulation probe: does `endpoint` accept a negative amount?
///
/// # Errors
/// Transport failures or invalid URL.
pub async fn probe_price_manipulation(
    client: &Client,
    base: &Url,
    key: &str,
    endpoint: &str,
) -> Result<bool, ScanError> {
    let url = base.join(endpoint).map_err(|_| ScanError::InvalidUrl)?;
    let resp = client
        .post(url)
        .header("apikey", key)
        .header("Authorization", format!("Bearer {key}"))
        .json(&serde_json::json!({"amount": -100, "quantity": 1}))
        .send()
        .await?;
    Ok(resp.status().as_u16() == 200)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn race_and_price_probes() {
        use std::sync::atomic::{AtomicU8, Ordering};
        use std::sync::Arc;
        use wiremock::matchers::{body_partial_json, method};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        // Single-shot control: server counts successes; 5 concurrent posts
        // all 200 → probe reports race. (wiremock has no rate limit, so
        // this asserts the >1 detection path.)
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let base = Url::parse(server.uri().as_str()).expect("url");
        let client = Client::new_lab();
        let raced = probe_race_condition(&client, &base, "k", "/rpc/claim")
            .await
            .expect("race probe");
        assert!(raced, "5 concurrent 200s must be detected as race");

        // Price probe accepts the negative amount.
        let counter = Arc::new(AtomicU8::new(0));
        let c = counter.clone();
        Mock::given(method("POST"))
            .and(body_partial_json(
                serde_json::json!({"amount": -100, "quantity": 1}),
            ))
            .respond_with(move |req: &wiremock::Request| {
                c.fetch_add(1, Ordering::SeqCst);
                let _ = req;
                ResponseTemplate::new(200)
            })
            .mount(&server)
            .await;
        let bypassed = probe_price_manipulation(&client, &base, "k", "/rpc/checkout")
            .await
            .expect("price probe");
        assert!(bypassed, "200 on negative amount must be a bypass");
    }

    #[tokio::test]
    async fn rejection_is_not_a_bypass() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(422))
            .mount(&server)
            .await;
        let base = Url::parse(server.uri().as_str()).expect("url");
        let client = Client::new_lab();
        assert!(
            !probe_price_manipulation(&client, &base, "k", "/rpc/checkout")
                .await
                .expect("price probe")
        );
    }
}
