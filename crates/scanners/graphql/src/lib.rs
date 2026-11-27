//! GraphQL scanner: proves a GraphQL endpoint executes batched request
//! arrays (a common rate-limit / cost-limit bypass).

use riftlock_core::ScopedClient as Client;
use riftlock_core::{
    text_limited_result, Coverage, Evidence, Finding, ProofGate, ScanError, Scanner, ScopeGuard,
};
use serde_json::json;
use url::Url;

/// The single-query probe. A 200 proves the endpoint executes queries at
/// all; it is the precondition for the batching differential.
fn single_query() -> serde_json::Value {
    json!({"query": "query { __typename }"})
}

/// The batched probe: two queries in one request.
fn batch_query() -> serde_json::Value {
    json!([
        {"query": "query { __typename }"},
        {"query": "query { __typename }"}
    ])
}

/// The alias-amplification probe: 100 field aliases in a single query. A
/// server that executes all of them in one request has no alias count cap.
fn alias_query() -> serde_json::Value {
    let q = format!(
        "query {{ {} }}",
        (1..=100)
            .map(|i| format!("a{i}: __typename"))
            .collect::<Vec<_>>()
            .join(" ")
    );
    json!({"query": q})
}

/// The introspection probe: leaks the full schema (types, private
/// operations) when introspection is left enabled.
fn introspection_query() -> serde_json::Value {
    json!({"query": "{__schema{types{name}}}"})
}

/// Whether an introspection response proves the schema is disclosed: a 200
/// whose `data` object actually carries `__schema`. A rejection message that
/// merely mentions `__schema` (validation errors do) is not a leak.
fn introspection_enabled(status: u16, body: &str) -> bool {
    status == 200
        && serde_json::from_str::<serde_json::Value>(body)
            .ok()
            .is_some_and(|v| v["data"]["__schema"].is_object())
}

/// Whether an alias response proves execution: a 200 whose data object
/// carries the last alias (`a100`), meaning every alias was resolved.
fn alias_executed(status: u16, body: &str) -> bool {
    status == 200
        && serde_json::from_str::<serde_json::Value>(body)
            .ok()
            .is_some_and(|v| v["data"]["a100"].is_string())
}

/// The GraphQL scanner. `matches()` is always true; the CLI feeds it the
/// `/graphql` endpoints discovered by AST (`endpoints`).
#[derive(Debug, Default)]
pub struct GraphQLScanner {
    /// GraphQL endpoint paths discovered by AST (absolute, e.g. `/graphql`).
    pub endpoints: Vec<String>,
    /// Shared coverage counters: an unreadable probe is a failed endpoint,
    /// never a checked negative.
    pub coverage: Coverage,
}

/// Whether a batched response proves execution: a 200 whose body is a JSON
/// array with one result per batched query.
fn batch_executed(status: u16, body: &str) -> bool {
    status == 200
        && serde_json::from_str::<serde_json::Value>(body)
            .ok()
            .and_then(|v| v.as_array().cloned())
            .is_some_and(|a| a.len() == 2)
}

impl GraphQLScanner {
    /// POST `payload` to `endpoint` on `url`'s origin. Returns (status, body).
    async fn post(
        client: &Client,
        url: &Url,
        endpoint: &str,
        payload: &serde_json::Value,
    ) -> Result<(u16, String), ScanError> {
        let target = url.join(endpoint).map_err(|_| ScanError::InvalidUrl)?;
        let resp = client.post(target).json(payload).send().await?;
        let status = resp.status().as_u16();
        let body = text_limited_result(resp).await?;
        Ok((status, body))
    }
}

impl Scanner for GraphQLScanner {
    fn id(&self) -> &'static str {
        "graphql"
    }

    fn matches(&self, _url: &Url) -> bool {
        // GraphQL endpoints live anywhere; discovery supplies the paths.
        true
    }

    async fn scan(
        &self,
        url: &Url,
        client: &Client,
        guard: &ScopeGuard,
        passive: bool,
    ) -> Result<Vec<Finding>, ScanError> {
        if passive {
            return Ok(Vec::new());
        }
        // Every GraphQL probe is a POST; read depth never sends them.
        if guard.is_read_only() {
            return Ok(Vec::new());
        }
        guard.check_active(url)?;
        let mut findings = Vec::new();
        // Nothing discovered matching graphql: the conventional path is
        // still worth one probe.
        let candidates = if self.endpoints.iter().any(|e| e.contains("graphql")) {
            self.endpoints.clone()
        } else {
            vec!["/graphql".to_owned()]
        };
        for endpoint in &candidates {
            if !endpoint.contains("graphql") {
                continue;
            }
            let probe = url.join(endpoint).map_err(|_| ScanError::InvalidUrl)?;
            if guard.check(&probe).is_err() {
                self.coverage.out_of_scope_endpoint_at(probe.as_str());
                continue;
            }
            // A body that cannot be read leaves this endpoint's proofs
            // unproven: record it and move on to the next endpoint.
            let check = self.coverage.begin_check();
            let probes: Result<(), ScanError> = async {
                // Precondition: single query executes. A blocked endpoint has
                // no batching to prove.
                let (status, _) =
                    GraphQLScanner::post(client, url, endpoint, &single_query()).await?;
                if status != 200 {
                    return Ok(());
                }
                // Introspection: the full schema disclosed to anyone.
                let (intro_status, intro_body) =
                    GraphQLScanner::post(client, url, endpoint, &introspection_query()).await?;
                if introspection_enabled(intro_status, &intro_body) {
                    findings.push(ProofGate::admit(Evidence::GraphQLIntrospection {
                        endpoint: probe.to_string(),
                    })?);
                }
                let (batch_status, batch_body) =
                    GraphQLScanner::post(client, url, endpoint, &batch_query()).await?;
                if batch_executed(batch_status, &batch_body) {
                    findings.push(ProofGate::admit(Evidence::GraphQLBatching {
                        endpoint: probe.to_string(),
                    })?);
                } else {
                    // Array batching rejected: alias amplification is the same
                    // rate-limit bypass through a different shape.
                    let (alias_status, alias_body) =
                        GraphQLScanner::post(client, url, endpoint, &alias_query()).await?;
                    if alias_executed(alias_status, &alias_body) {
                        findings.push(ProofGate::admit(Evidence::GraphQLBatching {
                            endpoint: probe.to_string(),
                        })?);
                    }
                }
                Ok(())
            }
            .await;
            match probes {
                Ok(()) => {
                    self.coverage
                        .endpoint_at(probe.as_str(), riftlock_core::EndpointOutcome::Tested);
                    let _ = check.finish(riftlock_core::CheckState::Completed);
                }
                Err(error) if error.transport_category().is_some() => {
                    riftlock_core::logln!(
                        "[!] GraphQL probe unreadable ({error}); endpoint marked failed."
                    );
                    self.coverage
                        .endpoint_at(probe.as_str(), riftlock_core::EndpointOutcome::Failed);
                    let _ = check.finish(riftlock_core::CheckState::Inconclusive);
                }
                Err(error) => return Err(error),
            }
        }
        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn read_only_scan_sends_nothing() {
        let server = wiremock::MockServer::start().await;
        let base = Url::parse(&server.uri()).expect("url");
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()])
            .expect("guard")
            .with_policy(riftlock_core::ScanPolicy::ReadOnly);
        let findings = Scanner::scan(
            &GraphQLScanner::default(),
            &base,
            &Client::new_lab(),
            &guard,
            false,
        )
        .await
        .expect("scan");
        assert!(findings.is_empty());
        assert!(server
            .received_requests()
            .await
            .expect("requests")
            .is_empty());
    }

    const OK_RESULT: &str = r#"{"data":{"__typename":"Query"}}"#;

    #[tokio::test]
    async fn scan_proves_batching() {
        let server = wiremock::MockServer::start().await;
        let single_body = single_query().to_string();
        let batch_body = batch_query().to_string();
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/graphql"))
            .and(wiremock::matchers::body_string(single_body))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string(OK_RESULT))
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/graphql"))
            .and(wiremock::matchers::body_string(batch_body))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_string(format!("[{OK_RESULT},{OK_RESULT}]")),
            )
            .mount(&server)
            .await;

        let base = Url::parse(server.uri().as_str()).expect("url");
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("guard");
        let scanner = GraphQLScanner {
            endpoints: vec!["/graphql".to_owned()],
            ..Default::default()
        };
        let findings = Scanner::scan(&scanner, &base, &Client::new_lab(), &guard, false)
            .await
            .expect("scan");
        assert_eq!(findings.len(), 1);
        assert!(matches!(
            findings[0].evidence(),
            Evidence::GraphQLBatching { endpoint }
                if endpoint.ends_with("/graphql")
        ));
    }

    #[tokio::test]
    async fn scan_negative_when_batch_rejected() {
        let server = wiremock::MockServer::start().await;
        let single_body = single_query().to_string();
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/graphql"))
            .and(wiremock::matchers::body_string(single_body))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string(OK_RESULT))
            .mount(&server)
            .await;
        // The batch is rejected even though single queries run: checked negative.
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/graphql"))
            .respond_with(wiremock::ResponseTemplate::new(400))
            .mount(&server)
            .await;

        let base = Url::parse(server.uri().as_str()).expect("url");
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("guard");
        let scanner = GraphQLScanner {
            endpoints: vec!["/graphql".to_owned()],
            ..Default::default()
        };
        let findings = Scanner::scan(&scanner, &base, &Client::new_lab(), &guard, false)
            .await
            .expect("scan");
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn scan_proves_alias_amplification() {
        let server = wiremock::MockServer::start().await;
        let single_body = single_query().to_string();
        let batch_body = batch_query().to_string();
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/graphql"))
            .and(wiremock::matchers::body_string(single_body))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string(OK_RESULT))
            .mount(&server)
            .await;
        // Array batching rejected...
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/graphql"))
            .and(wiremock::matchers::body_string(batch_body))
            .respond_with(wiremock::ResponseTemplate::new(400))
            .mount(&server)
            .await;
        // ...but the alias probe (any other body) executes fully.
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/graphql"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_string(r#"{"data":{"a100":"Query"}}"#),
            )
            .mount(&server)
            .await;

        let base = Url::parse(server.uri().as_str()).expect("url");
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("guard");
        let scanner = GraphQLScanner {
            endpoints: vec!["/graphql".to_owned()],
            ..Default::default()
        };
        let findings = Scanner::scan(&scanner, &base, &Client::new_lab(), &guard, false)
            .await
            .expect("scan");
        assert_eq!(findings.len(), 1);
        assert!(matches!(
            findings[0].evidence(),
            Evidence::GraphQLBatching { .. }
        ));
    }

    #[tokio::test]
    async fn scan_negative_when_execution_blocked() {
        let server = wiremock::MockServer::start().await;
        // Every POST blocked: no precondition, no probe of batching.
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .respond_with(wiremock::ResponseTemplate::new(403))
            .mount(&server)
            .await;

        let base = Url::parse(server.uri().as_str()).expect("url");
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("guard");
        let scanner = GraphQLScanner {
            endpoints: vec!["/graphql".to_owned()],
            ..Default::default()
        };
        let findings = Scanner::scan(&scanner, &base, &Client::new_lab(), &guard, false)
            .await
            .expect("scan");
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn scan_proves_introspection_when_nothing_discovered() {
        let server = wiremock::MockServer::start().await;
        // No discovered endpoints at all: the conventional /graphql path is
        // probed. Single query runs, the introspection query leaks __schema.
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/graphql"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_string(r#"{"data":{"__schema":{"queryType":{"name":"Query"}}}}"#),
            )
            .mount(&server)
            .await;

        let base = Url::parse(server.uri().as_str()).expect("url");
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("guard");
        let scanner = GraphQLScanner {
            endpoints: Vec::new(),
            ..Default::default()
        };
        let findings = Scanner::scan(&scanner, &base, &Client::new_lab(), &guard, false)
            .await
            .expect("scan");
        assert_eq!(findings.len(), 1);
        assert!(matches!(
            findings[0].evidence(),
            Evidence::GraphQLIntrospection { endpoint }
                if endpoint.ends_with("/graphql")
        ));
    }

    #[tokio::test]
    async fn scan_negative_when_introspection_blocked() {
        let server = wiremock::MockServer::start().await;
        // The endpoint runs plain queries but rejects introspection with a
        // validation error — no __schema, no finding.
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::body_string(single_query().to_string()))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string(OK_RESULT))
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_string(r#"{"errors":[{"message":"introspection disabled"}]}"#),
            )
            .mount(&server)
            .await;

        let base = Url::parse(server.uri().as_str()).expect("url");
        let guard = ScopeGuard::new_lab(&[server.uri().as_str()]).expect("guard");
        let scanner = GraphQLScanner {
            endpoints: vec!["/graphql".to_owned()],
            ..Default::default()
        };
        let findings = Scanner::scan(&scanner, &base, &Client::new_lab(), &guard, false)
            .await
            .expect("scan");
        assert!(findings.is_empty());
    }
}
