//! AST-based discovery of Supabase client usage in JS/TS bundles.

use std::collections::HashSet;
use std::sync::LazyLock;

use regex::Regex;

pub mod ast;
pub mod crawler;
pub mod param;
pub mod schema;

pub use riftlock_core::DiscoveredEndpoint;

/// One discovered Supabase client call site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Discovery {
    /// `.from('<table>')` — a queried table.
    Table {
        /// Table name from the string literal.
        name: String,
    },
    /// `.rpc('<fn>', {params})` — a PostgREST RPC call.
    Rpc {
        /// Function name.
        name: String,
        /// Raw source text of the params argument, if present.
        params: Option<String>,
    },
    /// `storage.from('<bucket>')` — a storage bucket accessed.
    Bucket {
        /// Bucket name.
        name: String,
    },
    /// `functions.invoke('<fn>')` — an edge function invoked.
    EdgeFunction {
        /// Function name.
        name: String,
    },
    /// A fetch endpoint discovered by constant folding or template-literal
    /// extraction (dynamic parts become `{param}`).
    Endpoint {
        /// Path, e.g. `/api/v2/users`.
        path: String,
        /// HTTP method (uppercased); `GET` when not stated.
        method: String,
    },
}

/// Discover Supabase client calls in JS/TS source text.
pub fn discover(source: &str) -> Vec<Discovery> {
    let mut out = ast::discover_ast(source);
    // Framework HTTP clients (Angular HttpClient, axios) hide API paths the
    // AST walk never sees: sweep the raw source for string-literal REST/GraphQL
    // paths and add the misses.
    // Keep explicit methods discovered by the AST or framework-call sweep;
    // only add the legacy GET fallback when no method was recognized for a path.
    let mut seen_paths: HashSet<String> = out
        .iter()
        .filter_map(|d| match d {
            Discovery::Endpoint { path, .. } => Some(path.clone()),
            _ => None,
        })
        .collect();
    let mut seen_methods: HashSet<(String, String)> = out
        .iter()
        .filter_map(|d| match d {
            Discovery::Endpoint { path, method } => Some((path.clone(), method.clone())),
            _ => None,
        })
        .collect();
    for caps in METHOD_API_PATH_RE.captures_iter(source) {
        let path = caps[2].to_owned();
        let method = caps[1].to_ascii_uppercase();
        seen_paths.insert(path.clone());
        if seen_methods.insert((path.clone(), method.clone())) {
            out.push(Discovery::Endpoint { path, method });
        }
    }
    for caps in API_PATH_RE
        .captures_iter(source)
        .chain(ROUTE_PATH_RE.captures_iter(source))
    {
        let path = caps[1].to_owned();
        if seen_paths.insert(path.clone()) && seen_methods.insert((path.clone(), "GET".to_owned()))
        {
            out.push(Discovery::Endpoint {
                path,
                method: "GET".to_owned(),
            });
        }
    }
    out
}

static METHOD_API_PATH_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"\b(get|post|put|patch|delete|head|options)\s*\(\s*[`"'](/(?:api|rest|v[0-9]+)/[^"'`\s]+|/graphql[A-Za-z0-9_\-./]*)["'`]"#,
    )
    .expect("static regex")
});
static API_PATH_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"[`"'](/(?:api|rest|v[0-9]+)/[^"'`\s]+|/graphql[A-Za-z0-9_\-./]*)["'`]"#)
        .expect("static regex")
});
static ROUTE_PATH_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?:path\s*[:=]\s*["'])(/[^"']*)["']"#).expect("static regex"));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regex_sweep_finds_framework_api_paths() {
        // Angular-style HttpClient call the AST walk cannot see.
        let src = r#"this.http.get("/rest/products/search?q=").subscribe();
        const login = '/rest/user/login';
        http.post(`/api/Challenges/`, {});
        fetch('/graphql');
        const notApi = '/assets/images.png';
        "#;
        let paths: Vec<String> = discover(src)
            .into_iter()
            .filter_map(|d| match d {
                Discovery::Endpoint { path, .. } => Some(path),
                _ => None,
            })
            .collect();
        assert_eq!(
            paths,
            vec![
                // `/graphql` leads: it comes from the AST fetch() walk. The
                // method-aware sweep follows, then the path-only fallback.
                "/graphql".to_owned(),
                "/rest/products/search?q=".to_owned(),
                "/api/Challenges/".to_owned(),
                "/rest/user/login".to_owned(),
            ]
        );
    }

    #[test]
    fn preserves_multiple_methods_for_the_same_endpoint_path() {
        let found = discover(
            r#"
                fetch('/api/v1/users');
                fetch('/api/v1/users', { method: 'post' });
                fetch('/api/v1/users', { method: 'DELETE' });
            "#,
        );
        let endpoints: Vec<(String, String)> = found
            .into_iter()
            .filter_map(|item| match item {
                Discovery::Endpoint { path, method } => Some((path, method)),
                _ => None,
            })
            .collect();
        assert_eq!(
            endpoints,
            vec![
                ("/api/v1/users".to_owned(), "GET".to_owned()),
                ("/api/v1/users".to_owned(), "POST".to_owned()),
                ("/api/v1/users".to_owned(), "DELETE".to_owned()),
            ]
        );
    }

    #[test]
    fn extracts_router_paths_and_deduplicates_api_routes() {
        let src = r#"
            const routes = [
                { path: '/account/:id', component: Account },
                { path: '/admin', component: Admin },
                { path: '/admin', component: Admin },
                { path: '/api/v1/users', component: Users },
            ];
            <Route path="/settings" element={<Settings />} />
        "#;
        let paths: Vec<String> = discover(src)
            .into_iter()
            .filter_map(|item| match item {
                Discovery::Endpoint { path, .. } => Some(path),
                _ => None,
            })
            .collect();
        assert_eq!(
            paths,
            vec!["/api/v1/users", "/account/:id", "/admin", "/settings",]
        );
    }

    #[test]
    fn fixture_extracts_four_calls() {
        let fixture = r#"
            const data = await supabase.from('profiles').select('*');
            const stats = await supabase.rpc('get_stats', { window: 7 });
            const files = await supabase.storage.from('avatars').list();
            const res = await supabase.functions.invoke('send-mail');
        "#;
        let found = discover(fixture);
        assert_eq!(
            found,
            vec![
                Discovery::Table {
                    name: "profiles".to_owned()
                },
                Discovery::Rpc {
                    name: "get_stats".to_owned(),
                    params: Some("{ window: 7 }".to_owned()),
                },
                Discovery::Bucket {
                    name: "avatars".to_owned()
                },
                Discovery::EdgeFunction {
                    name: "send-mail".to_owned()
                },
            ]
        );
    }
}
