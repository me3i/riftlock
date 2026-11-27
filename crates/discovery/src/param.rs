//! Common parameter names for dynamic endpoint probing.

use riftlock_core::ScanError;
use std::path::Path;

/// Load the parameter wordlist used by the dynamic scanners to fuzz
/// discovered endpoints. `Some(path)` reads the file one entry per line
/// (trimmed; blank lines and `#` comments skipped); `None` returns the
/// embedded default list.
///
/// # Errors
/// Reading the wordlist file failed.
pub fn load_wordlist(path: Option<&Path>) -> Result<Vec<String>, ScanError> {
    match path {
        None => Ok(fuzz_parameters()),
        Some(path) => Ok(std::fs::read_to_string(path)?
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(str::to_owned)
            .collect()),
    }
}

/// Embedded default list of parameter names common in BaaS applications.
pub fn fuzz_parameters() -> Vec<String> {
    [
        "id",
        "user_id",
        "userId",
        "admin",
        "is_admin",
        "role",
        "debug",
        "test",
        "limit",
        "offset",
        "page",
        "email",
        "token",
        "auth",
        "key",
        "apikey",
        "select",
        "filter",
        "sort",
        "tenant_id",
        "q",
        "search",
        "query",
        "user",
        "username",
        "file",
        "path",
        "url",
        "redirect",
        "next",
        "template",
        "tpl",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect()
}

/// Large parameter list used only by the godmode preset: the standard list
/// plus object-graph, auth and injection-oriented names. Entries are unique.
pub fn deep_fuzz_parameters() -> Vec<String> {
    let mut params = fuzz_parameters();
    params.extend(
        [
            "account",
            "account_id",
            "org",
            "org_id",
            "organization",
            "organization_id",
            "owner",
            "owner_id",
            "group",
            "group_id",
            "team",
            "team_id",
            "project",
            "project_id",
            "workspace",
            "workspace_id",
            "session",
            "session_id",
            "uid",
            "uuid",
            "guid",
            "subject",
            "sub",
            "iss",
            "aud",
            "scope",
            "permissions",
            "privilege",
            "password",
            "passwd",
            "secret",
            "api_key",
            "access_token",
            "refresh_token",
            "jwt",
            "signature",
            "callback",
            "return",
            "returnUrl",
            "return_url",
            "dest",
            "destination",
            "target",
            "uri",
            "webhook",
            "host",
            "domain",
            "origin",
            "format",
            "output",
            "type",
            "action",
            "cmd",
            "exec",
            "code",
            "lang",
            "locale",
            "currency",
            "price",
            "amount",
        ]
        .iter()
        .map(|s| (*s).to_owned()),
    );
    params
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_is_nonempty_and_unique() {
        let params = fuzz_parameters();
        assert!(params.len() >= 20);
        let mut sorted = params.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), params.len());
    }

    #[test]
    fn deep_list_is_a_unique_superset_of_the_standard_list() {
        let standard = fuzz_parameters();
        let deep = deep_fuzz_parameters();
        assert!(deep.len() > standard.len());
        for param in &standard {
            assert!(deep.contains(param), "deep list dropped {param}");
        }
        let mut sorted = deep.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), deep.len(), "deep list has duplicates");
    }

    #[test]
    fn none_returns_embedded_default() {
        assert_eq!(
            load_wordlist(None).expect("default wordlist"),
            fuzz_parameters()
        );
    }

    #[test]
    fn file_is_trimmed_and_skips_blanks_and_comments() {
        let mut dir = std::env::temp_dir();
        dir.push(format!("riftlock-wordlist-{}.txt", std::process::id()));
        std::fs::write(
            &dir,
            "# header comment\n  id  \n\n\tuser_id\t\n# tail\n\nkey\n",
        )
        .expect("write fixture");
        let loaded = load_wordlist(Some(&dir)).expect("load wordlist");
        std::fs::remove_file(&dir).expect("cleanup");
        assert_eq!(loaded, vec!["id", "user_id", "key"]);
    }

    #[test]
    fn missing_file_is_a_clean_error() {
        let missing = std::env::temp_dir().join("riftlock-no-such-wordlist-xyz.txt");
        let _ = std::fs::remove_file(&missing);
        assert!(matches!(
            load_wordlist(Some(&missing)),
            Err(ScanError::Io(_))
        ));
    }
}
