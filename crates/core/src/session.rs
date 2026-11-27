//! Multi-user session matrix for differential testing.

/// Tokens for each principal tier used in session-based differential
/// probes. Absent tiers are skipped by scanners.
#[derive(Debug, Clone, Default)]
pub struct SessionMatrix {
    /// Unauthenticated tier (no token).
    pub guest: Option<String>,
    /// A regular user's session token.
    pub user_a: Option<String>,
    /// A second regular user's session token (cross-tenant checks).
    pub user_b: Option<String>,
    /// An administrator's session token.
    pub admin: Option<String>,
}

impl SessionMatrix {
    /// Read session tokens from `RIFTLOCK_SESSION_GUEST`, `_USER_A`,
    /// `_USER_B`, `_ADMIN`.
    pub fn from_env() -> Self {
        let var = |name: &str| std::env::var(name).ok().filter(|s| !s.is_empty());
        Self {
            guest: var("RIFTLOCK_SESSION_GUEST"),
            user_a: var("RIFTLOCK_SESSION_USER_A"),
            user_b: var("RIFTLOCK_SESSION_USER_B"),
            admin: var("RIFTLOCK_SESSION_ADMIN"),
        }
    }
}
