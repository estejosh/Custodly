//! Mint a GitHub App installation access token, and verify what comes
//! back before anything downstream trusts it.
//!
//! Split into three pieces on purpose, each independently testable:
//! [`mint_jwt`] (pure -- no network), `verify_no_scope_creep` (pure --
//! no network), and [`mint_installation_token`] (the network call, which
//! is just those two pieces plus one HTTP round trip). A bug in the
//! trust logic should be catchable without a live GitHub App to test
//! against.

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};
use custodly_core::{Tier, assess_github_scope};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum GithubError {
    #[error("could not sign the App JWT: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
    #[error("GitHub API request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("GitHub returned {status}: {body}")]
    Api { status: u16, body: String },
    /// Per `docs/THREAT-MODEL.md`: "A key that comes back broader than
    /// requested is quarantined and reported, never stored." This is
    /// that quarantine -- reaching this variant means nothing was
    /// stored, because [`mint_installation_token`] returns before
    /// building a [`MintedToken`] at all.
    #[error(
        "GitHub granted more than was requested -- refusing to hand this back, nothing was \
         stored. requested {requested:?}, granted {granted:?}"
    )]
    ScopeCreep {
        requested: BTreeMap<String, String>,
        granted: BTreeMap<String, String>,
    },
    #[error("GitHub granted a permission level Custodly's tiering model doesn't recognize: {0:?}")]
    UnrecognizedPermission(BTreeMap<String, String>),
}

/// A GitHub App's identity. `private_key_pem` must be read fresh from
/// `master.kdbx` by the caller for exactly the duration of one mint
/// call and dropped afterward -- per `docs/THREAT-MODEL.md`, the App's
/// private key is the one master secret, sealed and never machine-held
/// beyond the moment it's actually used. Nothing in this crate caches
/// it or writes it anywhere.
pub struct AppCredentials {
    pub app_id: u64,
    pub private_key_pem: String,
}

/// What's being asked for: which installation, and the narrowest set of
/// permissions/repositories that satisfy the caller's need. GitHub lets
/// an installation-token request narrow down from what the App was
/// installed with -- Custodly should always ask for the least it can,
/// not the installation's full grant.
#[derive(Debug, Clone)]
pub struct RequestedGrant {
    pub installation_id: u64,
    /// `resource -> "read" | "write"`, e.g. `{"contents": "read"}` --
    /// GitHub's own permission vocabulary, not the `resource:level`
    /// string `assess_github_scope` reads (that string is built from
    /// what's actually granted, in [`MintedToken::from_response`]).
    pub permissions: BTreeMap<String, String>,
    /// `None` requests every repository the installation covers;
    /// `Some` narrows to specific repos by GitHub's numeric id.
    pub repository_ids: Option<Vec<u64>>,
}

/// A successfully minted and verified installation token, ready to be
/// wrapped in a `custodly_core::EntryMetadata` and deposited via
/// `custodly_vault::Vault::put`. There is no way to construct one except
/// through [`mint_installation_token`], which will not produce one for a
/// token that failed the scope-creep check.
#[derive(Debug, Clone)]
pub struct MintedToken {
    pub token: String,
    pub expires_at: DateTime<Utc>,
    pub granted_permissions: BTreeMap<String, String>,
    /// `"resource:level,resource:level"` -- the shape
    /// `custodly_core::assess_github_scope` reads, built from what
    /// GitHub actually granted, not what was requested, so tiering
    /// reflects reality rather than intent.
    pub scope_string: String,
    pub tier: Tier,
}

impl MintedToken {
    fn from_response(resp: InstallationTokenResponse) -> Self {
        let scope_string = resp
            .permissions
            .iter()
            .map(|(resource, level)| format!("{resource}:{level}"))
            .collect::<Vec<_>>()
            .join(",");
        let tier = Tier::score(assess_github_scope(&scope_string).as_ref());
        Self {
            token: resp.token,
            expires_at: resp.expires_at,
            granted_permissions: resp.permissions,
            scope_string,
            tier,
        }
    }
}

#[derive(Debug, Deserialize)]
struct InstallationTokenResponse {
    token: String,
    expires_at: DateTime<Utc>,
    #[serde(default)]
    permissions: BTreeMap<String, String>,
}

#[derive(Serialize)]
struct AccessTokenRequest<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    repository_ids: &'a Option<Vec<u64>>,
    permissions: &'a BTreeMap<String, String>,
}

#[derive(Serialize, Deserialize)]
struct Claims {
    iat: i64,
    exp: i64,
    iss: String,
}

/// Build and sign the App JWT GitHub's installation-token endpoint
/// requires as bearer auth. `iat` is backdated 60s to tolerate clock
/// drift between this machine and GitHub's; `exp` is capped at 9
/// minutes -- under GitHub's 10-minute hard limit, so a slow request
/// never straddles expiry mid-call. `now` is a parameter rather than
/// `Utc::now()` internally so the claim math is testable without
/// mocking the clock.
pub fn mint_jwt(app: &AppCredentials, now: DateTime<Utc>) -> Result<String, GithubError> {
    let claims = Claims {
        iat: (now - Duration::seconds(60)).timestamp(),
        exp: (now + Duration::minutes(9)).timestamp(),
        iss: app.app_id.to_string(),
    };
    let key = EncodingKey::from_rsa_pem(app.private_key_pem.as_bytes())?;
    Ok(encode(&Header::new(Algorithm::RS256), &claims, &key)?)
}

/// GitHub's permission levels, ranked so "wider than requested" is a
/// simple comparison. Anything GitHub might return that isn't one of
/// these is unrecognized, not silently trusted -- same fail-closed
/// instinct as `custodly_core::assess_github_scope`.
fn level_rank(level: &str) -> Option<u8> {
    match level {
        "read" => Some(0),
        "write" => Some(1),
        _ => None,
    }
}

/// Per `docs/THREAT-MODEL.md`: a token GitHub hands back with more than
/// what was requested is quarantined, never stored. Two ways that
/// happens: a permission granted that wasn't asked for at all, or one
/// granted at a higher level than requested (`read` asked, `write`
/// granted). Narrower than asked -- a permission requested but not
/// actually present in the grant -- is never the problem this guards
/// against; GitHub not fully satisfying a request is a different failure
/// than GitHub over-satisfying one.
fn verify_no_scope_creep(
    requested: &BTreeMap<String, String>,
    granted: &BTreeMap<String, String>,
) -> Result<(), GithubError> {
    for (resource, granted_level) in granted {
        let Some(requested_level) = requested.get(resource) else {
            return Err(GithubError::ScopeCreep {
                requested: requested.clone(),
                granted: granted.clone(),
            });
        };
        let Some(granted_rank) = level_rank(granted_level) else {
            return Err(GithubError::UnrecognizedPermission(granted.clone()));
        };
        let requested_rank = level_rank(requested_level).unwrap_or(u8::MAX);
        if granted_rank > requested_rank {
            return Err(GithubError::ScopeCreep {
                requested: requested.clone(),
                granted: granted.clone(),
            });
        }
    }
    Ok(())
}

/// Mint one installation access token for `grant.installation_id`,
/// scoped to exactly what `grant` asks for, and refuse to hand it back
/// if GitHub granted more than that. This is the only public entry
/// point into GitHub for this crate -- there is no lower-level "just
/// give me whatever the installation has" call.
pub async fn mint_installation_token(
    client: &reqwest::Client,
    app: &AppCredentials,
    grant: &RequestedGrant,
) -> Result<MintedToken, GithubError> {
    let jwt = mint_jwt(app, Utc::now())?;
    let url = format!(
        "https://api.github.com/app/installations/{}/access_tokens",
        grant.installation_id
    );
    let response = client
        .post(&url)
        .bearer_auth(jwt)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .header("User-Agent", "custodly")
        .json(&AccessTokenRequest {
            repository_ids: &grant.repository_ids,
            permissions: &grant.permissions,
        })
        .send()
        .await?;

    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(GithubError::Api { status: status.as_u16(), body });
    }
    let parsed: InstallationTokenResponse = response.json().await?;
    verify_no_scope_creep(&grant.permissions, &parsed.permissions)?;
    Ok(MintedToken::from_response(parsed))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test-only RSA keypair, generated fresh for this test suite and used
    // nowhere else -- not a real App key, not a secret. Regenerate with
    // `openssl genrsa -traditional -out key.pem 2048` /
    // `openssl rsa -in key.pem -pubout -out pub.pem` if it ever needs
    // replacing.
    const TEST_PRIVATE_KEY_PEM: &str = "-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAv2M0owXgR/QsS+f6b/BfLZ2XnzyF0JHaIcBetglfHQTYEzLq
VyGywqXnD8Lc8JIn9aBpnsfWz5zCkjov7JfTdbgDMqDsJr/BppsnSMDcn2pIXOms
c1fvamJVXLGG8ZOt0ru8K11U/UHTfH0HHAEcyl6jUd3NQ+pYtcabNrNP4job5289
EC16W45J73W3FziJ6oZN6A5NPV0hdVUxYCBp8IQMYPPSkNt70ekjpF6r4QDSzM/A
Y3ClEoevpZmNZjm/5eZwVl4t5+tzZUW07o7muzH1AFgkz4DMnj0CIajsBDd+LSXf
x1Fs41V87FRArETznHUZN0mpUtHYOe5EK5gStQIDAQABAoIBABvc0HvvThCLnqtK
UW5cey7D45/+CqkroqsJO4Ca6qrp2p8o6W7X7BNkXbgwsUOgs4qR2O6Rv1coRjdN
m06BZ/qaWHTVcqvNfN7JdbWkxjm7Gl/UcRO1uJgvSqgc/D1NN6AXTrSteMMKA0T7
Wr6b9toLXxF7DfgWNOX5zPzwq++OL3nLqSAbx0oKrUvMM93s/j2kIubRgSfTrfHU
+SZz5sA3C5PuiE13lxs0wKlAfLWK/Jdfzu6WO5dHWzDYNzkRkdtoaie3j2s5ECPB
7xfJDwmuLvxL90NVi/zPyZncnGXkHQiyHJRfLNNODU1MinAoGcRRmwbjM44bSj80
+MbHTX0CgYEA8Cb4HxJmYxD5+MEZ+PA8RKzQNKbc/sCI6nqKNoY3lQ2qottR22Q3
+yhhzBvBN2lI/OYVMc2FhCJxbDwBh3U9k0A2LssDjt9hlaDQa6KrX+e4CfJpJPXK
061J/hiuWGpQvoJIhlDz5f1O9kPs650SzDbS+TJq3Cu6hqnzNBkJBccCgYEAzARt
DrQZzVJOyZajqQ8pqj6xqCkq3iKLj54QsFQZXUtxtreQMl1k/xkZHxR1DDMJlnY2
l1J1oOJFJv4Rnz/SX3CinEkB1Ph69wwtTR0yoYDvt71VNnHS9/4Tca2jco7cIBrv
qwRx8MNV54Kn5WT9IwMf5vY9sVjQa4yDeZS3c6MCgYEAhpigufF7Fwz9vRClOOOU
M71TmB7pf5Jzak+xxStmXZDiURJxB3Bc+9Q/M8Fegmrs8GkX+ejBazROs6XSCZSJ
JU140LMR1HKYY99U0O7D9CWP/WsyyPdFbWwTK2mz1XQIuy2T7kvS1tUo+1dIoylO
zsvvZKGASNPtX+pCl7FsYCMCgYBOyxrPhfE9Ih+5rYsxvOBrluEIQDYFKrRZ2EM7
xo8xP/UAC28OdJGQEEJqhX0bJA785FT7Jma1pw3sHE30AjMelyLGV0/0z662ASbx
1Gf8hg6PGPlzGIzRKHib++LXWKNdZunPU90pjld8HTL43oMBZbCJg+qZtuJv1wnk
B/K+HwKBgQCp6Gr/ruiZozXnPrC9T85HkvXfB99pDwJRBvNPMlfM8QV4dJ00MOW9
ac61aqL7YunsFNkTZZ3HudNIK3UASXO5NPaAuH9Gn8ONRt3xvzw4Dul4pRQI+pFt
VMoFggg9jXf5lMzD8PoP4mRoFct8fIZlCAEnt+5U94lUr8EXsKY0Kg==
-----END RSA PRIVATE KEY-----";

    const TEST_PUBLIC_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv2M0owXgR/QsS+f6b/Bf
LZ2XnzyF0JHaIcBetglfHQTYEzLqVyGywqXnD8Lc8JIn9aBpnsfWz5zCkjov7JfT
dbgDMqDsJr/BppsnSMDcn2pIXOmsc1fvamJVXLGG8ZOt0ru8K11U/UHTfH0HHAEc
yl6jUd3NQ+pYtcabNrNP4job5289EC16W45J73W3FziJ6oZN6A5NPV0hdVUxYCBp
8IQMYPPSkNt70ekjpF6r4QDSzM/AY3ClEoevpZmNZjm/5eZwVl4t5+tzZUW07o7m
uzH1AFgkz4DMnj0CIajsBDd+LSXfx1Fs41V87FRArETznHUZN0mpUtHYOe5EK5gS
tQIDAQAB
-----END PUBLIC KEY-----";

    fn test_app() -> AppCredentials {
        AppCredentials { app_id: 123456, private_key_pem: TEST_PRIVATE_KEY_PEM.to_string() }
    }

    #[test]
    fn jwt_signs_and_verifies_with_the_matching_public_key() {
        let app = test_app();
        let now = Utc::now();
        let jwt = mint_jwt(&app, now).unwrap();

        let key = jsonwebtoken::DecodingKey::from_rsa_pem(TEST_PUBLIC_KEY_PEM.as_bytes()).unwrap();
        let mut validation = jsonwebtoken::Validation::new(Algorithm::RS256);
        validation.set_required_spec_claims(&["iat", "exp", "iss"]);
        let decoded = jsonwebtoken::decode::<Claims>(&jwt, &key, &validation).unwrap();

        assert_eq!(decoded.claims.iss, "123456");
        assert!(decoded.claims.exp > decoded.claims.iat);
        assert_eq!(decoded.claims.exp - decoded.claims.iat, 9 * 60 + 60);
    }

    #[test]
    fn jwt_exp_stays_under_githubs_ten_minute_limit() {
        let now = Utc::now();
        let jwt = mint_jwt(&test_app(), now).unwrap();
        let key = jsonwebtoken::DecodingKey::from_rsa_pem(TEST_PUBLIC_KEY_PEM.as_bytes()).unwrap();
        let mut validation = jsonwebtoken::Validation::new(Algorithm::RS256);
        validation.set_required_spec_claims(&["iat", "exp", "iss"]);
        let decoded = jsonwebtoken::decode::<Claims>(&jwt, &key, &validation).unwrap();
        assert!(decoded.claims.exp - now.timestamp() < 600);
    }

    fn perms(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn exact_match_is_not_scope_creep() {
        let requested = perms(&[("contents", "read")]);
        let granted = perms(&[("contents", "read")]);
        assert!(verify_no_scope_creep(&requested, &granted).is_ok());
    }

    #[test]
    fn narrower_than_requested_is_not_scope_creep() {
        let requested = perms(&[("contents", "write")]);
        let granted = perms(&[("contents", "read")]);
        assert!(verify_no_scope_creep(&requested, &granted).is_ok());
    }

    #[test]
    fn a_missing_requested_permission_is_not_scope_creep() {
        let requested = perms(&[("contents", "read"), ("issues", "read")]);
        let granted = perms(&[("contents", "read")]);
        assert!(verify_no_scope_creep(&requested, &granted).is_ok());
    }

    #[test]
    fn a_higher_level_than_requested_is_scope_creep() {
        let requested = perms(&[("contents", "read")]);
        let granted = perms(&[("contents", "write")]);
        assert!(matches!(
            verify_no_scope_creep(&requested, &granted),
            Err(GithubError::ScopeCreep { .. })
        ));
    }

    #[test]
    fn a_permission_not_requested_at_all_is_scope_creep() {
        let requested = perms(&[("contents", "read")]);
        let granted = perms(&[("contents", "read"), ("administration", "write")]);
        assert!(matches!(
            verify_no_scope_creep(&requested, &granted),
            Err(GithubError::ScopeCreep { .. })
        ));
    }

    #[test]
    fn an_unrecognized_granted_level_fails_closed() {
        let requested = perms(&[("contents", "admin")]);
        let granted = perms(&[("contents", "admin")]);
        assert!(matches!(
            verify_no_scope_creep(&requested, &granted),
            Err(GithubError::UnrecognizedPermission(_))
        ));
    }

    #[test]
    fn minted_token_scores_its_tier_from_what_was_actually_granted() {
        let resp = InstallationTokenResponse {
            token: "ghs_test".to_string(),
            expires_at: Utc::now() + Duration::hours(1),
            permissions: perms(&[("contents", "read")]),
        };
        let minted = MintedToken::from_response(resp);
        assert_eq!(minted.scope_string, "contents:read");
        assert_eq!(minted.tier, Tier::Tier0);
    }
}
