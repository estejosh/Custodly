//! [`custodly_core::ProviderAdapter`] for Codeberg/Forgejo.
//!
//! Confirmed 25 Sep 2026 (`forgejo/forgejo#11504`, `codeberg.org`, plus
//! Gitea/Forgejo's longstanding token-auth restriction,
//! `go-gitea/gitea#21186`):
//! - `POST /api/v1/users/{username}/tokens` creates a token and requires
//!   HTTP **basic auth** (the account's own username+password) -- NOT
//!   token auth, specifically to stop a token from minting more tokens.
//!   [`ParentCredential::secret`] here is therefore `"username:password"`,
//!   not a bearer token.
//! - A repo-scoped token can only carry the scopes `read:issue`,
//!   `write:issue`, `read:repository`, `write:repository` (the PR's own
//!   validation rule) -- never anything account-level.
//! - `DELETE /api/v1/users/{username}/tokens/{id}` revokes by numeric id.
//! - The response includes a `repositories` field: `null` means "every
//!   repo the account can see" (i.e. NOT scoped), a populated array means
//!   restricted to those repos.
//!
//! NOT confirmed against a live account this session (no Codeberg
//! account was available to test against -- see the Phase 1 report):
//! - The exact request-body field name for repo scoping. Assumed to be
//!   `repositories`, matching the response schema the PR's own
//!   discussion documents -- but never round-tripped against a real
//!   server.
//! - Whether `DELETE .../tokens/{id}` accepts the same basic-auth-only
//!   restriction as create, or something looser. Gitea's docs read as
//!   "Basic Authentication only" for the whole `tokens` family, not just
//!   create, which is the more conservative (safer) reading -- and the
//!   one this adapter goes with, so [`CodebergAdapter::revoke`] sends
//!   basic auth too.
//!
//! `revoke` needing the same account basic-auth as `mint` is exactly why
//! `custodly_core::ProviderAdapter::revoke` grew a `parent` argument
//! (25 Sep 2026, after this adapter and the OpenRouter one both hit the
//! same wall) -- without it there was no way to call this honestly at
//! all. Whatever fires this for real (the n8n reaper, not yet built) has
//! to fetch `parent` fresh from the vault at fire time, same as a mint,
//! never hold it across calls itself.

use async_trait::async_trait;
use chrono::Utc;
use custodly_core::{
    AdapterError, ChildRef, CredentialRequest, MintedChild, ParentCredential, ProviderAdapter,
    ProviderCapabilities, ScopeAssessment, assess_codeberg_scope,
};
use serde::{Deserialize, Serialize};

const ALLOWED_SCOPES: [&str; 4] = ["read:issue", "write:issue", "read:repository", "write:repository"];

/// One adapter instance per repo, same reasoning as `custodly-github`'s
/// adapter.
pub struct CodebergAdapter {
    /// No trailing slash -- `"https://codeberg.org"` for Codeberg itself,
    /// or a self-hosted Forgejo instance's base URL.
    base_url: String,
    /// The one repo (just the repo name -- Forgejo scopes a user's own
    /// tokens to repos reachable from that same account, not `owner/repo`)
    /// this instance will ever mint for.
    resource: String,
    client: reqwest::Client,
}

impl CodebergAdapter {
    #[must_use]
    pub fn new(base_url: impl Into<String>, resource: impl Into<String>, client: reqwest::Client) -> Self {
        Self { base_url: base_url.into(), resource: resource.into(), client }
    }
}

#[derive(Serialize)]
struct CreateTokenRequest {
    name: String,
    scopes: Vec<String>,
    repositories: Vec<String>,
}

#[derive(Deserialize)]
struct CreateTokenResponse {
    id: u64,
    sha1: String,
    #[serde(default)]
    repositories: Option<Vec<String>>,
}

#[async_trait]
impl ProviderAdapter for CodebergAdapter {
    fn provider(&self) -> &str {
        "codeberg"
    }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            resource_scoping: true,
            action_scoping: true,
            native_expiry: false,
            native_budget: false,
            api_create: true,
            api_revoke: true,
        }
    }

    async fn mint(&self, parent: &ParentCredential, request: &CredentialRequest) -> Result<MintedChild, AdapterError> {
        if request.provider != self.provider() {
            return Err(AdapterError::Unsupported(format!(
                "this adapter mints codeberg credentials, not {:?}",
                request.provider
            )));
        }
        if request.resource != self.resource {
            return Err(AdapterError::Unsupported(format!(
                "this adapter is scoped to {:?}, not {:?} -- one CodebergAdapter per repo, by design",
                self.resource, request.resource
            )));
        }

        let (username, password) = parent.secret.split_once(':').ok_or_else(|| {
            AdapterError::Rejected(
                "parent credential must be \"username:password\" for Codeberg/Forgejo -- token \
                 auth cannot mint tokens (go-gitea/gitea#21186)"
                    .to_string(),
            )
        })?;

        let mut scopes = Vec::new();
        for action in &request.actions {
            if !ALLOWED_SCOPES.contains(&action.as_str()) {
                return Err(AdapterError::Rejected(format!(
                    "action {action:?} isn't one of the scopes a repo-scoped Codeberg token can \
                     carry ({ALLOWED_SCOPES:?}, per forgejo/forgejo#11504)"
                )));
            }
            scopes.push(action.clone());
        }

        let url = format!("{}/api/v1/users/{}/tokens", self.base_url, username);
        let body = CreateTokenRequest {
            name: format!("custodly-{}-{}", request.requester, Utc::now().timestamp()),
            scopes: scopes.clone(),
            repositories: vec![self.resource.clone()],
        };

        let response = self
            .client
            .post(&url)
            .basic_auth(username, Some(password))
            .json(&body)
            .send()
            .await
            .map_err(|e| AdapterError::Http(e.to_string()))?;

        let status = response.status();
        if !status.is_success() {
            let text = response.text().await.unwrap_or_default();
            return Err(AdapterError::Rejected(format!("codeberg returned {status}: {text}")));
        }
        let parsed: CreateTokenResponse =
            response.json().await.map_err(|e| AdapterError::Unverifiable(e.to_string()))?;

        // `null`/absent `repositories` means "every repo this account can
        // see" per the confirmed response schema -- the opposite of
        // scoped. A populated array that isn't exactly this one repo is
        // scope creep. Either way, refuse to hand back a token that
        // isn't confirmed narrow, same instinct as GitHub's quarantine.
        match &parsed.repositories {
            Some(granted) if granted.as_slice() == [self.resource.clone()] => {}
            Some(granted) => {
                return Err(AdapterError::ScopeCreep(format!(
                    "requested repositories [{:?}], codeberg granted {granted:?}",
                    self.resource
                )));
            }
            None => {
                return Err(AdapterError::ScopeCreep(
                    "codeberg did not confirm a repository restriction on the minted token -- \
                     refusing an apparently-unscoped token"
                        .to_string(),
                ));
            }
        }

        Ok(MintedChild {
            secret: parsed.sha1,
            granted_resource: self.resource.clone(),
            granted_actions: scopes,
            // No native expiry -- see `capabilities()`. A ttl is still
            // enforced by whatever fires the (not-yet-built) reaper.
            expires_at: None,
            provider_ref: Some(parsed.id.to_string()),
        })
    }

    async fn verify(&self, minted: &MintedChild, request: &CredentialRequest) -> Result<ScopeAssessment, AdapterError> {
        if minted.granted_resource != request.resource {
            return Err(AdapterError::ScopeCreep(format!(
                "minted child is scoped to {:?}, request asked for {:?}",
                minted.granted_resource, request.resource
            )));
        }
        let scope_string = minted.granted_actions.join(",");
        assess_codeberg_scope(&scope_string)
            .ok_or_else(|| AdapterError::Unverifiable(format!("couldn't score granted scope {scope_string:?}")))
    }

    async fn revoke(&self, parent: &ParentCredential, child: &ChildRef) -> Result<(), AdapterError> {
        let (username, password) = parent.secret.split_once(':').ok_or_else(|| {
            AdapterError::Rejected(
                "parent credential must be \"username:password\" for Codeberg/Forgejo revoke, same as mint"
                    .to_string(),
            )
        })?;
        let url = format!("{}/api/v1/users/{}/tokens/{}", self.base_url, username, child.provider_ref);
        let response = self
            .client
            .delete(&url)
            .basic_auth(username, Some(password))
            .send()
            .await
            .map_err(|e| AdapterError::Http(e.to_string()))?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(AdapterError::Rejected(format!("codeberg refused the revoke: {}", response.status())))
        }
    }
}

#[cfg(test)]
mod tests {
    use custodly_core::{CredentialRequest, ProviderAdapter as _, Strategy};

    use super::*;

    fn adapter() -> CodebergAdapter {
        CodebergAdapter::new("https://codeberg.org", "estejosh/custodly-test", reqwest::Client::new())
    }

    #[test]
    fn declares_capabilities_that_pick_native_child_with_reaper() {
        assert_eq!(adapter().strategy(), Strategy::NativeChildWithReaper);
    }

    #[tokio::test]
    async fn mint_refuses_a_resource_this_adapter_isnt_scoped_to_before_any_network_call() {
        let request = CredentialRequest::new(
            "codeberg",
            "someone-else/other-repo",
            vec!["read:repository".to_string()],
            3600,
            None,
            "test",
        )
        .unwrap();
        let parent = ParentCredential { secret: "alice:hunter2".to_string() };
        let err = adapter().mint(&parent, &request).await.unwrap_err();
        assert!(matches!(err, AdapterError::Unsupported(_)));
    }

    #[tokio::test]
    async fn mint_refuses_a_request_for_a_different_provider() {
        let request = CredentialRequest::new(
            "github",
            "estejosh/custodly-test",
            vec!["read:repository".to_string()],
            3600,
            None,
            "test",
        )
        .unwrap();
        let parent = ParentCredential { secret: "alice:hunter2".to_string() };
        let err = adapter().mint(&parent, &request).await.unwrap_err();
        assert!(matches!(err, AdapterError::Unsupported(_)));
    }

    #[tokio::test]
    async fn mint_refuses_a_parent_credential_without_a_colon_before_any_network_call() {
        let request = CredentialRequest::new(
            "codeberg",
            "estejosh/custodly-test",
            vec!["read:repository".to_string()],
            3600,
            None,
            "test",
        )
        .unwrap();
        let parent = ParentCredential { secret: "not-username-colon-password".to_string() };
        let err = adapter().mint(&parent, &request).await.unwrap_err();
        assert!(matches!(err, AdapterError::Rejected(_)));
    }

    #[tokio::test]
    async fn mint_refuses_an_action_outside_the_repo_scoped_token_vocabulary() {
        let request = CredentialRequest::new(
            "codeberg",
            "estejosh/custodly-test",
            vec!["write:organization".to_string()],
            3600,
            None,
            "test",
        )
        .unwrap();
        let parent = ParentCredential { secret: "alice:hunter2".to_string() };
        let err = adapter().mint(&parent, &request).await.unwrap_err();
        assert!(matches!(err, AdapterError::Rejected(_)));
    }

    #[tokio::test]
    async fn verify_catches_resource_level_creep() {
        let request = CredentialRequest::new(
            "codeberg",
            "estejosh/custodly-test",
            vec!["read:repository".to_string()],
            3600,
            None,
            "test",
        )
        .unwrap();
        let minted = MintedChild {
            secret: "tok".to_string(),
            granted_resource: "someone-else/other-repo".to_string(),
            granted_actions: vec!["read:repository".to_string()],
            expires_at: None,
            provider_ref: Some("1".to_string()),
        };
        let err = adapter().verify(&minted, &request).await.unwrap_err();
        assert!(matches!(err, AdapterError::ScopeCreep(_)));
    }

    #[tokio::test]
    async fn verify_accepts_a_matching_read_only_grant_as_tier_0() {
        let request = CredentialRequest::new(
            "codeberg",
            "estejosh/custodly-test",
            vec!["read:repository".to_string()],
            3600,
            None,
            "test",
        )
        .unwrap();
        let minted = MintedChild {
            secret: "tok".to_string(),
            granted_resource: "estejosh/custodly-test".to_string(),
            granted_actions: vec!["read:repository".to_string()],
            expires_at: None,
            provider_ref: Some("1".to_string()),
        };
        let assessment = adapter().verify(&minted, &request).await.unwrap();
        assert_eq!(custodly_core::Tier::score(Some(&assessment)), custodly_core::Tier::Tier0);
    }

    #[tokio::test]
    async fn revoke_refuses_a_parent_credential_without_a_colon_before_any_network_call() {
        let parent = ParentCredential { secret: "not-username-colon-password".to_string() };
        let child = ChildRef { provider_ref: "1".to_string() };
        let err = adapter().revoke(&parent, &child).await.unwrap_err();
        assert!(matches!(err, AdapterError::Rejected(_)));
    }
}
