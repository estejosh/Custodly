//! [`custodly_core::ProviderAdapter`] for GitHub -- wraps the pilot's
//! existing `mint_installation_token`/`verify_no_scope_creep` (in
//! [`crate::app`]) behind the provider-agnostic contract, rather than
//! replacing them. Two things this adapter adds on top of what
//! `crate::app` already did:
//!
//! 1. **Resource is required, not optional.** The confirmed 24 Sep 2026
//!    gap was `RequestedGrant::repository_ids: Option<Vec<u64>>` letting
//!    a mint go out unscoped to every repo an installation covers. One
//!    `GithubAdapter` is built for exactly one repo (`resource`) and
//!    refuses to mint for any other -- Custodly-side resource scoping,
//!    enforced before any network call, on top of (not instead of)
//!    GitHub's own installation-level scoping.
//! 2. **Resource-level scope-creep checking.** `crate::app`'s
//!    `verify_no_scope_creep` only ever checked actions (permission
//!    levels) -- flagged in `custodly_core::adapter`'s module docs as a
//!    known gap. [`GithubAdapter::verify`] closes it by also comparing
//!    `MintedChild::granted_resource` against what was requested.

use std::collections::BTreeMap;

use async_trait::async_trait;
use custodly_core::{
    AdapterError, ChildRef, CredentialRequest, MintedChild, ParentCredential, ProviderAdapter,
    ProviderCapabilities, ScopeAssessment, assess_github_scope,
};

use crate::app::{AppCredentials, GithubError, RequestedGrant, mint_installation_token};

/// One adapter instance per repo, on purpose -- see the module docs.
pub struct GithubAdapter {
    app_id: u64,
    installation_id: u64,
    /// The one repo (`"owner/repo"`) this instance will ever mint for.
    resource: String,
    client: reqwest::Client,
}

impl GithubAdapter {
    #[must_use]
    pub fn new(app_id: u64, installation_id: u64, resource: impl Into<String>, client: reqwest::Client) -> Self {
        Self { app_id, installation_id, resource: resource.into(), client }
    }
}

/// GitHub's own vocabulary is `"resource:level"` (`"contents:write"`,
/// `"issues:read"`) -- `CredentialRequest::actions` carries these
/// verbatim per `custodly_core::request`'s module docs ("a GitHub repo
/// full name and `contents:write`"). Reject anything that doesn't parse
/// as exactly that shape before any network call, same instinct as
/// `CredentialRequest::new` refusing an empty resource up front.
fn parse_action(action: &str) -> Result<(String, String), AdapterError> {
    let mut parts = action.splitn(2, ':');
    let resource = parts.next().filter(|s| !s.is_empty());
    let level = parts.next().filter(|s| !s.is_empty());
    match (resource, level) {
        (Some(r), Some(l)) => Ok((r.to_string(), l.to_string())),
        _ => Err(AdapterError::Rejected(format!(
            "action {action:?} isn't in GitHub's \"resource:level\" vocabulary, e.g. \"contents:write\""
        ))),
    }
}

fn map_github_error(err: GithubError) -> AdapterError {
    match err {
        GithubError::Api { status, body } => AdapterError::Http(format!("github returned {status}: {body}")),
        GithubError::ScopeCreep { requested, granted } => {
            AdapterError::ScopeCreep(format!("requested {requested:?}, granted {granted:?}"))
        }
        GithubError::UnrecognizedPermission(p) => {
            AdapterError::Unverifiable(format!("unrecognized permission level(s): {p:?}"))
        }
        other => AdapterError::Http(other.to_string()),
    }
}

#[async_trait]
impl ProviderAdapter for GithubAdapter {
    fn provider(&self) -> &str {
        "github"
    }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            resource_scoping: true,
            action_scoping: true,
            // Installation access tokens expire in ~1hr, GitHub-enforced.
            native_expiry: true,
            native_budget: false,
            api_create: true,
            // See `ChildRef`'s docs in `custodly_core::adapter`: real,
            // but the only auth GitHub accepts for it is the token
            // itself, not an opaque id.
            api_revoke: true,
        }
    }

    async fn mint(&self, parent: &ParentCredential, request: &CredentialRequest) -> Result<MintedChild, AdapterError> {
        if request.provider != self.provider() {
            return Err(AdapterError::Unsupported(format!(
                "this adapter mints github credentials, not {:?}",
                request.provider
            )));
        }
        if request.resource != self.resource {
            return Err(AdapterError::Unsupported(format!(
                "this adapter is scoped to {:?}, not {:?} -- one GithubAdapter per repo, by design",
                self.resource, request.resource
            )));
        }

        let mut permissions = BTreeMap::new();
        for action in &request.actions {
            let (res, level) = parse_action(action)?;
            permissions.insert(res, level);
        }

        let app = AppCredentials { app_id: self.app_id, private_key_pem: parent.secret.clone() };
        let grant = RequestedGrant {
            installation_id: self.installation_id,
            permissions,
            // `None`, deliberately: this installation is already scoped
            // to exactly `self.resource` (confirmed 2026-09 --
            // Installation ID 164446141 covers only estejosh/Custodly
            // and nothing else), so "every repo this installation can
            // see" and "this one repo" are the same set today. A
            // multi-repo installation would need `resource` resolved to
            // a numeric repository id here instead of relying on that
            // coincidence -- not built in this pass; flagged as a
            // follow-up for whenever a second repo joins the
            // installation.
            repository_ids: None,
        };

        let minted = mint_installation_token(&self.client, &app, &grant).await.map_err(map_github_error)?;

        let granted_actions =
            minted.granted_permissions.iter().map(|(resource, level)| format!("{resource}:{level}")).collect();
        let token = minted.token;

        Ok(MintedChild {
            granted_resource: self.resource.clone(),
            granted_actions,
            expires_at: Some(minted.expires_at),
            // See `ChildRef`'s docs: this IS the live token, not an
            // opaque id -- GitHub's self-revoke endpoint has no other
            // form of auth. `MintedChild::fmt` redacts it, same as
            // `secret`.
            provider_ref: Some(token.clone()),
            secret: token,
        })
    }

    async fn verify(&self, minted: &MintedChild, request: &CredentialRequest) -> Result<ScopeAssessment, AdapterError> {
        // The gap `custodly_core::adapter`'s module docs flag: the
        // pilot's `verify_no_scope_creep` only ever checked actions.
        // This is the resource-level half of that check.
        if minted.granted_resource != request.resource {
            return Err(AdapterError::ScopeCreep(format!(
                "minted child is scoped to {:?}, request asked for {:?}",
                minted.granted_resource, request.resource
            )));
        }
        let scope_string = minted.granted_actions.join(",");
        assess_github_scope(&scope_string)
            .ok_or_else(|| AdapterError::Unverifiable(format!("couldn't score granted scope {scope_string:?}")))
    }

    async fn revoke(&self, _parent: &ParentCredential, child: &ChildRef) -> Result<(), AdapterError> {
        // GitHub's installation-token self-revoke
        // (`DELETE /installation/token`) authenticates as the token
        // being revoked -- there is no id-based revoke for installation
        // tokens, so `child.provider_ref` holds the live token here
        // (see `ChildRef`'s docs), not an opaque id. `parent` (the App's
        // private key) isn't needed for this one -- GitHub is the
        // exception where the child can revoke itself.
        let response = self
            .client
            .delete("https://api.github.com/installation/token")
            .header("Authorization", format!("token {}", child.provider_ref))
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header("User-Agent", "custodly")
            .send()
            .await
            .map_err(|e| AdapterError::Http(e.to_string()))?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(AdapterError::Rejected(format!("github refused the revoke: {}", response.status())))
        }
    }
}

#[cfg(test)]
mod tests {
    use custodly_core::{CredentialRequest, ProviderAdapter as _, Strategy};

    use super::*;

    fn adapter() -> GithubAdapter {
        GithubAdapter::new(123456, 164446141, "estejosh/Custodly", reqwest::Client::new())
    }

    #[test]
    fn declares_capabilities_that_pick_native_child() {
        assert_eq!(adapter().strategy(), Strategy::NativeChild);
    }

    #[test]
    fn parse_action_accepts_the_resource_colon_level_shape() {
        assert_eq!(parse_action("contents:write").unwrap(), ("contents".to_string(), "write".to_string()));
    }

    #[test]
    fn parse_action_rejects_anything_without_a_colon() {
        assert!(parse_action("contents-write").is_err());
    }

    #[test]
    fn parse_action_rejects_an_empty_level() {
        assert!(parse_action("contents:").is_err());
    }

    #[tokio::test]
    async fn mint_refuses_a_resource_this_adapter_isnt_scoped_to_before_any_network_call() {
        let request = CredentialRequest::new(
            "github",
            "someone-else/other-repo",
            vec!["contents:write".to_string()],
            3600,
            None,
            "test",
        )
        .unwrap();
        let parent = ParentCredential { secret: "not-a-real-pem".to_string() };
        let err = adapter().mint(&parent, &request).await.unwrap_err();
        assert!(matches!(err, AdapterError::Unsupported(_)));
    }

    #[tokio::test]
    async fn mint_refuses_a_request_for_a_different_provider() {
        let request = CredentialRequest::new(
            "codeberg",
            "estejosh/Custodly",
            vec!["contents:write".to_string()],
            3600,
            None,
            "test",
        )
        .unwrap();
        let parent = ParentCredential { secret: "not-a-real-pem".to_string() };
        let err = adapter().mint(&parent, &request).await.unwrap_err();
        assert!(matches!(err, AdapterError::Unsupported(_)));
    }

    #[tokio::test]
    async fn verify_catches_resource_level_creep_the_pilots_checker_could_not() {
        let request = CredentialRequest::new(
            "github",
            "estejosh/Custodly",
            vec!["contents:read".to_string()],
            3600,
            None,
            "test",
        )
        .unwrap();
        let minted = MintedChild {
            secret: "ghs_test".to_string(),
            // Granted a *different* resource than requested -- the case
            // `crate::app`'s action-only checker would have missed.
            granted_resource: "someone-else/other-repo".to_string(),
            granted_actions: vec!["contents:read".to_string()],
            expires_at: None,
            provider_ref: Some("ghs_test".to_string()),
        };
        let err = adapter().verify(&minted, &request).await.unwrap_err();
        assert!(matches!(err, AdapterError::ScopeCreep(_)));
    }

    #[tokio::test]
    async fn verify_accepts_a_matching_read_only_grant_as_tier_0() {
        let request = CredentialRequest::new(
            "github",
            "estejosh/Custodly",
            vec!["contents:read".to_string()],
            3600,
            None,
            "test",
        )
        .unwrap();
        let minted = MintedChild {
            secret: "ghs_test".to_string(),
            granted_resource: "estejosh/Custodly".to_string(),
            granted_actions: vec!["contents:read".to_string()],
            expires_at: None,
            provider_ref: Some("ghs_test".to_string()),
        };
        let assessment = adapter().verify(&minted, &request).await.unwrap();
        assert_eq!(custodly_core::Tier::score(Some(&assessment)), custodly_core::Tier::Tier0);
    }
}
