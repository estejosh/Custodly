//! The provider-agnostic request shape every adapter mints against:
//! `{owner, provider, resource, actions, ttl, budget?, requester}`. This
//! is the multi-provider restructure (25 Sep 2026, "Custodly is not a
//! GitHub tool") made a type: the core knows nothing provider-specific
//! here. `resource` and `actions` are opaque strings each adapter
//! interprets in its own vocabulary -- a GitHub repo full name and
//! `contents:write`, a Forgejo repo path and `write:repository`, an
//! OpenRouter account and a spend action. Validating those strings
//! against what a specific provider actually accepts is the adapter's
//! job, not this module's.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::entry::LOCAL_OWNER;

/// A spend cap, for providers that have one (OpenRouter, DeepSeek-if-it-
/// ever-gets-one). Always an integer in the provider's smallest unit
/// (cents, credits) -- never a float, so two adapters' rounding can't
/// silently drift apart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Budget {
    pub limit_minor_units: u64,
    pub currency: String,
}

/// Refuses to build a [`CredentialRequest`] missing what makes it
/// narrowable and refusable before any network call -- the whole point
/// of requiring `resource` and `ttl_seconds` up front. This is the fix
/// for the confirmed 24 Sep 2026 gap where GitHub's `--repository-id`
/// being optional let a mint request go out unscoped to every repo an
/// installation covers.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CredentialRequestError {
    #[error("owner must not be empty")]
    EmptyOwner,
    #[error("provider must not be empty")]
    EmptyProvider,
    #[error(
        "resource must not be empty -- a request with no resource can't be refused before a \
         network call the way docs/design-brief.md requires, and can't be narrowed by any \
         adapter strategy"
    )]
    EmptyResource,
    #[error("at least one action is required")]
    NoActions,
    #[error("requester must not be empty")]
    EmptyRequester,
    #[error("ttl_seconds must be greater than zero")]
    ZeroTtl,
}

/// One request for exactly one credential. Built only through
/// [`CredentialRequest::new`] (owned by [`LOCAL_OWNER`]) or
/// [`CredentialRequest::for_owner`] (multi-tenant) -- there is no way to
/// construct one with an empty `resource` or a zero `ttl_seconds`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialRequest {
    pub owner: String,
    pub provider: String,
    /// What this credential reaches -- a repo, an account, a project.
    /// Provider-specific vocabulary; the core never interprets it.
    pub resource: String,
    /// What it can do to `resource` -- provider-native action names
    /// (`"contents:write"`, `"write:repository"`). At least one required.
    pub actions: Vec<String>,
    pub ttl_seconds: u64,
    pub budget: Option<Budget>,
    /// Who's asking -- an agent id, a CLI invocation's identity. Used by
    /// the requester-can-only-touch-their-own-owner's-parents check
    /// (`custodly-core::adapter`), not validated against anything here.
    pub requester: String,
}

impl CredentialRequest {
    /// Build a request for [`LOCAL_OWNER`] ("josh") -- the common case
    /// today.
    pub fn new(
        provider: impl Into<String>,
        resource: impl Into<String>,
        actions: Vec<String>,
        ttl_seconds: u64,
        budget: Option<Budget>,
        requester: impl Into<String>,
    ) -> Result<Self, CredentialRequestError> {
        Self::for_owner(LOCAL_OWNER, provider, resource, actions, ttl_seconds, budget, requester)
    }

    /// Build a request for a specific owner -- the multi-tenant path.
    #[allow(clippy::too_many_arguments)]
    pub fn for_owner(
        owner: impl Into<String>,
        provider: impl Into<String>,
        resource: impl Into<String>,
        actions: Vec<String>,
        ttl_seconds: u64,
        budget: Option<Budget>,
        requester: impl Into<String>,
    ) -> Result<Self, CredentialRequestError> {
        let owner = owner.into();
        let provider = provider.into();
        let resource = resource.into();
        let requester = requester.into();
        if owner.trim().is_empty() {
            return Err(CredentialRequestError::EmptyOwner);
        }
        if provider.trim().is_empty() {
            return Err(CredentialRequestError::EmptyProvider);
        }
        if resource.trim().is_empty() {
            return Err(CredentialRequestError::EmptyResource);
        }
        if actions.is_empty() {
            return Err(CredentialRequestError::NoActions);
        }
        if requester.trim().is_empty() {
            return Err(CredentialRequestError::EmptyRequester);
        }
        if ttl_seconds == 0 {
            return Err(CredentialRequestError::ZeroTtl);
        }
        Ok(Self { owner, provider, resource, actions, ttl_seconds, budget, requester })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_request() -> Result<CredentialRequest, CredentialRequestError> {
        CredentialRequest::new(
            "github",
            "estejosh/Custodly",
            vec!["contents:write".to_string()],
            3600,
            None,
            "custodly-cli",
        )
    }

    #[test]
    fn a_well_formed_request_builds() {
        let req = ok_request().unwrap();
        assert_eq!(req.owner, LOCAL_OWNER);
        assert_eq!(req.resource, "estejosh/Custodly");
    }

    #[test]
    fn empty_resource_is_refused_before_any_network_call() {
        let err = CredentialRequest::new(
            "github", "", vec!["contents:write".to_string()], 3600, None, "custodly-cli",
        )
        .unwrap_err();
        assert_eq!(err, CredentialRequestError::EmptyResource);
    }

    #[test]
    fn zero_ttl_is_refused() {
        let err = CredentialRequest::new(
            "github", "estejosh/Custodly", vec!["contents:write".to_string()], 0, None, "custodly-cli",
        )
        .unwrap_err();
        assert_eq!(err, CredentialRequestError::ZeroTtl);
    }

    #[test]
    fn no_actions_is_refused() {
        let err = CredentialRequest::new(
            "github", "estejosh/Custodly", vec![], 3600, None, "custodly-cli",
        )
        .unwrap_err();
        assert_eq!(err, CredentialRequestError::NoActions);
    }

    #[test]
    fn empty_requester_is_refused() {
        let err = CredentialRequest::new(
            "github", "estejosh/Custodly", vec!["contents:write".to_string()], 3600, None, "",
        )
        .unwrap_err();
        assert_eq!(err, CredentialRequestError::EmptyRequester);
    }

    #[test]
    fn for_owner_rejects_an_empty_owner() {
        let err = CredentialRequest::for_owner(
            "", "github", "estejosh/Custodly", vec!["contents:write".to_string()], 3600, None, "custodly-cli",
        )
        .unwrap_err();
        assert_eq!(err, CredentialRequestError::EmptyOwner);
    }

    #[test]
    fn for_owner_sets_a_non_local_owner() {
        let req = CredentialRequest::for_owner(
            "acme", "github", "acme/widgets", vec!["contents:read".to_string()], 3600, None, "acme-agent",
        )
        .unwrap();
        assert_eq!(req.owner, "acme");
    }
}
