//! [`custodly_core::ProviderAdapter`] for OpenRouter's provisioning API.
//!
//! Confirmed 25 Sep 2026
//! (`openrouter.ai/docs/features/provisioning-api-keys` +
//! `openrouter.ai/docs/api-reference/api-keys/create-api-key`):
//! - `POST /api/v1/keys` creates a key, authenticated with a
//!   **management key** as a bearer token (a separate credential from an
//!   ordinary OpenRouter API key -- that management key IS
//!   [`ParentCredential::secret`] here).
//! - The request accepts `expires_at` (an ISO 8601 UTC timestamp) and
//!   `limit` (a USD spend cap) directly on creation.
//! - The response's top-level `key` field is the actual usable key
//!   (shown only once); `data.hash`, `data.limit`, and `data.expires_at`
//!   confirm what was actually granted.
//! - `DELETE /api/v1/keys/{hash}` revokes by hash, same bearer auth as
//!   create.
//! - There is **no resource or model scoping at all** -- a minted key
//!   reaches every model on the account. `limit` is the only thing that
//!   narrows anything.
//!
//! This corrects the prior session's read of this provider: because
//! `expires_at` turns out to be settable directly on create (not
//! confirmed before this session), this is actually strategy 1 (native
//! child) once a spend limit is required, not strategy 2 -- see
//! [`OpenRouterAdapter::capabilities`].
//!
//! Given there's no resource scoping, `CredentialRequest::resource` is
//! **not enforced by OpenRouter at all** -- it's a Custodly-side label
//! only (folded into the generated key's `name`, and checked against
//! what this adapter instance was built for, same as the other
//! adapters), not something the provider can confirm or refuse. The real
//! narrowing for this provider is entirely the spend limit, which is why
//! [`OpenRouterAdapter::mint`] refuses to mint at all without a
//! [`custodly_core::CredentialRequest::budget`] -- an uncapped OpenRouter
//! key reaches every model with no ceiling, which this adapter treats as
//! categorically unmintable, not merely undesirable.

use async_trait::async_trait;
use chrono::{Duration as ChronoDuration, SecondsFormat, Utc};
use custodly_core::{
    AdapterError, ChildRef, CredentialRequest, MintedChild, ParentCredential, ProviderAdapter,
    ProviderCapabilities, ScopeAssessment, assess_openrouter_scope,
};
use serde::{Deserialize, Serialize};

/// One adapter instance per resource label, same pattern as the other
/// adapters, even though OpenRouter itself never checks it -- see the
/// module docs.
pub struct OpenRouterAdapter {
    /// No trailing slash -- `"https://openrouter.ai"`.
    base_url: String,
    resource: String,
    client: reqwest::Client,
}

impl OpenRouterAdapter {
    #[must_use]
    pub fn new(base_url: impl Into<String>, resource: impl Into<String>, client: reqwest::Client) -> Self {
        Self { base_url: base_url.into(), resource: resource.into(), client }
    }
}

#[derive(Serialize)]
struct CreateKeyRequest {
    name: String,
    limit: f64,
    expires_at: String,
}

#[derive(Deserialize)]
struct CreateKeyResponseData {
    hash: String,
    limit: Option<f64>,
    expires_at: Option<chrono::DateTime<Utc>>,
}

#[derive(Deserialize)]
struct CreateKeyResponse {
    key: String,
    data: CreateKeyResponseData,
}

#[async_trait]
impl ProviderAdapter for OpenRouterAdapter {
    fn provider(&self) -> &str {
        "openrouter"
    }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            resource_scoping: false,
            action_scoping: false,
            native_expiry: true,
            native_budget: true,
            api_create: true,
            api_revoke: true,
        }
    }

    async fn mint(&self, parent: &ParentCredential, request: &CredentialRequest) -> Result<MintedChild, AdapterError> {
        if request.provider != self.provider() {
            return Err(AdapterError::Unsupported(format!(
                "this adapter mints openrouter credentials, not {:?}",
                request.provider
            )));
        }
        if request.resource != self.resource {
            return Err(AdapterError::Unsupported(format!(
                "this adapter is scoped to the label {:?}, not {:?} -- note openrouter itself doesn't \
                 enforce this, see the module docs",
                self.resource, request.resource
            )));
        }
        let Some(budget) = &request.budget else {
            return Err(AdapterError::Rejected(
                "openrouter requires a budget -- Custodly never mints an uncapped OpenRouter key"
                    .to_string(),
            ));
        };
        if budget.currency != "USD" {
            return Err(AdapterError::Rejected(format!(
                "openrouter spend limits are USD only, not {:?}",
                budget.currency
            )));
        }

        let limit_usd = budget.limit_minor_units as f64 / 100.0;
        let expires_at = Utc::now() + ChronoDuration::seconds(request.ttl_seconds as i64);
        let body = CreateKeyRequest {
            name: format!("custodly-{}-{}-{}", request.owner, request.resource, Utc::now().timestamp()),
            limit: limit_usd,
            expires_at: expires_at.to_rfc3339_opts(SecondsFormat::Secs, true),
        };

        let url = format!("{}/api/v1/keys", self.base_url);
        let response = self
            .client
            .post(&url)
            .bearer_auth(&parent.secret)
            .json(&body)
            .send()
            .await
            .map_err(|e| AdapterError::Http(e.to_string()))?;

        let status = response.status();
        if !status.is_success() {
            let text = response.text().await.unwrap_or_default();
            return Err(AdapterError::Rejected(format!("openrouter returned {status}: {text}")));
        }
        let parsed: CreateKeyResponse =
            response.json().await.map_err(|e| AdapterError::Unverifiable(e.to_string()))?;

        let granted_limit = match parsed.data.limit {
            Some(l) if l > 0.0 && l <= limit_usd => l,
            other => {
                return Err(AdapterError::ScopeCreep(format!(
                    "requested spend limit {limit_usd:.2}, openrouter granted {other:?}"
                )));
            }
        };
        let Some(granted_expires) = parsed.data.expires_at else {
            return Err(AdapterError::ScopeCreep(
                "openrouter did not confirm an expiry on the minted key -- refusing an apparently \
                 unbounded-lifetime key"
                    .to_string(),
            ));
        };

        Ok(MintedChild {
            secret: parsed.key,
            granted_resource: self.resource.clone(),
            // No action scoping exists for this provider -- this slot
            // instead records the one thing that actually got confirmed
            // narrow, the granted spend limit. `verify` reads it back
            // out; see its doc comment.
            granted_actions: vec![format!("limit_usd:{granted_limit:.2}")],
            expires_at: Some(granted_expires),
            provider_ref: Some(parsed.data.hash),
        })
    }

    async fn verify(&self, minted: &MintedChild, request: &CredentialRequest) -> Result<ScopeAssessment, AdapterError> {
        if minted.granted_resource != request.resource {
            return Err(AdapterError::ScopeCreep(format!(
                "minted child is labeled {:?}, request asked for {:?}",
                minted.granted_resource, request.resource
            )));
        }
        let Some(budget) = &request.budget else {
            return Err(AdapterError::Unverifiable("no budget on the request to verify against".to_string()));
        };
        let requested_limit = budget.limit_minor_units as f64 / 100.0;
        let granted_limit = minted
            .granted_actions
            .iter()
            .find_map(|a| a.strip_prefix("limit_usd:").and_then(|s| s.parse::<f64>().ok()));
        assess_openrouter_scope(requested_limit, granted_limit).ok_or_else(|| {
            AdapterError::Unverifiable(format!(
                "couldn't confirm the granted spend limit against requested {requested_limit:.2}"
            ))
        })
    }

    async fn revoke(&self, parent: &ParentCredential, child: &ChildRef) -> Result<(), AdapterError> {
        let url = format!("{}/api/v1/keys/{}", self.base_url, child.provider_ref);
        let response = self
            .client
            .delete(&url)
            .bearer_auth(&parent.secret)
            .send()
            .await
            .map_err(|e| AdapterError::Http(e.to_string()))?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(AdapterError::Rejected(format!("openrouter refused the revoke: {}", response.status())))
        }
    }
}

#[cfg(test)]
mod tests {
    use custodly_core::{Budget, CredentialRequest, ProviderAdapter as _, Strategy};

    use super::*;

    fn adapter() -> OpenRouterAdapter {
        OpenRouterAdapter::new("https://openrouter.ai", "custodly-agent-pool", reqwest::Client::new())
    }

    fn usd(dollars: u64) -> Budget {
        Budget { limit_minor_units: dollars * 100, currency: "USD".to_string() }
    }

    #[test]
    fn declares_capabilities_that_pick_native_child() {
        // Corrects the prior session's assumption -- expires_at turns
        // out to be settable on create, so this isn't strategy 2.
        assert_eq!(adapter().strategy(), Strategy::NativeChild);
    }

    #[tokio::test]
    async fn mint_refuses_a_request_for_a_different_provider() {
        let request = CredentialRequest::new(
            "github",
            "custodly-agent-pool",
            vec!["chat:use".to_string()],
            3600,
            Some(usd(5)),
            "test",
        )
        .unwrap();
        let parent = ParentCredential { secret: "sk-or-v1-mgmt-test".to_string() };
        let err = adapter().mint(&parent, &request).await.unwrap_err();
        assert!(matches!(err, AdapterError::Unsupported(_)));
    }

    #[tokio::test]
    async fn mint_refuses_a_mismatched_resource_label_before_any_network_call() {
        let request = CredentialRequest::new(
            "openrouter",
            "some-other-label",
            vec!["chat:use".to_string()],
            3600,
            Some(usd(5)),
            "test",
        )
        .unwrap();
        let parent = ParentCredential { secret: "sk-or-v1-mgmt-test".to_string() };
        let err = adapter().mint(&parent, &request).await.unwrap_err();
        assert!(matches!(err, AdapterError::Unsupported(_)));
    }

    #[tokio::test]
    async fn mint_refuses_a_request_with_no_budget_before_any_network_call() {
        let request = CredentialRequest::new(
            "openrouter",
            "custodly-agent-pool",
            vec!["chat:use".to_string()],
            3600,
            None,
            "test",
        )
        .unwrap();
        let parent = ParentCredential { secret: "sk-or-v1-mgmt-test".to_string() };
        let err = adapter().mint(&parent, &request).await.unwrap_err();
        assert!(matches!(err, AdapterError::Rejected(_)));
    }

    #[tokio::test]
    async fn mint_refuses_a_non_usd_budget_before_any_network_call() {
        let request = CredentialRequest::new(
            "openrouter",
            "custodly-agent-pool",
            vec!["chat:use".to_string()],
            3600,
            Some(Budget { limit_minor_units: 500, currency: "EUR".to_string() }),
            "test",
        )
        .unwrap();
        let parent = ParentCredential { secret: "sk-or-v1-mgmt-test".to_string() };
        let err = adapter().mint(&parent, &request).await.unwrap_err();
        assert!(matches!(err, AdapterError::Rejected(_)));
    }

    #[tokio::test]
    async fn verify_catches_a_resource_label_mismatch() {
        let request = CredentialRequest::new(
            "openrouter",
            "custodly-agent-pool",
            vec!["chat:use".to_string()],
            3600,
            Some(usd(5)),
            "test",
        )
        .unwrap();
        let minted = MintedChild {
            secret: "sk-or-v1-child".to_string(),
            granted_resource: "some-other-label".to_string(),
            granted_actions: vec!["limit_usd:5.00".to_string()],
            expires_at: None,
            provider_ref: Some("hash123".to_string()),
        };
        let err = adapter().verify(&minted, &request).await.unwrap_err();
        assert!(matches!(err, AdapterError::ScopeCreep(_)));
    }

    #[tokio::test]
    async fn verify_a_matching_capped_grant_is_still_tier_2() {
        let request = CredentialRequest::new(
            "openrouter",
            "custodly-agent-pool",
            vec!["chat:use".to_string()],
            3600,
            Some(usd(5)),
            "test",
        )
        .unwrap();
        let minted = MintedChild {
            secret: "sk-or-v1-child".to_string(),
            granted_resource: "custodly-agent-pool".to_string(),
            granted_actions: vec!["limit_usd:5.00".to_string()],
            expires_at: None,
            provider_ref: Some("hash123".to_string()),
        };
        let assessment = adapter().verify(&minted, &request).await.unwrap();
        assert_eq!(custodly_core::Tier::score(Some(&assessment)), custodly_core::Tier::Tier2);
    }

    #[tokio::test]
    async fn verify_a_looser_grant_than_requested_is_unverifiable() {
        let request = CredentialRequest::new(
            "openrouter",
            "custodly-agent-pool",
            vec!["chat:use".to_string()],
            3600,
            Some(usd(5)),
            "test",
        )
        .unwrap();
        let minted = MintedChild {
            secret: "sk-or-v1-child".to_string(),
            granted_resource: "custodly-agent-pool".to_string(),
            granted_actions: vec!["limit_usd:50.00".to_string()],
            expires_at: None,
            provider_ref: Some("hash123".to_string()),
        };
        let err = adapter().verify(&minted, &request).await.unwrap_err();
        assert!(matches!(err, AdapterError::Unverifiable(_)));
    }
}
