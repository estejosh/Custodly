//! [`custodly_core::ProviderAdapter`] for DeepSeek -- strategy 3
//! (broker), the one `custodly_core::adapter`'s module docs describe as
//! covering only "mint/verify/revoke of the proxy relationship's
//! record"; actually proxying live traffic is a running service, out of
//! scope for a trait method.
//!
//! **Confirmed 25 Sep 2026: DeepSeek has no key-management API at all.**
//! Dashboard-only key creation, nothing to call, nothing to scope,
//! nothing to revoke by API. `capabilities().api_create` is honestly
//! `false`, which is what forces `pick_strategy` to `Broker` regardless
//! of anything else -- there is no "narrower DeepSeek key" to mint in
//! the first place, so the real parent key (a single long-lived
//! dashboard-issued key) must never leave Custodly at all.
//!
//! **What this adapter actually does**: it does NOT talk to DeepSeek.
//! It talks to a small admin API this module defines --
//! `POST {proxy_base_url}/v1/grants` / `DELETE {proxy_base_url}/v1/grants/{id}`
//! -- against a **proxy service that does not exist yet**. That service
//! is meant to be the thing a caller's DeepSeek API traffic actually
//! flows through: it would hold the one real DeepSeek key, accept
//! requests bearing a `MintedChild::secret` (a Custodly-issued proxy
//! token, never the real key), check that token against the grant this
//! adapter recorded (resource label, ttl, budget), and only then forward
//! to DeepSeek with the real key injected server-side.
//!
//! **This is a real, unresolved design/deployment decision, not a detail
//! to guess at**: where does that proxy service run (a new small axum
//! service next to `custodly-core::server`'s existing policy endpoint?
//! an n8n workflow? something on Ferryman, despite the "don't touch
//! Ferryman" rule -- which would need Josh's explicit sign-off to even
//! discuss)? How does it get the real DeepSeek key without it ever being
//! printed or logged? How does a caller's completion traffic actually
//! reach it -- does every DeepSeek-calling agent get pointed at a new
//! base URL? None of that is decided here. This crate defines the grant
//! record contract so the adapter and the (future) proxy service can be
//! built against an agreed interface independently, and it makes the
//! DeepSeek half of Phase 1 testable now -- but calling `mint` against a
//! real `proxy_base_url` today will fail, because nothing is listening.
//!
//! `financial_exposure` is unconditionally `CanMoveMoney` in `verify` --
//! every DeepSeek completion spends real money on the one account behind
//! the broker, a cap only bounds it, and there is no external confirmation
//! path at all (the whole reason this is Broker), so every DeepSeek grant
//! is Tier 2, always, no exceptions.

use async_trait::async_trait;
use chrono::{Duration as ChronoDuration, SecondsFormat, Utc};
use custodly_core::{
    AdapterError, BlastRadius, ChildRef, CredentialRequest, Enforcement, FinancialExposure, MintedChild,
    ParentCredential, ProviderAdapter, ProviderCapabilities, Reversibility, ScopeAssessment,
};
use serde::{Deserialize, Serialize};

/// One adapter instance per resource label, same as the other adapters
/// -- DeepSeek itself doesn't check it (there's nothing to check it
/// against), but a not-yet-built proxy service could enforce it later.
pub struct DeepSeekAdapter {
    /// No trailing slash. Base URL of the (not yet built) proxy admin
    /// API -- see the module docs.
    proxy_base_url: String,
    /// Custodly's own credential for talking to its own proxy service,
    /// separate from the real DeepSeek key (`ParentCredential::secret`).
    proxy_admin_token: String,
    resource: String,
    client: reqwest::Client,
}

impl DeepSeekAdapter {
    #[must_use]
    pub fn new(
        proxy_base_url: impl Into<String>,
        proxy_admin_token: impl Into<String>,
        resource: impl Into<String>,
        client: reqwest::Client,
    ) -> Self {
        Self {
            proxy_base_url: proxy_base_url.into(),
            proxy_admin_token: proxy_admin_token.into(),
            resource: resource.into(),
            client,
        }
    }
}

#[derive(Serialize)]
struct CreateGrantRequest {
    real_key: String,
    resource: String,
    actions: Vec<String>,
    expires_at: String,
    budget_usd: Option<f64>,
}

#[derive(Deserialize)]
struct CreateGrantResponse {
    proxy_token: String,
    grant_id: String,
}

#[async_trait]
impl ProviderAdapter for DeepSeekAdapter {
    fn provider(&self) -> &str {
        "deepseek"
    }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            // All false: this describes DeepSeek's own API, which has
            // none of this. `api_create: false` alone is what forces
            // `pick_strategy` to `Broker` -- see the module docs.
            resource_scoping: false,
            action_scoping: false,
            native_expiry: false,
            native_budget: false,
            api_create: false,
            api_revoke: false,
        }
    }

    async fn mint(&self, parent: &ParentCredential, request: &CredentialRequest) -> Result<MintedChild, AdapterError> {
        if request.provider != self.provider() {
            return Err(AdapterError::Unsupported(format!(
                "this adapter mints deepseek broker grants, not {:?}",
                request.provider
            )));
        }
        if request.resource != self.resource {
            return Err(AdapterError::Unsupported(format!(
                "this adapter is scoped to the label {:?}, not {:?}",
                self.resource, request.resource
            )));
        }

        let Some(budget) = &request.budget else {
            return Err(AdapterError::Rejected(
                "deepseek broker grants require a budget -- Custodly never mints an uncapped \
                 spend-capable proxy token, same reasoning as the OpenRouter adapter"
                    .to_string(),
            ));
        };
        if budget.currency != "USD" {
            return Err(AdapterError::Rejected(format!(
                "deepseek broker grants are budgeted in USD only, not {:?}",
                budget.currency
            )));
        }
        let budget_usd = budget.limit_minor_units as f64 / 100.0;
        let expires_at = Utc::now() + ChronoDuration::seconds(request.ttl_seconds as i64);

        let body = CreateGrantRequest {
            real_key: parent.secret.clone(),
            resource: request.resource.clone(),
            actions: request.actions.clone(),
            expires_at: expires_at.to_rfc3339_opts(SecondsFormat::Secs, true),
            budget_usd: Some(budget_usd),
        };

        let url = format!("{}/v1/grants", self.proxy_base_url);
        let response = self
            .client
            .post(&url)
            .bearer_auth(&self.proxy_admin_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| AdapterError::Http(format!("proxy grant service unreachable: {e}")))?;

        let status = response.status();
        if !status.is_success() {
            let text = response.text().await.unwrap_or_default();
            return Err(AdapterError::Rejected(format!("proxy grant service returned {status}: {text}")));
        }
        let parsed: CreateGrantResponse =
            response.json().await.map_err(|e| AdapterError::Unverifiable(e.to_string()))?;

        Ok(MintedChild {
            // The Custodly-issued proxy token -- NEVER the real DeepSeek
            // key, which stays server-side at the proxy. This is the
            // entire point of Broker strategy.
            secret: parsed.proxy_token,
            granted_resource: request.resource.clone(),
            granted_actions: request.actions.clone(),
            expires_at: Some(expires_at),
            provider_ref: Some(parsed.grant_id),
        })
    }

    async fn verify(&self, minted: &MintedChild, request: &CredentialRequest) -> Result<ScopeAssessment, AdapterError> {
        if minted.granted_resource != request.resource {
            return Err(AdapterError::ScopeCreep(format!(
                "minted grant is labeled {:?}, request asked for {:?}",
                minted.granted_resource, request.resource
            )));
        }
        if request.budget.is_none() {
            // Should be unreachable -- `mint` already refuses a
            // budget-less request -- but `verify` doesn't trust that
            // path was actually taken to build `request`.
            return Err(AdapterError::Unverifiable(
                "no budget on the request to verify against".to_string(),
            ));
        }
        // There is no external provider read-back to confirm this
        // against -- DeepSeek has no API at all, which is the entire
        // reason this is Broker. Custodly's own proxy-grant record IS
        // the ground truth for this token's scope, so "verified" here
        // means internally consistent with what was requested, not
        // externally confirmed. See the module docs for why
        // `financial_exposure` is unconditional.
        Ok(ScopeAssessment {
            reversibility: Reversibility::Reversible,
            blast_radius: BlastRadius::Own,
            financial_exposure: FinancialExposure::CanMoveMoney,
            read_only: false,
            enforcement: Enforcement::Verified,
        })
    }

    async fn revoke(&self, _parent: &ParentCredential, child: &ChildRef) -> Result<(), AdapterError> {
        // Broker revoke means dropping the proxy-grant record -- the
        // real DeepSeek key was never handed to the caller, so there's
        // nothing at DeepSeek itself to revoke. Only the proxy service's
        // own admin token is needed, not `parent`.
        let url = format!("{}/v1/grants/{}", self.proxy_base_url, child.provider_ref);
        let response = self
            .client
            .delete(&url)
            .bearer_auth(&self.proxy_admin_token)
            .send()
            .await
            .map_err(|e| AdapterError::Http(format!("proxy grant service unreachable: {e}")))?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(AdapterError::Rejected(format!("proxy grant service refused the revoke: {}", response.status())))
        }
    }
}

#[cfg(test)]
mod tests {
    use custodly_core::{Budget, CredentialRequest, ProviderAdapter as _, Strategy};

    use super::*;

    fn adapter() -> DeepSeekAdapter {
        DeepSeekAdapter::new(
            "https://proxy.internal.example",
            "proxy-admin-test-token",
            "custodly-agent-pool",
            reqwest::Client::new(),
        )
    }

    fn usd(dollars: u64) -> Budget {
        Budget { limit_minor_units: dollars * 100, currency: "USD".to_string() }
    }

    #[test]
    fn declares_capabilities_that_force_broker() {
        // api_create: false alone forces this, regardless of the other
        // fields -- matches `no_create_api_is_always_broker_regardless_of_other_capabilities`
        // in custodly-core::adapter.
        assert_eq!(adapter().strategy(), Strategy::Broker);
    }

    #[tokio::test]
    async fn mint_refuses_a_request_for_a_different_provider() {
        let request = CredentialRequest::new(
            "openrouter",
            "custodly-agent-pool",
            vec!["chat:use".to_string()],
            3600,
            Some(usd(5)),
            "test",
        )
        .unwrap();
        let parent = ParentCredential { secret: "sk-deepseek-test".to_string() };
        let err = adapter().mint(&parent, &request).await.unwrap_err();
        assert!(matches!(err, AdapterError::Unsupported(_)));
    }

    #[tokio::test]
    async fn mint_refuses_a_mismatched_resource_label_before_any_network_call() {
        let request = CredentialRequest::new(
            "deepseek",
            "some-other-label",
            vec!["chat:use".to_string()],
            3600,
            Some(usd(5)),
            "test",
        )
        .unwrap();
        let parent = ParentCredential { secret: "sk-deepseek-test".to_string() };
        let err = adapter().mint(&parent, &request).await.unwrap_err();
        assert!(matches!(err, AdapterError::Unsupported(_)));
    }

    #[tokio::test]
    async fn mint_refuses_a_request_with_no_budget_before_any_network_call() {
        let request = CredentialRequest::new(
            "deepseek",
            "custodly-agent-pool",
            vec!["chat:use".to_string()],
            3600,
            None,
            "test",
        )
        .unwrap();
        let parent = ParentCredential { secret: "sk-deepseek-test".to_string() };
        let err = adapter().mint(&parent, &request).await.unwrap_err();
        assert!(matches!(err, AdapterError::Rejected(_)));
    }

    #[tokio::test]
    async fn mint_refuses_a_non_usd_budget_before_any_network_call() {
        let request = CredentialRequest::new(
            "deepseek",
            "custodly-agent-pool",
            vec!["chat:use".to_string()],
            3600,
            Some(Budget { limit_minor_units: 500, currency: "EUR".to_string() }),
            "test",
        )
        .unwrap();
        let parent = ParentCredential { secret: "sk-deepseek-test".to_string() };
        let err = adapter().mint(&parent, &request).await.unwrap_err();
        assert!(matches!(err, AdapterError::Rejected(_)));
    }

    #[tokio::test]
    async fn verify_catches_a_resource_label_mismatch() {
        let request = CredentialRequest::new(
            "deepseek",
            "custodly-agent-pool",
            vec!["chat:use".to_string()],
            3600,
            Some(usd(5)),
            "test",
        )
        .unwrap();
        let minted = MintedChild {
            secret: "proxy-tok-abc".to_string(),
            granted_resource: "some-other-label".to_string(),
            granted_actions: vec!["chat:use".to_string()],
            expires_at: None,
            provider_ref: Some("grant-1".to_string()),
        };
        let err = adapter().verify(&minted, &request).await.unwrap_err();
        assert!(matches!(err, AdapterError::ScopeCreep(_)));
    }

    #[tokio::test]
    async fn verify_a_matching_grant_is_still_tier_2_on_financial_exposure() {
        let request = CredentialRequest::new(
            "deepseek",
            "custodly-agent-pool",
            vec!["chat:use".to_string()],
            3600,
            Some(usd(5)),
            "test",
        )
        .unwrap();
        let minted = MintedChild {
            secret: "proxy-tok-abc".to_string(),
            granted_resource: "custodly-agent-pool".to_string(),
            granted_actions: vec!["chat:use".to_string()],
            expires_at: None,
            provider_ref: Some("grant-1".to_string()),
        };
        let assessment = adapter().verify(&minted, &request).await.unwrap();
        assert_eq!(custodly_core::Tier::score(Some(&assessment)), custodly_core::Tier::Tier2);
    }
}
