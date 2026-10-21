//! The provider-agnostic adapter contract (multi-provider restructure,
//! 25 Sep 2026). Adapters *declare* what they can do; this module
//! *decides* how to deliver a narrower child from that -- an adapter
//! never picks its own strategy, so two adapters can't silently disagree
//! about what "strategy 2" means.
//!
//! Three strategies, from `docs/design-brief.md`'s restructure notes:
//! 1. **Native child** -- the provider enforces resource, action, time,
//!    and (if requested) money on the child itself.
//! 2. **Native child + reaper** -- the provider can scope resource/action
//!    but can't expire the child; Custodly records it and revokes it at
//!    its ttl (the reaper runs as an n8n workflow, not code in this
//!    crate -- see the roadmap).
//! 3. **Broker** -- the provider can't narrow anything meaningful via
//!    API. The real parent key never leaves Custodly; a caller gets a
//!    Custodly-issued proxy credential instead. `ProviderAdapter` here
//!    only covers mint/verify/revoke of that proxy relationship's
//!    *record* -- actually proxying live provider traffic is a running
//!    service, not a trait method, and is out of scope for this module.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::request::CredentialRequest;
use crate::tier::ScopeAssessment;

/// What a provider adapter can actually do, declared once per adapter.
/// Never hand-waved as "GitHub-like" or "OpenRouter-like" -- every field
/// is a yes/no this module's [`pick_strategy`] can act on mechanically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderCapabilities {
    /// Can a minted child be restricted to less than the parent's full
    /// reach (one repo, one project, one account scope)?
    pub resource_scoping: bool,
    /// Can a minted child be restricted to fewer actions than the parent
    /// has (read vs. write, specific endpoints)?
    pub action_scoping: bool,
    /// Does the provider itself expire the child (a TTL the provider
    /// enforces), rather than Custodly having to remember to revoke it?
    pub native_expiry: bool,
    /// Can a spend cap be set on the child by the provider itself?
    pub native_budget: bool,
    /// Is there an API to create a child credential at all (as opposed
    /// to dashboard-only issuance)?
    pub api_create: bool,
    /// Is there an API to revoke/delete a specific child credential?
    pub api_revoke: bool,
}

/// The core's strategy decision for one provider, from its declared
/// [`ProviderCapabilities`]. See the module docs for what each means.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Strategy {
    NativeChild,
    NativeChildWithReaper,
    Broker,
}

/// Pick a strategy from what a provider actually declares it can
/// enforce -- never from the provider's name or reputation. A provider
/// that can narrow resource/action via API but can neither expire nor
/// revoke what it minted gets `Broker`, not `NativeChildWithReaper`:
/// a reaper only works when there's an API to revoke through, so
/// "narrows scope but nothing can ever end it" is no safer in practice
/// than never having narrowed it at all -- don't dress that up as a
/// bounded child.
#[must_use]
pub fn pick_strategy(caps: &ProviderCapabilities) -> Strategy {
    if !caps.api_create {
        return Strategy::Broker;
    }
    // All four narrowing dimensions count -- resource, action, and
    // money are each a real way to make a child narrower than its
    // parent, per docs/design-brief.md's restructure notes. Time alone
    // never counts here: every strategy already handles time (either
    // natively or via the reaper), so it isn't what distinguishes them.
    let narrows_something = caps.resource_scoping || caps.action_scoping || caps.native_budget;
    if !narrows_something {
        return Strategy::Broker;
    }
    if caps.native_expiry && caps.api_revoke {
        Strategy::NativeChild
    } else if caps.api_revoke {
        Strategy::NativeChildWithReaper
    } else {
        Strategy::Broker
    }
}

/// A parent secret loaded from `master.kdbx` for exactly one mint, then
/// dropped -- never held across two mints, never two loaded at once
/// (`custodly-vault::Vault` already only ever holds one at a time; see
/// its module docs). `Debug` never prints `secret`, matching the
/// standing rule that a key never appears in a log or transcript.
#[derive(Clone)]
pub struct ParentCredential {
    pub secret: String,
}

impl std::fmt::Debug for ParentCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParentCredential").field("secret", &"<redacted>").finish()
    }
}

/// What minting produced, before it's verified or stored. `Debug` never
/// prints `secret`, same reasoning as [`ParentCredential`].
#[derive(Clone)]
pub struct MintedChild {
    pub secret: String,
    /// What the provider says it actually granted -- may differ from
    /// `request.resource` if the provider only supports coarser scoping
    /// than asked for; `verify` is what catches that.
    pub granted_resource: String,
    pub granted_actions: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
    /// Whatever id the provider needs to revoke this later (a token id,
    /// a key hash). `None` for a provider with no revoke API at all.
    /// Usually opaque, but GitHub's adapter puts the live token here --
    /// see [`ChildRef`]'s docs -- so `Debug` redacts this field too,
    /// same as `secret`, rather than assuming it's always safe to show.
    pub provider_ref: Option<String>,
}

impl std::fmt::Debug for MintedChild {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MintedChild")
            .field("secret", &"<redacted>")
            .field("granted_resource", &self.granted_resource)
            .field("granted_actions", &self.granted_actions)
            .field("expires_at", &self.expires_at)
            .field("provider_ref", &self.provider_ref.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// Enough to revoke one previously-minted child. For most providers
/// this is an opaque id, deliberately not the secret itself, since
/// revoking never needs it. GitHub is a documented exception: its
/// installation-token self-revoke API (`DELETE /installation/token`)
/// accepts no auth but the token being revoked, so `custodly-github`'s
/// adapter necessarily puts the live token in `provider_ref` there.
/// `Debug` redacts unconditionally regardless of which case this is,
/// since this type can't tell them apart and a provider_ref must never
/// appear in a log or transcript either way.
#[derive(Clone, Serialize, Deserialize)]
pub struct ChildRef {
    pub provider_ref: String,
}

impl std::fmt::Debug for ChildRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChildRef").field("provider_ref", &"<redacted>").finish()
    }
}

#[derive(Debug, Error)]
pub enum AdapterError {
    #[error("http request to provider failed: {0}")]
    Http(String),
    #[error("provider granted more than was requested: {0}")]
    ScopeCreep(String),
    #[error("this adapter/strategy doesn't support {0}")]
    Unsupported(String),
    #[error("provider rejected the request: {0}")]
    Rejected(String),
    #[error("could not verify the actual granted scope: {0}")]
    Unverifiable(String),
}

/// One provider's adapter. Implementors declare [`ProviderCapabilities`]
/// truthfully (over-claiming here is how a child ends up under-scored by
/// [`crate::tier::Tier::score`]) and implement mint/verify/revoke against
/// that provider's real API.
///
/// `verify` always runs after `mint`, for every provider, not just ones
/// with a confirmed read-back API -- an adapter with nothing to check
/// against returns `Err(AdapterError::Unverifiable)`, which the caller
/// turns into `Enforcement::Unverified` (`crate::tier`) rather than
/// silently trusting `mint`'s own claim. This generalizes GitHub's
/// `verify_no_scope_creep` past its original permission-map-only shape:
/// an implementation should check resource-level creep too, not only
/// action-level, which the GitHub pilot's version doesn't yet.
#[async_trait]
pub trait ProviderAdapter: Send + Sync {
    fn provider(&self) -> &str;
    fn capabilities(&self) -> ProviderCapabilities;

    #[must_use]
    fn strategy(&self) -> Strategy {
        pick_strategy(&self.capabilities())
    }

    async fn mint(
        &self,
        parent: &ParentCredential,
        request: &CredentialRequest,
    ) -> Result<MintedChild, AdapterError>;

    async fn verify(
        &self,
        minted: &MintedChild,
        request: &CredentialRequest,
    ) -> Result<ScopeAssessment, AdapterError>;

    /// Revoke early (parent leak, bulk cleanup) or as a reaper firing at
    /// ttl. A `Broker`-strategy adapter's "revocation" means dropping the
    /// proxy record, not calling the provider -- the real key was never
    /// handed out to revoke.
    ///
    /// Takes `parent`, same as `mint` -- added 25 Sep 2026 after building
    /// the Codeberg and OpenRouter adapters back to back and hitting the
    /// same wall twice: both providers' real revoke/delete endpoints need
    /// the *account's* credentials (basic auth, a management key), not
    /// just an opaque id, and a signature without `parent` made that
    /// impossible to implement honestly for either one. Whatever fires
    /// this for a `NativeChildWithReaper` provider (an n8n reaper today)
    /// has to fetch `parent` fresh from the vault at fire time, same as a
    /// mint does -- never hold it in the adapter across calls.
    async fn revoke(&self, parent: &ParentCredential, child: &ChildRef) -> Result<(), AdapterError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps(resource: bool, action: bool, expiry: bool, budget: bool, create: bool, revoke: bool) -> ProviderCapabilities {
        ProviderCapabilities {
            resource_scoping: resource,
            action_scoping: action,
            native_expiry: expiry,
            native_budget: budget,
            api_create: create,
            api_revoke: revoke,
        }
    }

    #[test]
    fn github_shaped_capabilities_pick_native_child() {
        // Resource (repo) + action (permission) scoping, provider-enforced
        // ~1hr expiry, real revoke (tokens can be invalidated) -- no
        // native budget, and none requested for GitHub anyway.
        let c = caps(true, true, true, false, true, true);
        assert_eq!(pick_strategy(&c), Strategy::NativeChild);
    }

    #[test]
    fn codeberg_shaped_capabilities_pick_native_child_with_reaper() {
        // Repo-scoped tokens via API (PR #11504), DELETE to revoke, but
        // no native expiry on the token itself.
        let c = caps(true, true, false, false, true, true);
        assert_eq!(pick_strategy(&c), Strategy::NativeChildWithReaper);
    }

    #[test]
    fn openrouter_shaped_capabilities_pick_native_child_with_reaper_on_budget_alone() {
        // Confirmed 25 Sep 2026: provisioning API creates/revokes keys
        // with spend limits, but no resource/model scoping and no native
        // expiry. Budget narrowing alone is still a real narrowing
        // dimension -- this is NativeChildWithReaper for money, with the
        // caveat (surfaced at the tiering layer, not here) that resource
        // is NOT narrowed at all: any request naming a specific resource
        // can't actually be honored by this provider.
        let c = caps(false, false, false, true, true, true);
        assert_eq!(pick_strategy(&c), Strategy::NativeChildWithReaper);
    }

    #[test]
    fn deepseek_shaped_capabilities_pick_broker() {
        // Confirmed 25 Sep 2026: no key-management API exists at all.
        let c = caps(false, false, false, false, false, false);
        assert_eq!(pick_strategy(&c), Strategy::Broker);
    }

    #[test]
    fn scoping_without_any_revoke_path_is_still_broker() {
        // Can narrow at creation time, but nothing -- not the provider,
        // not a reaper -- can ever end it. Treat as unbounded.
        let c = caps(true, true, false, false, true, false);
        assert_eq!(pick_strategy(&c), Strategy::Broker);
    }

    #[test]
    fn no_create_api_is_always_broker_regardless_of_other_capabilities() {
        let c = caps(true, true, true, true, false, true);
        assert_eq!(pick_strategy(&c), Strategy::Broker);
    }

    #[test]
    fn parent_credential_debug_never_prints_the_secret() {
        let p = ParentCredential { secret: "super-secret-pem".to_string() };
        let debug = format!("{p:?}");
        assert!(!debug.contains("super-secret-pem"));
    }

    #[test]
    fn minted_child_debug_never_prints_the_secret() {
        let m = MintedChild {
            secret: "ghs_abcdef".to_string(),
            granted_resource: "estejosh/Custodly".to_string(),
            granted_actions: vec!["contents:write".to_string()],
            expires_at: None,
            provider_ref: None,
        };
        let debug = format!("{m:?}");
        assert!(!debug.contains("ghs_abcdef"));
    }
}
