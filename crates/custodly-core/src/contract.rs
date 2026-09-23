//! `boundary/v1` wire types: the payload shapes Custodly and Ferryman agree
//! on. See `docs/BOUNDARY.md` for the contract these implement, and
//! Ferryman's own `crates/ferryman-channel/src/boundary.rs` for the other
//! half - these types are deliberately a separate definition, not a shared
//! crate, because the two repos move at different speeds on purpose; the
//! version string is what keeps them honest about drifting.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Contract version every `boundary/v1` payload carries. A receiver that
/// doesn't recognize the major version rejects the call rather than
/// guessing at its shape.
pub const CONTRACT_VERSION: &str = "boundary/v1";

/// Rejects a `boundary/v1` call rather than guessing at a shape it wasn't
/// built for - the enforcement half of the rule `CONTRACT_VERSION`'s doc
/// comment states. Kept to the one thing that's actually decided
/// (version mismatch); grows variants as real failure modes turn up
/// instead of anticipating ones that haven't.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ContractError {
    #[error("unsupported contract version {got:?}, expected {expected:?}")]
    UnsupportedVersion { expected: &'static str, got: String },
}

/// Check a received `contract_version` string against [`CONTRACT_VERSION`].
/// Call this before touching the rest of a `deposit()` or `policy()`
/// payload, on either side of the boundary.
pub fn check_version(received: &str) -> Result<(), ContractError> {
    if received == CONTRACT_VERSION {
        Ok(())
    } else {
        Err(ContractError::UnsupportedVersion {
            expected: CONTRACT_VERSION,
            got: received.to_string(),
        })
    }
}

/// How the deposited secret was acquired, per the two acquisition tracks
/// in `docs/design-brief.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcquiredVia {
    /// Track 1: minted through the provider's own key-management API.
    Track1Api,
    /// Track 2: produced by a scripted recipe against the provider's
    /// dashboard.
    Track2Recipe,
}

/// Everything about a deposited secret except its value. Never the
/// plaintext secret or anything it could be reconstructed from - this
/// struct is what crosses the wire in `deposit()` alongside the sealed
/// ciphertext, and it is serialized and logged freely because none of it
/// is sensitive on its own.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositMetadata {
    /// Which project this credential belongs to, e.g. `"redaktly"`. Drives
    /// `VaultEntry::group_path` (`entry.rs`) so a project's secrets are a
    /// single group lookup in the vault, and is the same string Ferryman's
    /// `ProjectRoute::project_id` names on the other side of the boundary.
    pub project: String,
    pub provider: String,
    /// Provider-native scope string, e.g. `"repo:read,pr:write"`.
    pub scope: String,
    /// Custodly's own scoring result (0, 1, or 2) - see [`crate::tier::Tier`].
    /// Informational to Ferryman; Ferryman does not re-derive it.
    pub tier: u8,
    pub acquired_via: AcquiredVia,
    pub acquired_at: DateTime<Utc>,
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
    /// Short human string for Ferryman's dashboard, e.g. "GitHub App
    /// install token, pilot repo, read+PR".
    pub label: String,
}

/// A value sealed to a recipient's X25519 public key: an ephemeral public
/// key, a nonce, and ciphertext+tag, all hex-encoded. The wire shape
/// `deposit()`'s `sealed_secret` argument takes - produced by
/// [`crate::seal::seal_for_ingestion`], opened on the Ferryman side by
/// `ferryman_channel::boundary::open_deposit`. Both sides must agree on
/// what associated data the seal is bound to; see that function's docs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedSecret {
    pub ephemeral_public_hex: String,
    pub nonce_hex: String,
    pub ciphertext_hex: String,
}

/// Ferryman's proof that custody transferred, returned from `deposit()`.
/// No secret or key material comes back - this is Custodly's own record
/// of what was deposited and when, for the "record of what was acquired
/// and why" it owns per `docs/BOUNDARY.md`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositReceipt {
    pub deposit_id: String,
    pub accepted_at: DateTime<Utc>,
    pub contract_version: String,
}

/// One thing Custodly still needs before it will treat a request for a
/// provider+scope as fulfillable, e.g. `"onboarding_complete"` or, for
/// tier 2, `"gate:human_approval"`. A string rather than an enum: the set
/// of requirements is Custodly's to extend without forcing a Ferryman
/// release to recognize a new one.
pub type ContractRequirement = String;

/// Custodly's answer, from `policy()`, to "how sensitive is this
/// provider+scope" - the response Ferryman needs to build its own
/// grant/approval UI without reimplementing [`crate::tier`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyResponse {
    /// 0, 1, or 2 - see [`crate::tier::Tier::as_u8`].
    pub tier: u8,
    pub requires: Vec<ContractRequirement>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deposit_metadata_round_trips_through_json() {
        let metadata = DepositMetadata {
            project: "acme".into(),
            provider: "github".into(),
            scope: "repo:read,pr:write".into(),
            tier: 1,
            acquired_via: AcquiredVia::Track1Api,
            acquired_at: Utc::now(),
            expires_at: None,
            label: "GitHub App install token, pilot repo, read+PR".into(),
        };
        let json = serde_json::to_string(&metadata).unwrap();
        let back: DepositMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(back.provider, "github");
        assert_eq!(back.acquired_via, AcquiredVia::Track1Api);
        assert_eq!(back.expires_at, None);
    }

    #[test]
    fn acquired_via_serializes_as_the_documented_snake_case_strings() {
        assert_eq!(
            serde_json::to_string(&AcquiredVia::Track1Api).unwrap(),
            "\"track1_api\""
        );
        assert_eq!(
            serde_json::to_string(&AcquiredVia::Track2Recipe).unwrap(),
            "\"track2_recipe\""
        );
    }

    #[test]
    fn check_version_accepts_the_current_contract_version() {
        assert!(check_version(CONTRACT_VERSION).is_ok());
    }

    #[test]
    fn check_version_rejects_anything_else() {
        let err = check_version("boundary/v2").unwrap_err();
        assert_eq!(
            err,
            ContractError::UnsupportedVersion {
                expected: CONTRACT_VERSION,
                got: "boundary/v2".to_string(),
            }
        );
    }

    #[test]
    fn policy_response_round_trips() {
        let response = PolicyResponse {
            tier: 2,
            requires: vec!["onboarding_complete".into(), "gate:human_approval".into()],
        };
        let json = serde_json::to_string(&response).unwrap();
        let back: PolicyResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(back.tier, 2);
        assert_eq!(back.requires.len(), 2);
    }
}
