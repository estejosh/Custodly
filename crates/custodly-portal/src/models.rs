//! The two things this portal can ever hold pending -- see
//! `custodly-owner-portal.md` for why the shape is this narrow. There is
//! deliberately no "arbitrary request" variant: an owner only ever sees
//! something Custodly already assembled.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingStatus {
    Pending,
    Fulfilled,
    Denied,
}

/// What an owner is being asked to do. `Authorize` needs no Custodly-side
/// code -- the provider's own consent screen is the identity check.
/// `Approve` does need one: a Tier 2 gate must not be rubber-stamped by a
/// bare tap, per `custodly-remote-approval.md`'s stated bar, so the code
/// has to actually be typed back.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PendingKind {
    Authorize {
        provider: String,
        resource: String,
        scopes: Vec<String>,
    },
    Approve {
        provider: String,
        resource: String,
        requested_scope: String,
        current_scope: Option<String>,
        tier: u8,
        /// SHA-256 hex of the single-use code. The plaintext code is
        /// returned to the caller exactly once, when the request is
        /// created (`PendingRequest::new_approve`) -- never stored,
        /// never logged, never recoverable from this record.
        code_hash: String,
    },
}

/// One thing waiting on an owner's click. `id` doubles as the OAuth
/// `state` parameter for an `Authorize` request and as the URL token for
/// either kind -- generated the same unguessable way as an approval code
/// (`crate::code::generate`), not a sequential id.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingRequest {
    pub id: String,
    pub owner: String,
    pub project: String,
    pub kind: PendingKind,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub status: PendingStatus,
}

impl PendingRequest {
    #[must_use]
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        now > self.expires_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_expired_is_false_before_and_true_after_the_deadline() {
        let now = Utc::now();
        let req = PendingRequest {
            id: "x".into(),
            owner: "josh".into(),
            project: "custodly".into(),
            kind: PendingKind::Authorize {
                provider: "slack".into(),
                resource: "acme-workspace".into(),
                scopes: vec!["chat:write".into()],
            },
            created_at: now,
            expires_at: now + chrono::Duration::minutes(15),
            status: PendingStatus::Pending,
        };
        assert!(!req.is_expired(now));
        assert!(req.is_expired(now + chrono::Duration::minutes(16)));
    }
}
