//! The vault-facing shape of a stored secret, and the query key used to
//! fetch exactly one of them.
//!
//! Two rules this module exists to enforce in types, not just docs:
//!
//! 1. Every entry stored in the vault carries [`EntryMetadata`] -- no
//!    secret goes in "bare." `custodly-vault` refuses to write an entry
//!    without it. `group_path` is derived from `metadata.project`, never
//!    supplied separately, so an entry can't end up filed under a
//!    project other than the one its own metadata names.
//! 2. Reading a secret back is a scoped, single-key lookup
//!    (`SecretQuery`), never a browse or a dump. An agent working in a
//!    repo asks for "the GitHub key for redaktly" and gets that one
//!    value -- it never gets a handle to the vault, and a query that
//!    matches zero or more than one entry is an error, not a list.
//!
//! `EntryMetadata` is deliberately a separate type from
//! [`crate::contract::DepositMetadata`], not a reuse of it under a
//! different name. `contract::DepositMetadata` is the `boundary/v1` wire
//! shape `deposit()` sends to Ferryman (`docs/BOUNDARY.md`: provider,
//! scope, tier, acquired_via, expires_at, acquired_at, label) -- it has
//! no `project` or `source_description` field because Ferryman's side of
//! that contract doesn't need them. `EntryMetadata` is what
//! `custodly-vault` actually writes into a KeePass entry's Notes field
//! (`docs/design-brief.md`, "Vault entries": provider, project,
//! source_description, acquired_via, acquired_at, expires_at, tier) --
//! richer, and local-only. Collapsing the two into one type is what
//! caused this crate to stop compiling against `custodly-vault` in the
//! first place; keeping them apart, under different names, is the fix.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::tier::Tier;

/// The implicit owner for every entry/query that doesn't name one --
/// Josh, on this machine, today. Multi-tenancy (`docs/design-brief.md`
/// restructure, 25 Sep 2026: "Josh now, clients later") adds `owner` as
/// a real dimension without breaking anything already in `working.kdbx`:
/// an owner of `LOCAL_OWNER` keeps the original two-level group path
/// (`project/label`) exactly as it already is on disk; only a *different*
/// owner gets the new three-level path (`owner/project/label`). This is
/// why `SecretQuery::new`/`EntryMetadata::new` (no owner arg) still work
/// unchanged -- they're `LOCAL_OWNER` under the hood, not a separate code
/// path that could drift from the multi-tenant one.
pub const LOCAL_OWNER: &str = "josh";

/// How a locally-stored secret was acquired -- the vault's own
/// provenance record. Distinct from [`crate::contract::AcquiredVia`]
/// (`track1_api` / `track2_recipe`, the coarse summary that crosses the
/// `boundary/v1` wire to Ferryman): this is the finer-grained record kept
/// in a KeePass entry's Notes field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcquisitionSource {
    /// Minted via the GitHub App pilot (`docs/mvp-scope.md`, "Track 1
    /// pilot").
    GithubAppInstallationToken,
    /// Typed in by Josh directly -- not (yet) acquired through either
    /// track.
    ManualEntry,
    /// Pulled in from somewhere it was previously sitting loose, e.g. a
    /// scattered `.env` file or another folder. `found_at` records where,
    /// for the audit trail.
    Migrated { found_at: String },
    /// A parent credential obtained through `custodly-portal`'s
    /// owner-authorize flow (`custodly-owner-portal.md`) -- an owner
    /// clicked "Allow" on the provider's own OAuth consent screen, the
    /// portal exchanged the resulting code server-side, and this is what
    /// landed in the vault. `provider` records which OAuth flow ran;
    /// kept distinct from `ManualEntry` because this one *did* go
    /// through a real, provider-verified consent step, not someone
    /// typing a key in by hand.
    OwnerPortalOauth { provider: String },
    /// A key the owner typed into the Custodly phone app and sent as a
    /// sealed deposit (`docs/PHONE-DEPOSIT.md`). `device_id` is the enrolled
    /// phone that signed it -- distinct from `ManualEntry` because it
    /// crossed a device boundary under a device signature.
    PhoneDeposit { device_id: String },
}

/// Refuses to build an [`EntryMetadata`] missing what makes a stored
/// secret traceable: which project it belongs to, and what it's for.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EntryMetadataError {
    #[error("project must not be empty -- a secret with no project is a liability, not an asset")]
    EmptyProject,
    #[error("source_description must not be empty -- record what this is for and how it was acquired")]
    EmptySourceDescription,
}

/// Everything about a secret stored in the vault, except its value.
/// Never the plaintext secret or anything it could be reconstructed
/// from -- serialized into a KeePass entry's Notes field as plain
/// `key=value` lines by `custodly-vault`, so it's readable directly in
/// the KeePassXC GUI, not just parseable by Custodly's own code.
///
/// The only way to build one is [`EntryMetadata::new`], which refuses an
/// empty `project` or `source_description` -- see the module docs for
/// why this is a separate type from `contract::DepositMetadata`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryMetadata {
    /// Which tenant this credential belongs to -- `LOCAL_OWNER` ("josh")
    /// for everything acquired before 25 Sep 2026 and for anything
    /// acquired for Josh's own use since. A future client owner is never
    /// implied by omission; see [`EntryMetadata::for_owner`].
    #[serde(default = "default_owner")]
    pub owner: String,
    pub provider: String,
    /// Which project/repo this credential belongs to, e.g. `"redaktly"`.
    /// Drives [`VaultEntry::group_path`] -- never supplied separately.
    pub project: String,
    /// Free text: what this is for and how it was acquired.
    pub source_description: String,
    pub acquired_via: AcquisitionSource,
    pub acquired_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub tier: Tier,
}

impl EntryMetadata {
    /// Build an `EntryMetadata` for [`LOCAL_OWNER`] ("josh") -- the only
    /// owner that existed before the multi-tenant restructure, and still
    /// the right default for anything acquired for Josh's own use.
    /// Fails closed on the two fields that make a stored secret
    /// traceable rather than a liability: `project` and
    /// `source_description` must both be non-empty.
    pub fn new(
        provider: impl Into<String>,
        project: impl Into<String>,
        source_description: impl Into<String>,
        acquired_via: AcquisitionSource,
        acquired_at: DateTime<Utc>,
        expires_at: Option<DateTime<Utc>>,
        tier: Tier,
    ) -> Result<Self, EntryMetadataError> {
        Self::for_owner(
            LOCAL_OWNER,
            provider,
            project,
            source_description,
            acquired_via,
            acquired_at,
            expires_at,
            tier,
        )
    }

    /// Build an `EntryMetadata` for a specific owner -- the multi-tenant
    /// path. Same validation as [`EntryMetadata::new`]; `owner` is not
    /// validated non-empty here because [`LOCAL_OWNER`] is always a
    /// valid, non-empty fallback and every real caller either supplies
    /// it or goes through `new`.
    #[allow(clippy::too_many_arguments)]
    pub fn for_owner(
        owner: impl Into<String>,
        provider: impl Into<String>,
        project: impl Into<String>,
        source_description: impl Into<String>,
        acquired_via: AcquisitionSource,
        acquired_at: DateTime<Utc>,
        expires_at: Option<DateTime<Utc>>,
        tier: Tier,
    ) -> Result<Self, EntryMetadataError> {
        let project = project.into();
        let source_description = source_description.into();
        if project.trim().is_empty() {
            return Err(EntryMetadataError::EmptyProject);
        }
        if source_description.trim().is_empty() {
            return Err(EntryMetadataError::EmptySourceDescription);
        }
        Ok(Self {
            owner: owner.into(),
            provider: provider.into(),
            project,
            source_description,
            acquired_via,
            acquired_at,
            expires_at,
            tier,
        })
    }
}

fn default_owner() -> String {
    LOCAL_OWNER.to_string()
}

/// A secret as stored in the vault: the value itself plus the provenance
/// metadata it was deposited with. `custodly-vault` maps this onto a
/// KeePass entry with the secret in the password field and every
/// `EntryMetadata` field mirrored into the Notes field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultEntry {
    /// KeePass group path this entry lives under, e.g.
    /// "redaktly/github-pat". Entries are grouped by project first --
    /// this is what makes a project-scoped query a single group lookup
    /// rather than a filter over the whole vault. Always
    /// `"{metadata.project}/{label}"`; see `VaultEntry::new`.
    pub group_path: String,
    /// Short name for this credential within its project, e.g.
    /// "github-pat", "openai-key".
    pub label: String,
    pub metadata: EntryMetadata,
    pub secret: String,
}

impl VaultEntry {
    /// Build a `VaultEntry`. `group_path` is always derived from
    /// `metadata.project` + `label` -- there is no way to construct one
    /// with a `group_path` that disagrees with its own metadata.
    #[must_use]
    pub fn new(label: impl Into<String>, metadata: EntryMetadata, secret: impl Into<String>) -> Self {
        let label = label.into();
        let group_path = format!("{}/{label}", metadata.project);
        Self { group_path, label, metadata, secret: secret.into() }
    }

    #[must_use]
    pub fn query(&self) -> SecretQuery {
        SecretQuery::new(self.metadata.project.clone(), self.label.clone())
    }
}

/// A request for exactly one secret. Built from what the caller (an
/// agent, a CLI invocation on a recipient's machine) actually knows: the
/// project it's working in, and which credential it needs within that
/// project.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretQuery {
    #[serde(default = "default_owner")]
    pub owner: String,
    pub project: String,
    pub label: String,
}

impl SecretQuery {
    /// A query for [`LOCAL_OWNER`] ("josh") -- unchanged from before the
    /// multi-tenant restructure, and still what every local agent on
    /// this box should use for Josh's own credentials.
    #[must_use]
    pub fn new(project: impl Into<String>, label: impl Into<String>) -> Self {
        Self::for_owner(LOCAL_OWNER, project, label)
    }

    /// A query for a specific owner -- the multi-tenant path. A
    /// requester's own identity must actually match `owner` before this
    /// is allowed to resolve; enforcing that is the caller's job (e.g.
    /// `custodly-core::adapter`), not `Vault::get`'s -- the vault only
    /// ever answers "what's stored at this path," never "who's asking."
    #[must_use]
    pub fn for_owner(owner: impl Into<String>, project: impl Into<String>, label: impl Into<String>) -> Self {
        Self { owner: owner.into(), project: project.into(), label: label.into() }
    }

    /// The group path this query resolves to. For [`LOCAL_OWNER`], this
    /// is unchanged from before the restructure -- "redaktly/github-pat"
    /// stays "redaktly/github-pat", so every entry already in
    /// `working.kdbx` keeps resolving. Any other owner gets a real third
    /// level: "acme/redaktly/github-pat" -- a different KeePass group
    /// entirely, never collapsible with Josh's own "redaktly" group.
    /// `custodly-vault` opens only the one entry this resolves to -- it
    /// never enumerates a group to find it.
    #[must_use]
    pub fn group_path(&self) -> String {
        if self.owner == LOCAL_OWNER {
            format!("{}/{}", self.project, self.label)
        } else {
            format!("{}/{}/{}", self.owner, self.project, self.label)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_refuses_an_empty_project() {
        let err = EntryMetadata::new(
            "github", "", "some key", AcquisitionSource::ManualEntry, Utc::now(), None, Tier::Tier0,
        )
        .unwrap_err();
        assert_eq!(err, EntryMetadataError::EmptyProject);
    }

    #[test]
    fn new_refuses_an_empty_source_description() {
        let err = EntryMetadata::new(
            "github", "redaktly", "", AcquisitionSource::ManualEntry, Utc::now(), None, Tier::Tier0,
        )
        .unwrap_err();
        assert_eq!(err, EntryMetadataError::EmptySourceDescription);
    }

    #[test]
    fn group_path_is_project_slash_label() {
        let metadata = EntryMetadata::new(
            "github", "redaktly", "a key", AcquisitionSource::ManualEntry, Utc::now(), None, Tier::Tier0,
        )
        .unwrap();
        let entry = VaultEntry::new("github-pat", metadata, "sk-abc");
        assert_eq!(entry.group_path, "redaktly/github-pat");
        assert_eq!(entry.query().group_path(), "redaktly/github-pat");
    }

    #[test]
    fn local_owner_query_keeps_the_pre_restructure_two_level_path() {
        assert_eq!(SecretQuery::new("redaktly", "github-pat").group_path(), "redaktly/github-pat");
    }

    #[test]
    fn a_different_owner_gets_a_real_third_level_never_collapsing_into_joshs_group() {
        let query = SecretQuery::for_owner("acme", "redaktly", "github-pat");
        assert_eq!(query.group_path(), "acme/redaktly/github-pat");
        assert_ne!(query.group_path(), SecretQuery::new("redaktly", "github-pat").group_path());
    }

    #[test]
    fn entry_metadata_new_defaults_to_local_owner() {
        let metadata = EntryMetadata::new(
            "github", "redaktly", "a key", AcquisitionSource::ManualEntry, Utc::now(), None, Tier::Tier0,
        )
        .unwrap();
        assert_eq!(metadata.owner, LOCAL_OWNER);
    }

    #[test]
    fn entry_metadata_for_owner_still_validates_project_and_source_description() {
        let err = EntryMetadata::for_owner(
            "acme", "github", "", "a key", AcquisitionSource::ManualEntry, Utc::now(), None, Tier::Tier0,
        )
        .unwrap_err();
        assert_eq!(err, EntryMetadataError::EmptyProject);
    }

    #[test]
    fn deserializing_an_entry_written_before_the_owner_field_existed_defaults_to_local_owner() {
        // Exactly the shape `custodly-vault` wrote into working.kdbx's
        // Notes field before this change (24 Sep 2026's github-repo-push
        // entry) -- no `owner=` line at all.
        let json = r#"{
            "provider": "github",
            "project": "custodly",
            "source_description": "GitHub App installation token",
            "acquired_via": "github_app_installation_token",
            "acquired_at": "2026-09-24T20:03:35Z",
            "expires_at": "2026-09-24T21:03:35Z",
            "tier": "tier1"
        }"#;
        let metadata: EntryMetadata = serde_json::from_str(json).unwrap();
        assert_eq!(metadata.owner, LOCAL_OWNER);
    }
}
