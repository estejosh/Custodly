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
    /// Build an `EntryMetadata`. Fails closed on the two fields that
    /// make a stored secret traceable rather than a liability: `project`
    /// and `source_description` must both be non-empty.
    pub fn new(
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
    pub project: String,
    pub label: String,
}

impl SecretQuery {
    #[must_use]
    pub fn new(project: impl Into<String>, label: impl Into<String>) -> Self {
        Self { project: project.into(), label: label.into() }
    }

    /// The group path this query resolves to, e.g. project "redaktly",
    /// label "github-pat" -> "redaktly/github-pat". `custodly-vault`
    /// opens only that one entry by this path -- it never enumerates the
    /// group to find it.
    #[must_use]
    pub fn group_path(&self) -> String {
        format!("{}/{}", self.project, self.label)
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
}
