//! Custodly's own scoring model, the `boundary/v1` contract it shares with
//! Ferryman, the vault-entry/query types that keep every stored secret
//! traceable to a project and readable only by scoped, single-key lookup,
//! and the sealing operation that gets a secret across the boundary in the
//! first place. See `docs/design-brief.md` (tiering), `docs/BOUNDARY.md`
//! (the deposit/policy contract), and `docs/THREAT-MODEL.md` in the
//! project root -- this module is the code those docs describe, not a
//! reinterpretation of them.
//!
//! (Doc filenames above corrected 2026-09-21 to match what's actually in
//! `docs/` -- `custodly-design.md` and `custodly-threat-model.md`, named in
//! an earlier version of this comment, don't exist. If those renames are
//! still intended, rename the files and this comment together.)

pub mod client;
pub mod contract;
pub mod entry;
pub mod policy;
pub mod seal;
pub mod server;
pub mod tier;

pub use contract::{
    AcquiredVia, ContractError, ContractRequirement, DepositMetadata, DepositReceipt,
    PolicyResponse, SealedSecret, check_version, CONTRACT_VERSION,
};
pub use entry::{AcquisitionSource, EntryMetadata, EntryMetadataError, SecretQuery, VaultEntry};
pub use seal::{deposit_aad, seal_for_ingestion};
pub use tier::{BlastRadius, FinancialExposure, Reversibility, ScopeAssessment, Tier, assess_github_scope};
