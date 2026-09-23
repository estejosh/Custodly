//! The GitHub App pilot -- `docs/mvp-scope.md`, "Track 1 pilot: GitHub,
//! via a GitHub App." Not a plain PAT (GitHub has no API to mint those):
//! this crate signs a JWT with the App's private key and exchanges it
//! for a short-lived, narrowly-scoped installation access token.
//!
//! Storage is deliberately out of scope here -- `mint_installation_token`
//! returns a [`app::MintedToken`], and the caller (`custodly-cli`, once
//! it has one) builds a `custodly_core::EntryMetadata` from it and hands
//! both to `custodly_vault::Vault::put`. Keeping the mint and the store
//! as separate steps with a plain data type between them is what makes
//! the scope-creep check in this crate the ONLY gate a minted token
//! passes through before it can be stored -- there's no code path that
//! stores a token without going through `verify_no_scope_creep` first,
//! because there's no other way to produce a `MintedToken` at all.

pub mod app;

pub use app::{AppCredentials, GithubError, MintedToken, RequestedGrant, mint_installation_token, mint_jwt};
