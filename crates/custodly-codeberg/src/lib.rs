//! Codeberg/Forgejo adapter. See [`adapter`]'s module docs for exactly
//! what's confirmed against the real API vs. still assumed and unverified
//! against a live account.

pub mod adapter;

pub use adapter::CodebergAdapter;
