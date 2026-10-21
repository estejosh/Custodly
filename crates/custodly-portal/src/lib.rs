//! Owner-facing web surface: two actions only, "authorize a provider"
//! and "approve/deny a pending Tier 2 request" -- see
//! `custodly-owner-portal.md` in the project docs for the design this
//! implements and what it deliberately doesn't do yet.

pub mod code;
pub mod models;
pub mod oauth;
pub mod routes;
pub mod store;

pub use models::{PendingKind, PendingRequest, PendingStatus};
pub use oauth::{OAuthError, OAuthProvider, SlackOAuth};
pub use routes::{AppState, app};
pub use store::{PendingStore, StoreError};
