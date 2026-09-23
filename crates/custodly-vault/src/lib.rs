//! KeePassXC-backed vault client: wraps `keepassxc-cli` to read and write
//! `working.kdbx` (client reads/writes freely once its own password is
//! configured) and, for onboarding/recovery only, `master.kdbx` (password
//! known only to Josh, typed to unlock, never stored by this client).
//!
//! See `docs/mvp-scope.md` ("Vault mechanism") for the decided design and
//! `docs/THREAT-MODEL.md` for the password-handling rules this
//! implementation follows: the working-store password resolved through
//! the OS keystore via `keyring` at process start, never written to disk
//! in any form, and `master.kdbx`'s password never machine-held at all.

pub mod password;
pub mod vault;

pub use vault::{Vault, VaultError};
