//! The vault's own unlock password, resolved through the OS keystore
//! (Windows Credential Manager / Keychain / Secret Service) via `keyring`
//! -- never written to disk next to the database. First call for a given
//! `vault_name` generates and stores a strong random password; every
//! later call returns the same one.

use keyring::Entry;
use rand::RngExt;

const SERVICE: &str = "custodly";
const GENERATED_LEN: usize = 40;

/// Fetch this vault's password from the OS keystore, generating and
/// storing one on first use.
pub fn get_or_create(vault_name: &str) -> Result<String, keyring::Error> {
    let entry = Entry::new(SERVICE, vault_name)?;
    match entry.get_password() {
        Ok(existing) => Ok(existing),
        Err(keyring::Error::NoEntry) => {
            let generated = generate();
            entry.set_password(&generated)?;
            Ok(generated)
        }
        Err(other) => Err(other),
    }
}

/// Not exposed as `pub` -- generating a password is an implementation
/// detail of "provision one if none exists," not a general utility.
fn generate() -> String {
    const CHARS: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*-_=+";
    let mut rng = rand::rng();
    (0..GENERATED_LEN)
        .map(|_| CHARS[rng.random_range(0..CHARS.len())] as char)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_password_is_the_right_length_and_charset() {
        let p = generate();
        assert_eq!(p.len(), GENERATED_LEN);
        assert!(p.is_ascii());
    }
}
