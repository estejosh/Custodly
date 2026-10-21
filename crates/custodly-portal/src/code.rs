//! Single-use codes and unguessable ids, both built the same way: fill
//! random bytes, map each into a short alphabet, done -- deliberately
//! not `rand::Rng::random_range` in a loop, so this doesn't depend on an
//! exact `rand` API shape beyond `fill_bytes`, which the rest of this
//! workspace already relies on (`custodly-cli`'s deposit-id generation).

use sha2::{Digest, Sha256};

/// Unambiguous alphabet -- no `0`/`O`, no `1`/`I`, matching
/// `custodly-remote-approval.md`'s "Josh has to type it back" design: a
/// code that's easy to misread defeats the point of requiring it typed.
const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

fn random_token(len: usize) -> String {
    let mut buf = vec![0_u8; len];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut buf);
    buf.iter().map(|b| ALPHABET[(*b as usize) % ALPHABET.len()] as char).collect()
}

/// A fresh single-use approval code, plus its SHA-256 hex hash to store
/// in place of the plaintext (`PendingKind::Approve::code_hash`). Short
/// enough to type back from a phone; the hash is what's persisted, the
/// plaintext is returned to the caller exactly once.
#[must_use]
pub fn generate_approval_code() -> (String, String) {
    let code = random_token(8);
    let hash = hash_code(&code);
    (code, hash)
}

#[must_use]
pub fn hash_code(code: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(code.trim().to_ascii_uppercase().as_bytes());
    hex::encode(hasher.finalize())
}

/// Constant-time-ish comparison isn't the point here (the hash itself is
/// what's compared, not the secret directly) -- this exists so callers
/// never compare a raw code against a raw code.
#[must_use]
pub fn verify_code(code: &str, hash_hex: &str) -> bool {
    hash_code(code) == hash_hex
}

/// An unguessable id for a `PendingRequest` -- longer than an approval
/// code since it doubles as a URL token and an OAuth `state` value, not
/// something meant to be typed.
#[must_use]
pub fn generate_id() -> String {
    random_token(22)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_codes_use_only_the_unambiguous_alphabet() {
        let (code, _) = generate_approval_code();
        assert_eq!(code.len(), 8);
        assert!(code.chars().all(|c| ALPHABET.contains(&(c as u8))));
    }

    #[test]
    fn a_code_verifies_against_its_own_hash_case_insensitively() {
        let (code, hash) = generate_approval_code();
        assert!(verify_code(&code, &hash));
        assert!(verify_code(&code.to_ascii_lowercase(), &hash));
    }

    #[test]
    fn a_wrong_code_never_verifies() {
        let (_, hash) = generate_approval_code();
        assert!(!verify_code("WRONGCOD", &hash));
    }

    #[test]
    fn two_generated_codes_are_not_the_same() {
        let (a, _) = generate_approval_code();
        let (b, _) = generate_approval_code();
        assert_ne!(a, b);
    }

    #[test]
    fn ids_are_long_enough_to_not_collide_in_practice_and_dont_match_codes() {
        let id = generate_id();
        assert_eq!(id.len(), 22);
    }
}
