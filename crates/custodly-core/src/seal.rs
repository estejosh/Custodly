//! Sealing a deposit to Ferryman's per-project ingestion key.
//!
//! This is the Custodly-side half of `boundary/v1`'s `deposit()`: the exact
//! construction Ferryman's `ferryman_channel::secrets` module already uses
//! for sealing a value to one recipient's X25519 public key - ephemeral
//! X25519 keypair, X25519 ECDH, HKDF-SHA256 (salted with both public keys,
//! per RFC 7748's guidance not to use a raw ECDH output directly - the one
//! place a hand-rolled shortcut was tried and then deliberately undone on
//! the Ferryman side), XChaCha20-Poly1305. Mirrored here rather than
//! shared as a crate because the two repos move at different speeds on
//! purpose; this module's job is to keep matching that construction
//! byte-for-byte, not to reinvent one.
//!
//! Custodly holds no persistent identity for this: unlike a Ferryman
//! agent, which keeps a stable keypair so it is the same recipient every
//! time, a sealer only ever needs a fresh ephemeral key and the
//! recipient's already-known public key. Nothing here is stored.
//!
//! **Corrected 2026-09-21, after actually cross-checking against
//! Ferryman.** This module previously used its own HKDF "info" label
//! (`"custodly-boundary/v1"`), reasoned as keeping a deposit
//! distinguishable from a regular secret at the KDF layer. That reasoning
//! was wrong in a way that broke the contract outright: Ferryman's
//! `open_slot` calls the same `slot_cipher` function
//! `ferryman-channel/src/secrets.rs` uses for ordinary secrets, which
//! hardcodes its own HKDF info to `SECRET_FORMAT` ("ferryman-secret/v1")
//! regardless of caller - it is not something a deposit gets to override.
//! A different info label derives a different key from the same ECDH
//! shared secret, so every value this module sealed would have failed to
//! open on the Ferryman side, silently, the first time the two repos were
//! actually run against each other rather than read separately. What
//! *does* distinguish a deposit from a regular secret - correctly - is
//! the AEAD's associated data: Ferryman's `deposit_aad(project_id)`,
//! which callers must still pass as `aad` below.

use anyhow::{Context, Result, anyhow, bail};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::contract::SealedSecret;

/// The HKDF "info" label - **must** be Ferryman's own `SECRET_FORMAT`
/// value, byte for byte. `ferryman-channel/src/secrets.rs`'s `slot_cipher`
/// (which `open_slot`/`open_deposit` call) hardcodes this label for every
/// recipient slot it opens, deposits included; there is no per-call
/// override on that side. See the module docs' "Corrected 2026-09-21" for
/// what using a different value here actually breaks.
const HKDF_INFO: &str = "ferryman-secret/v1";

fn hex_decode_32(encoded: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(encoded).context("public key is not valid hex")?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("public key is not 32 bytes"))
}

fn cipher_for(
    ephemeral: &StaticSecret,
    ephemeral_public: &PublicKey,
    recipient_public: &PublicKey,
) -> Result<XChaCha20Poly1305> {
    let shared = ephemeral.diffie_hellman(recipient_public);
    let mut salt = Vec::with_capacity(64);
    salt.extend_from_slice(ephemeral_public.as_bytes());
    salt.extend_from_slice(recipient_public.as_bytes());
    let mut key = [0_u8; 32];
    Hkdf::<Sha256>::new(Some(&salt), shared.as_bytes())
        .expand(HKDF_INFO.as_bytes(), &mut key)
        .map_err(|_| anyhow!("could not derive the seal key"))?;
    XChaCha20Poly1305::new_from_slice(&key).map_err(|_| anyhow!("invalid derived key"))
}

/// Seal `value` to `recipient_public_hex` (Ferryman's ingestion identity
/// public key for the target project) under `aad` as associated data. Both
/// sides must agree on `aad` out of band; Ferryman's opener binds
/// `boundary::deposit_aad(project_id)` - the contract version, the
/// ingestion identity's name, and the project id - so `aad` here must be
/// built the same way for a given project, or the deposit will not open.
///
/// A fresh ephemeral keypair is generated per call. Nothing about the
/// caller is bound into the key derivation beyond that ephemeral key and
/// the recipient's public key - Custodly does not have, and this function
/// does not need, any stable identity of its own.
pub fn seal_for_ingestion(recipient_public_hex: &str, aad: &[u8], value: &str) -> Result<SealedSecret> {
    if value.is_empty() {
        bail!("refusing to seal an empty value");
    }
    let recipient_public = PublicKey::from(hex_decode_32(recipient_public_hex)?);

    let mut ephemeral_seed = [0_u8; 32];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut ephemeral_seed);
    let ephemeral = StaticSecret::from(ephemeral_seed);
    let ephemeral_public = PublicKey::from(&ephemeral);

    let cipher = cipher_for(&ephemeral, &ephemeral_public, &recipient_public)?;
    let mut nonce = [0_u8; 24];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut nonce);
    let ciphertext = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: value.as_bytes(),
                aad,
            },
        )
        .map_err(|_| anyhow!("sealing failed"))?;

    Ok(SealedSecret {
        ephemeral_public_hex: hex::encode(ephemeral_public.as_bytes()),
        nonce_hex: hex::encode(nonce),
        ciphertext_hex: hex::encode(ciphertext),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Opens what `seal_for_ingestion` produced, standing in for
    /// Ferryman's `open_slot` so this module can prove self-consistency
    /// without a copy of Ferryman's crate to link against.
    fn open_for_tests(recipient_secret: &StaticSecret, sealed: &SealedSecret, aad: &[u8]) -> Result<String> {
        let ephemeral_public = PublicKey::from(hex_decode_32(&sealed.ephemeral_public_hex)?);
        let recipient_public = PublicKey::from(recipient_secret);
        let mut salt = Vec::with_capacity(64);
        salt.extend_from_slice(ephemeral_public.as_bytes());
        salt.extend_from_slice(recipient_public.as_bytes());
        let shared = recipient_secret.diffie_hellman(&ephemeral_public);
        let mut key = [0_u8; 32];
        Hkdf::<Sha256>::new(Some(&salt), shared.as_bytes())
            .expand(HKDF_INFO.as_bytes(), &mut key)
            .unwrap();
        let cipher = XChaCha20Poly1305::new_from_slice(&key).unwrap();
        let nonce = hex_decode_24(&sealed.nonce_hex)?;
        let ciphertext = hex::decode(&sealed.ciphertext_hex).context("ciphertext hex")?;
        let plaintext = cipher
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &ciphertext,
                    aad,
                },
            )
            .map_err(|_| anyhow!("decrypt failed"))?;
        String::from_utf8(plaintext).context("not utf8")
    }

    fn hex_decode_24(encoded: &str) -> Result<[u8; 24]> {
        let bytes = hex::decode(encoded).context("nonce hex")?;
        bytes.try_into().map_err(|_| anyhow!("nonce is not 24 bytes"))
    }

    #[test]
    fn seal_then_open_round_trips() {
        let recipient_secret = StaticSecret::from([1_u8; 32]);
        let recipient_public_hex = hex::encode(PublicKey::from(&recipient_secret).as_bytes());
        let aad = b"boundary/v1\ncustodly-ingestion\nacme";

        let sealed = seal_for_ingestion(&recipient_public_hex, aad, "sk-live-abc123").unwrap();
        let opened = open_for_tests(&recipient_secret, &sealed, aad).unwrap();
        assert_eq!(opened, "sk-live-abc123");
    }

    #[test]
    fn a_different_aad_fails_to_open() {
        let recipient_secret = StaticSecret::from([1_u8; 32]);
        let recipient_public_hex = hex::encode(PublicKey::from(&recipient_secret).as_bytes());

        let sealed = seal_for_ingestion(&recipient_public_hex, b"aad-one", "value").unwrap();
        assert!(open_for_tests(&recipient_secret, &sealed, b"aad-two").is_err());
    }

    #[test]
    fn a_different_recipient_cannot_open() {
        let intended = StaticSecret::from([1_u8; 32]);
        let intended_public_hex = hex::encode(PublicKey::from(&intended).as_bytes());
        let someone_else = StaticSecret::from([2_u8; 32]);

        let sealed = seal_for_ingestion(&intended_public_hex, b"aad", "value").unwrap();
        assert!(open_for_tests(&someone_else, &sealed, b"aad").is_err());
    }

    #[test]
    fn each_call_uses_a_fresh_ephemeral_key_and_nonce() {
        let recipient_secret = StaticSecret::from([1_u8; 32]);
        let recipient_public_hex = hex::encode(PublicKey::from(&recipient_secret).as_bytes());

        let first = seal_for_ingestion(&recipient_public_hex, b"aad", "same value").unwrap();
        let second = seal_for_ingestion(&recipient_public_hex, b"aad", "same value").unwrap();
        assert_ne!(first.ephemeral_public_hex, second.ephemeral_public_hex);
        assert_ne!(first.nonce_hex, second.nonce_hex);
        assert_ne!(first.ciphertext_hex, second.ciphertext_hex);
    }

    #[test]
    fn refuses_to_seal_an_empty_value() {
        let recipient_secret = StaticSecret::from([1_u8; 32]);
        let recipient_public_hex = hex::encode(PublicKey::from(&recipient_secret).as_bytes());
        assert!(seal_for_ingestion(&recipient_public_hex, b"aad", "").is_err());
    }
}
