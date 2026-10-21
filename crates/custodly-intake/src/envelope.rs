//! `custodly-deposit/v1`: the sealed, signed file a phone sends
//! (`docs/PHONE-DEPOSIT.md`). X25519 + HKDF-SHA256 + ChaCha20-Poly1305 for
//! secrecy, Ed25519 for who sent it. The phone app implements the sending
//! half in plain Java (`android/`); this module is the opening half, plus a
//! `seal` used by tests and any future desktop sender.

use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit, Payload as AeadPayload},
};
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

pub const VERSION: &str = "custodly-deposit/v1";
/// Largest secret value accepted, in bytes.
pub const MAX_VALUE_BYTES: usize = 16 * 1024;
const MAX_AGE_DAYS: i64 = 14;
const MAX_FUTURE_DAYS: i64 = 1;

/// The file as it sits in `inbox/`. Everything is hex except `created`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositFile {
    pub v: String,
    pub id: String,
    pub device_id: String,
    pub created: String,
    pub intake_fp: String,
    pub eph_pub: String,
    pub nonce: String,
    pub ct: String,
    pub sig: String,
}

/// What the phone puts inside the ciphertext.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Payload {
    /// `deposit` (default), `request` (ask beastly to mint a key), or `approve` / `deny`
    /// (answer a proposal beastly sent back). Only a deposit carries a value.
    #[serde(default)]
    pub kind: String,
    /// For a request: how long the key should live, in hours.
    #[serde(default)]
    pub ttl_hours: Option<u32>,
    /// For a request: the spend cap in whole US dollars.
    #[serde(default)]
    pub budget_usd: Option<u32>,
    /// What the key is for, as typed (free text; resolved on the desktop).
    #[serde(default)]
    pub project: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub value: String,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
}

// Never print the value, even in a debug log.
impl std::fmt::Debug for Payload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Payload")
            .field("project", &self.project)
            .field("name", &self.name)
            .field("value", &"<redacted>")
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum OpenError {
    #[error("unsupported deposit version {0:?}")]
    Version(String),
    #[error("this deposit was sealed to a different intake key")]
    WrongIntake,
    #[error("deposit is too old or dated in the future")]
    Stale,
    #[error("malformed deposit: {0}")]
    Format(&'static str),
    #[error("signature does not match the enrolled device")]
    BadSignature,
    #[error("could not decrypt")]
    Decrypt,
    #[error("invalid contents: {0}")]
    Invalid(&'static str),
}

fn sha(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// `ab12-cd34-ef56`: what the owner compares on the phone and on beastly.
#[must_use]
pub fn fingerprint(intake_pub: &[u8; 32]) -> String {
    let h = hex::encode(&sha(intake_pub)[..6]);
    format!("{}-{}-{}", &h[0..4], &h[4..8], &h[8..12])
}

/// The same fingerprint without dashes; what a deposit carries.
#[must_use]
pub fn fingerprint_compact(intake_pub: &[u8; 32]) -> String {
    hex::encode(&sha(intake_pub)[..6])
}

#[must_use]
pub fn device_id(device_pub: &[u8; 32]) -> String {
    hex::encode(&sha(device_pub)[..8])
}

/// Six digits both the phone and the portal show for one device key.
#[must_use]
pub fn device_code(device_pub: &[u8; 32]) -> String {
    let h = sha(device_pub);
    let n = u32::from_be_bytes([h[0], h[1], h[2], h[3]]) % 1_000_000;
    format!("{n:06}")
}

fn aad_string(id: &str, device_id: &str, created: &str, intake_fp: &str) -> String {
    format!("{VERSION}\n{id}\n{device_id}\n{created}\n{intake_fp}")
}

fn sign_bytes(aad: &str, eph_pub: &str, nonce: &str, ct: &str) -> Vec<u8> {
    format!("{aad}\n{eph_pub}\n{nonce}\n{ct}").into_bytes()
}

fn derive_key(shared: &[u8], eph_pub: &[u8; 32], intake_pub: &[u8; 32]) -> Result<[u8; 32], OpenError> {
    let mut salt = Vec::with_capacity(64);
    salt.extend_from_slice(eph_pub);
    salt.extend_from_slice(intake_pub);
    let mut key = [0_u8; 32];
    Hkdf::<Sha256>::new(Some(&salt), shared)
        .expand(VERSION.as_bytes(), &mut key)
        .map_err(|_| OpenError::Format("key derivation failed"))?;
    Ok(key)
}

fn hex_array<const N: usize>(s: &str, what: &'static str) -> Result<[u8; N], OpenError> {
    hex::decode(s)
        .ok()
        .and_then(|b| <[u8; N]>::try_from(b).ok())
        .ok_or(OpenError::Format(what))
}

fn is_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.'
}

/// Checks that make a payload safe to use as a vault path and a secret name.
pub fn validate(p: &Payload) -> Result<(), OpenError> {
    match p.kind.as_str() {
        "" | "deposit" => {}
        "request" => {
            let svc = p.provider.as_deref().unwrap_or("");
            let ok = !svc.trim().is_empty()
                && svc.chars().count() <= 64
                && !svc.chars().any(char::is_control)
                && !p.project.trim().is_empty()
                && p.project.chars().count() <= 120
                && !p.project.chars().any(char::is_control)
                && p.ttl_hours.is_some_and(|h| (1..=720).contains(&h))
                && p.budget_usd.is_none_or(|b| (1..=1000).contains(&b));
            return if ok { Ok(()) } else { Err(OpenError::Invalid("key request")) };
        }
        "approve" | "deny" => {
            // `name` is the request id; `note` is the digest of the proposal being answered.
            let id_ok = p.name.len() == 32 && p.name.chars().all(|c| c.is_ascii_hexdigit());
            let digest_ok = p.note.as_deref().is_some_and(|d| d.len() == 64 && d.chars().all(|c| c.is_ascii_hexdigit()));
            return if id_ok && digest_ok { Ok(()) } else { Err(OpenError::Invalid("approval")) };
        }
        _ => return Err(OpenError::Invalid("kind")),
    }
    // `project` is what the owner typed for "what is this key for": free text. The
    // desktop resolves it to a real project (route.rs); it is never used as a path.
    let for_ok = !p.project.trim().is_empty() && p.project.chars().count() <= 120 && !p.project.chars().any(char::is_control);
    if !for_ok {
        return Err(OpenError::Invalid("what the key is for"));
    }
    // Ferryman's own rule for a secret name: an uppercase label like DEEPSEEK_API_KEY.
    // Empty means "work it out" (route::derive_name).
    let name_ok = p.name.is_empty()
        || (p.name.len() <= 64
        && p.name.starts_with(|c: char| c.is_ascii_uppercase())
        && p.name.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'));
    if !name_ok {
        return Err(OpenError::Invalid("secret name"));
    }
    if let Some(l) = &p.label
        && (l.is_empty() || l.len() > 64 || !l.chars().all(is_name_char))
    {
        return Err(OpenError::Invalid("label"));
    }
    if p.value.is_empty() || p.value.len() > MAX_VALUE_BYTES {
        return Err(OpenError::Invalid("value size"));
    }
    Ok(())
}

/// Seal and sign a deposit. Used by tests and any desktop sender; the phone
/// app does the same steps in Java.
pub fn seal(
    intake_pub: &[u8; 32],
    device_key: &SigningKey,
    payload: &Payload,
    id: &str,
    created: DateTime<Utc>,
) -> Result<DepositFile, OpenError> {
    let device_pub = device_key.verifying_key().to_bytes();
    let created = created.to_rfc3339_opts(SecondsFormat::Secs, true);
    let intake_fp = fingerprint_compact(intake_pub);
    let did = device_id(&device_pub);

    let mut seed = [0_u8; 32];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut seed);
    let eph = StaticSecret::from(seed);
    let eph_pub = PublicKey::from(&eph);
    let shared = eph.diffie_hellman(&PublicKey::from(*intake_pub));
    let key = derive_key(shared.as_bytes(), eph_pub.as_bytes(), intake_pub)?;

    let mut nonce = [0_u8; 12];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut nonce);
    let aad = aad_string(id, &did, &created, &intake_fp);
    let plaintext = serde_json::to_vec(payload).map_err(|_| OpenError::Format("payload"))?;
    let ct = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| OpenError::Format("key"))?
        .encrypt(&Nonce::from(nonce), AeadPayload { msg: &plaintext, aad: aad.as_bytes() })
        .map_err(|_| OpenError::Decrypt)?;

    let (eph_hex, nonce_hex, ct_hex) = (hex::encode(eph_pub.as_bytes()), hex::encode(nonce), hex::encode(ct));
    let sig = device_key.sign(&sign_bytes(&aad, &eph_hex, &nonce_hex, &ct_hex));
    Ok(DepositFile {
        v: VERSION.to_string(),
        id: id.to_string(),
        device_id: did,
        created,
        intake_fp,
        eph_pub: eph_hex,
        nonce: nonce_hex,
        ct: ct_hex,
        sig: hex::encode(sig.to_bytes()),
    })
}

/// Verify the device signature, then decrypt and validate. The signature is
/// checked first so unauthenticated input never reaches the AEAD.
pub fn open(
    intake: &StaticSecret,
    device_pub: &VerifyingKey,
    f: &DepositFile,
    now: DateTime<Utc>,
) -> Result<Payload, OpenError> {
    if f.v != VERSION {
        return Err(OpenError::Version(f.v.clone()));
    }
    let intake_pub = PublicKey::from(intake);
    if f.intake_fp != fingerprint_compact(intake_pub.as_bytes()) {
        return Err(OpenError::WrongIntake);
    }
    if f.device_id != device_id(&device_pub.to_bytes()) {
        return Err(OpenError::BadSignature);
    }
    let created: DateTime<Utc> = DateTime::parse_from_rfc3339(&f.created)
        .map_err(|_| OpenError::Format("created"))?
        .with_timezone(&Utc);
    if created < now - Duration::days(MAX_AGE_DAYS) || created > now + Duration::days(MAX_FUTURE_DAYS) {
        return Err(OpenError::Stale);
    }
    if f.id.len() != 32 || !f.id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(OpenError::Format("id"));
    }

    let eph_pub: [u8; 32] = hex_array(&f.eph_pub, "eph_pub")?;
    let nonce: [u8; 12] = hex_array(&f.nonce, "nonce")?;
    let sig: [u8; 64] = hex_array(&f.sig, "sig")?;
    let ct = hex::decode(&f.ct).map_err(|_| OpenError::Format("ct"))?;

    let aad = aad_string(&f.id, &f.device_id, &f.created, &f.intake_fp);
    device_pub
        .verify(&sign_bytes(&aad, &f.eph_pub, &f.nonce, &f.ct), &Signature::from_bytes(&sig))
        .map_err(|_| OpenError::BadSignature)?;

    let shared = intake.diffie_hellman(&PublicKey::from(eph_pub));
    let key = derive_key(shared.as_bytes(), &eph_pub, intake_pub.as_bytes())?;
    let plaintext = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| OpenError::Format("key"))?
        .decrypt(&Nonce::from(nonce), AeadPayload { msg: &ct, aad: aad.as_bytes() })
        .map_err(|_| OpenError::Decrypt)?;
    let payload: Payload = serde_json::from_slice(&plaintext).map_err(|_| OpenError::Invalid("payload json"))?;
    validate(&payload)?;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> (StaticSecret, SigningKey) {
        (StaticSecret::from([7_u8; 32]), SigningKey::from_bytes(&[9_u8; 32]))
    }

    fn payload() -> Payload {
        Payload {
            project: "custodly".into(),
            name: "OPENROUTER_API_KEY".into(),
            value: "sk-or-v1-example".into(),
            label: None,
            provider: Some("openrouter".into()),
            note: None,
            ..Payload::default()
        }
    }

    fn id() -> String {
        "0123456789abcdef0123456789abcdef".to_string()
    }

    #[test]
    fn a_sealed_deposit_opens_to_the_same_payload() {
        let (intake, dev) = keys();
        let f = seal(PublicKey::from(&intake).as_bytes(), &dev, &payload(), &id(), Utc::now()).unwrap();
        let got = open(&intake, &dev.verifying_key(), &f, Utc::now()).unwrap();
        assert_eq!(got.value, "sk-or-v1-example");
        assert_eq!(got.name, "OPENROUTER_API_KEY");
        assert!(!format!("{got:?}").contains("sk-or-v1"));
    }

    #[test]
    fn tampering_with_the_ciphertext_fails_the_signature_first() {
        let (intake, dev) = keys();
        let mut f = seal(PublicKey::from(&intake).as_bytes(), &dev, &payload(), &id(), Utc::now()).unwrap();
        let mut ct = hex::decode(&f.ct).unwrap();
        ct[0] ^= 1;
        f.ct = hex::encode(ct);
        assert_eq!(open(&intake, &dev.verifying_key(), &f, Utc::now()).unwrap_err(), OpenError::BadSignature);
    }

    #[test]
    fn a_different_device_key_is_rejected() {
        let (intake, dev) = keys();
        let other = SigningKey::from_bytes(&[10_u8; 32]);
        let f = seal(PublicKey::from(&intake).as_bytes(), &dev, &payload(), &id(), Utc::now()).unwrap();
        assert_eq!(open(&intake, &other.verifying_key(), &f, Utc::now()).unwrap_err(), OpenError::BadSignature);
    }

    #[test]
    fn a_deposit_for_another_intake_key_is_rejected() {
        let (intake, dev) = keys();
        let elsewhere = StaticSecret::from([8_u8; 32]);
        let f = seal(PublicKey::from(&elsewhere).as_bytes(), &dev, &payload(), &id(), Utc::now()).unwrap();
        assert_eq!(open(&intake, &dev.verifying_key(), &f, Utc::now()).unwrap_err(), OpenError::WrongIntake);
    }

    #[test]
    fn old_and_future_dated_deposits_are_rejected() {
        let (intake, dev) = keys();
        let pubk = PublicKey::from(&intake);
        let old = seal(pubk.as_bytes(), &dev, &payload(), &id(), Utc::now() - Duration::days(15)).unwrap();
        let future = seal(pubk.as_bytes(), &dev, &payload(), &id(), Utc::now() + Duration::days(2)).unwrap();
        assert_eq!(open(&intake, &dev.verifying_key(), &old, Utc::now()).unwrap_err(), OpenError::Stale);
        assert_eq!(open(&intake, &dev.verifying_key(), &future, Utc::now()).unwrap_err(), OpenError::Stale);
    }

    #[test]
    fn an_edited_id_breaks_the_signature_and_the_aad() {
        let (intake, dev) = keys();
        let mut f = seal(PublicKey::from(&intake).as_bytes(), &dev, &payload(), &id(), Utc::now()).unwrap();
        f.id = "ffffffffffffffffffffffffffffffff".into();
        assert_eq!(open(&intake, &dev.verifying_key(), &f, Utc::now()).unwrap_err(), OpenError::BadSignature);
    }

    #[test]
    fn names_and_projects_that_could_escape_a_path_are_invalid() {
        let mut p = payload();
        p.project = "bad\nnewline".into();
        assert!(validate(&p).is_err());
        let mut p = payload();
        p.project = "x".repeat(121);
        assert!(validate(&p).is_err());
        let mut p = payload();
        p.project = "../etc".into(); // free text is fine: it is never used as a path
        assert!(validate(&p).is_ok());
        let mut p = payload();
        p.name = String::new(); // derived on the desktop
        assert!(validate(&p).is_ok());
        let mut p = payload();
        p.name = "a b".into();
        assert!(validate(&p).is_err());
        let mut p = payload();
        p.name = "openrouter_api_key".into();
        assert!(validate(&p).is_err());
        let mut p = payload();
        p.value = "x".repeat(MAX_VALUE_BYTES + 1);
        assert!(validate(&p).is_err());
        assert!(validate(&payload()).is_ok());
    }

    #[test]
    fn the_phones_request_and_answer_json_parse_and_validate() {
        // Exactly the shapes android/.../Deposit.java writes.
        let req: Payload = serde_json::from_str(
            r#"{"kind":"request","project":"redaktly","provider":"openrouter","ttl_hours":24,"budget_usd":5}"#,
        )
        .unwrap();
        assert!(validate(&req).is_ok());
        let no_cap: Payload = serde_json::from_str(r#"{"kind":"request","project":"x","provider":"y","ttl_hours":0}"#).unwrap();
        assert!(validate(&no_cap).is_err());
        let digest = "a".repeat(64);
        let ans: Payload = serde_json::from_str(&format!(
            r#"{{"kind":"approve","name":"{}","note":"{digest}"}}"#,
            "0".repeat(32)
        ))
        .unwrap();
        assert!(validate(&ans).is_ok());
        let bad: Payload = serde_json::from_str(r#"{"kind":"approve","name":"short","note":"x"}"#).unwrap();
        assert!(validate(&bad).is_err());
        let weird: Payload = serde_json::from_str(r#"{"kind":"sudo","project":"x","value":"v"}"#).unwrap();
        assert!(validate(&weird).is_err());
    }

    #[test]
    fn fingerprint_and_device_code_shapes() {
        let k = [3_u8; 32];
        assert_eq!(fingerprint(&k).len(), 14);
        assert_eq!(fingerprint(&k).replace('-', ""), fingerprint_compact(&k));
        assert_eq!(device_code(&k).len(), 6);
        assert_eq!(device_id(&k).len(), 16);
    }
}