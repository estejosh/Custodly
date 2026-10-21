//! Which phones may send deposits. A phone proposes itself with a public
//! `enroll-<id>.json`; nothing it sends is accepted until the owner types the
//! 6-digit code shown on the phone into the portal, which proves the person
//! at beastly is looking at that phone.

use std::path::PathBuf;

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::envelope::{device_code, device_id};

pub const ENROLL_VERSION: &str = "custodly-enroll/v1";

/// The file a phone writes to `inbox/`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollFile {
    pub v: String,
    pub device_id: String,
    pub device_pub: String,
    pub name: String,
    pub created: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub device_id: String,
    pub device_pub: String,
    pub name: String,
    pub created: String,
}

impl Device {
    /// The code the phone shows for this key.
    #[must_use]
    pub fn code(&self) -> String {
        pub_bytes(&self.device_pub).map(|b| device_code(&b)).unwrap_or_default()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceStatus {
    Unknown,
    Pending,
    Enrolled,
    Rejected,
}

#[derive(Debug, Error)]
pub enum DeviceError {
    #[error("not an enrollment file this intake understands")]
    Invalid,
    #[error("no such pending device")]
    NotPending,
    #[error("that code does not match the device")]
    WrongCode,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

fn pub_bytes(hex_key: &str) -> Option<[u8; 32]> {
    hex::decode(hex_key).ok()?.try_into().ok()
}

fn safe_id(id: &str) -> bool {
    id.len() == 16 && id.chars().all(|c| c.is_ascii_hexdigit())
}

pub struct DeviceRegistry {
    dir: PathBuf,
}

impl DeviceRegistry {
    pub fn new(dir: impl Into<PathBuf>) -> Result<Self, DeviceError> {
        let dir = dir.into();
        for sub in ["pending", "enrolled", "rejected"] {
            std::fs::create_dir_all(dir.join(sub))?;
        }
        Ok(Self { dir })
    }

    fn path(&self, sub: &str, id: &str) -> PathBuf {
        self.dir.join(sub).join(format!("{id}.json"))
    }

    #[must_use]
    pub fn status(&self, id: &str) -> DeviceStatus {
        if !safe_id(id) {
            return DeviceStatus::Unknown;
        }
        if self.path("enrolled", id).exists() {
            DeviceStatus::Enrolled
        } else if self.path("rejected", id).exists() {
            DeviceStatus::Rejected
        } else if self.path("pending", id).exists() {
            DeviceStatus::Pending
        } else {
            DeviceStatus::Unknown
        }
    }

    /// Queue a phone for the owner to enroll. The claimed id must be derived
    /// from the claimed key, so one phone cannot enroll under another's id.
    pub fn record_pending(&self, e: &EnrollFile) -> Result<DeviceStatus, DeviceError> {
        let key = pub_bytes(&e.device_pub).ok_or(DeviceError::Invalid)?;
        if e.v != ENROLL_VERSION || e.device_id != device_id(&key) || e.name.len() > 64 {
            return Err(DeviceError::Invalid);
        }
        VerifyingKey::from_bytes(&key).map_err(|_| DeviceError::Invalid)?;
        let status = self.status(&e.device_id);
        if status != DeviceStatus::Unknown {
            return Ok(status);
        }
        let d = Device {
            device_id: e.device_id.clone(),
            device_pub: e.device_pub.clone(),
            name: e.name.chars().filter(|c| !c.is_control()).collect(),
            created: e.created.clone(),
        };
        std::fs::write(self.path("pending", &d.device_id), serde_json::to_vec_pretty(&d)?)?;
        Ok(DeviceStatus::Pending)
    }

    fn list(&self, sub: &str) -> Vec<Device> {
        std::fs::read_dir(self.dir.join(sub))
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| serde_json::from_slice(&std::fs::read(e.path()).ok()?).ok())
            .collect()
    }

    #[must_use]
    pub fn list_pending(&self) -> Vec<Device> {
        self.list("pending")
    }

    #[must_use]
    pub fn list_enrolled(&self) -> Vec<Device> {
        self.list("enrolled")
    }

    #[must_use]
    pub fn list_rejected(&self) -> Vec<Device> {
        self.list("rejected")
    }

    /// Enroll a pending device, but only when `typed_code` is the code the
    /// phone shows for it.
    pub fn enroll(&self, id: &str, typed_code: &str) -> Result<(), DeviceError> {
        if !safe_id(id) || !self.path("pending", id).exists() {
            return Err(DeviceError::NotPending);
        }
        let d: Device = serde_json::from_slice(&std::fs::read(self.path("pending", id))?)?;
        let typed: String = typed_code.chars().filter(char::is_ascii_digit).collect();
        if typed.is_empty() || typed != d.code() {
            return Err(DeviceError::WrongCode);
        }
        std::fs::rename(self.path("pending", id), self.path("enrolled", id))?;
        Ok(())
    }

    pub fn reject(&self, id: &str) -> Result<(), DeviceError> {
        if !safe_id(id) || !self.path("pending", id).exists() {
            return Err(DeviceError::NotPending);
        }
        std::fs::rename(self.path("pending", id), self.path("rejected", id))?;
        Ok(())
    }

    /// The signing key of an enrolled device, and only an enrolled one.
    #[must_use]
    pub fn verifying_key(&self, id: &str) -> Option<VerifyingKey> {
        if self.status(id) != DeviceStatus::Enrolled {
            return None;
        }
        let d: Device = serde_json::from_slice(&std::fs::read(self.path("enrolled", id)).ok()?).ok()?;
        VerifyingKey::from_bytes(&pub_bytes(&d.device_pub)?).ok()
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;

    fn tmp() -> PathBuf {
        std::env::temp_dir().join(format!("custodly-devices-test-{}", hex::encode(rand::random::<[u8; 8]>())))
    }

    fn enroll_file(seed: u8) -> EnrollFile {
        let key = SigningKey::from_bytes(&[seed; 32]).verifying_key().to_bytes();
        EnrollFile {
            v: ENROLL_VERSION.into(),
            device_id: device_id(&key),
            device_pub: hex::encode(key),
            name: "Pixel".into(),
            created: "2026-10-08T00:00:00Z".into(),
        }
    }

    #[test]
    fn a_phone_is_only_trusted_after_the_right_code_is_typed() {
        let dir = tmp();
        let reg = DeviceRegistry::new(&dir).unwrap();
        let e = enroll_file(1);
        assert_eq!(reg.record_pending(&e).unwrap(), DeviceStatus::Pending);
        assert!(reg.verifying_key(&e.device_id).is_none());
        assert!(matches!(reg.enroll(&e.device_id, "000000"), Err(DeviceError::WrongCode)));
        let code = reg.list_pending()[0].code();
        reg.enroll(&e.device_id, &format!("{} {}", &code[..3], &code[3..])).unwrap();
        assert!(reg.verifying_key(&e.device_id).is_some());
        assert_eq!(reg.status(&e.device_id), DeviceStatus::Enrolled);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn an_id_that_does_not_match_the_key_is_refused() {
        let dir = tmp();
        let reg = DeviceRegistry::new(&dir).unwrap();
        let mut e = enroll_file(2);
        e.device_id = enroll_file(3).device_id;
        assert!(matches!(reg.record_pending(&e), Err(DeviceError::Invalid)));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn a_rejected_phone_stays_rejected_and_cannot_requeue() {
        let dir = tmp();
        let reg = DeviceRegistry::new(&dir).unwrap();
        let e = enroll_file(4);
        reg.record_pending(&e).unwrap();
        reg.reject(&e.device_id).unwrap();
        assert_eq!(reg.record_pending(&e).unwrap(), DeviceStatus::Rejected);
        assert!(reg.list_pending().is_empty());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn path_like_ids_are_never_looked_up() {
        let dir = tmp();
        let reg = DeviceRegistry::new(&dir).unwrap();
        assert_eq!(reg.status("../enrolled/x"), DeviceStatus::Unknown);
        assert!(matches!(reg.enroll("../x", "123456"), Err(DeviceError::NotPending)));
        std::fs::remove_dir_all(dir).ok();
    }
}