//! The intake's X25519 private key. It lives in the Windows Credential
//! Manager (the same place the vault password does), never in a file, so a
//! copy of the sync folder or the project folder does not contain it.

use anyhow::{Context, Result};
use x25519_dalek::{PublicKey, StaticSecret};

const SERVICE: &str = "custodly-intake";

pub struct IntakeKey {
    secret: StaticSecret,
}

impl IntakeKey {
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self { secret: StaticSecret::from(seed) }
    }

    /// Load the key stored under `name`, creating it on first run.
    pub fn load_or_create(name: &str) -> Result<Self> {
        let entry = keyring::Entry::new(SERVICE, name).context("opening the credential store")?;
        match entry.get_password() {
            Ok(hex_seed) => {
                let seed: [u8; 32] = hex::decode(hex_seed.trim())
                    .context("stored intake key is not hex")?
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("stored intake key is not 32 bytes"))?;
                Ok(Self::from_seed(seed))
            }
            Err(keyring::Error::NoEntry) => {
                let mut seed = [0_u8; 32];
                rand::Rng::fill_bytes(&mut rand::rng(), &mut seed);
                entry.set_password(&hex::encode(seed)).context("saving the new intake key")?;
                Ok(Self::from_seed(seed))
            }
            Err(e) => Err(e).context("reading the intake key"),
        }
    }

    #[must_use]
    pub fn secret(&self) -> &StaticSecret {
        &self.secret
    }

    #[must_use]
    pub fn public(&self) -> [u8; 32] {
        *PublicKey::from(&self.secret).as_bytes()
    }
}