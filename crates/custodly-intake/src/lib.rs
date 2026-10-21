//! Receives keys sent from the Custodly phone app as sealed files in a
//! Syncthing folder. See `docs/PHONE-DEPOSIT.md`.

pub mod acquire;
pub mod check;
pub mod devices;
pub mod envelope;
pub mod intake;
pub mod keystore;
pub mod route;

pub use devices::{Device, DeviceError, DeviceRegistry, DeviceStatus, EnrollFile};
pub use intake::{
    Config, Deliver, FerrySecretConfig, FerrySecretDeliver, FerrymanDeliver, Intake, ProjectConfig, ProjectDeliver, Receipt,
    SecretStore, TickReport,
};
pub use keystore::IntakeKey;