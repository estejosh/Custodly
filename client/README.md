# client/

The real implementation of the local client now lives in `../crates/`
(`custodly-vault` wraps `keepassxc-cli`; `custodly-cli` exposes the
request contract). This directory holds the vault databases themselves:

- `vault/working.kdbx` — day-to-day scoped keys. Password resolved
  through the OS keystore (`keyring`), never a file on disk.
- `vault/master.kdbx` — not yet created. Root/dashboard-mintable
  credentials go here once it exists; its password is Josh's alone, typed
  to unlock, never machine-held. See `../docs/THREAT-MODEL.md`.
