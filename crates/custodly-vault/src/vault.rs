//! `Vault` wraps `keepassxc-cli` as a non-interactive subprocess: the
//! vault password (from the OS keystore) and any entry password are
//! written to the child's piped stdin rather than typed at a terminal
//! prompt, which is what actually makes this safe to call from a script
//! or an agent -- no masked-input prompt to hang on.

use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use chrono::{DateTime, Utc};
use custodly_core::{AcquisitionSource, EntryMetadata, SecretQuery, Tier, VaultEntry};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("keepassxc-cli not found at {0}")]
    CliNotFound(PathBuf),
    #[error("keepassxc-cli failed: {0}")]
    CliFailed(String),
    #[error("no entry found for {project}/{label}")]
    NotFound { project: String, label: String },
    #[error("entry {project}/{label} has no valid Custodly metadata in its Notes field")]
    UnparseableMetadata { project: String, label: String },
    #[error(transparent)]
    Keyring(#[from] keyring::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub struct Vault {
    cli_path: PathBuf,
    db_path: PathBuf,
    keyring_name: String,
}

impl Vault {
    #[must_use]
    pub fn new(
        cli_path: impl Into<PathBuf>,
        db_path: impl Into<PathBuf>,
        keyring_name: impl Into<String>,
    ) -> Self {
        Self {
            cli_path: cli_path.into(),
            db_path: db_path.into(),
            keyring_name: keyring_name.into(),
        }
    }

    fn db_str(&self) -> &str {
        self.db_path.to_str().expect("vault path is valid UTF-8")
    }

    fn password(&self) -> Result<String, VaultError> {
        Ok(crate::password::get_or_create(&self.keyring_name)?)
    }

    /// Run `keepassxc-cli` with the given args, feeding the vault
    /// password followed by `extra_stdin` (one line each) to its stdin.
    /// `extra_stdin` exists for `add`/`edit -p`, which separately prompt
    /// for the entry's own password (twice: enter + confirm).
    fn run(&self, args: &[&str], extra_stdin: &[&str]) -> Result<String, VaultError> {
        if !self.cli_path.exists() {
            return Err(VaultError::CliNotFound(self.cli_path.clone()));
        }
        let mut child = Command::new(&self.cli_path)
            .args(args.iter().copied())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        {
            let stdin = child.stdin.as_mut().expect("stdin was piped");
            writeln!(stdin, "{}", self.password()?)?;
            for line in extra_stdin {
                writeln!(stdin, "{line}")?;
            }
        }
        let output = child.wait_with_output()?;
        if !output.status.success() {
            return Err(VaultError::CliFailed(
                String::from_utf8_lossy(&output.stderr).into_owned(),
            ));
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    /// Ensure the group for `project` exists. Idempotent -- `mkdir`
    /// failing because the group is already there is not an error here.
    fn ensure_group(&self, project: &str) -> Result<(), VaultError> {
        let _ = self.run(&["mkdir", "-q", self.db_str(), project], &[]);
        Ok(())
    }

    /// Store `entry`. This is the only write path, and it takes a
    /// `custodly_core::VaultEntry` -- so a secret cannot be written
    /// without its `EntryMetadata` (project, source, tier) already
    /// validated by `EntryMetadata::new`. Metadata is serialized into
    /// the entry's Notes field (`keepassxc-cli` has no custom-attribute
    /// flag), so it's also visible to a human opening the vault directly
    /// in the KeePassXC GUI.
    pub fn put(&self, entry: &VaultEntry) -> Result<(), VaultError> {
        self.ensure_group(&entry.metadata.project)?;
        let notes = encode_metadata(&entry.metadata);
        self.run(
            &[
                "add", "-q", "-p", "--notes", &notes, self.db_str(),
                entry.group_path.as_str(),
            ],
            &[entry.secret.as_str(), entry.secret.as_str()],
        )?;
        Ok(())
    }

    /// Fetch exactly one secret. This opens the single entry
    /// `query.group_path()` names via `show -a Password -a Notes` --
    /// only those two named attributes of that one entry come back.
    /// There is no `list`/`search` method on `Vault`: an agent scoped to
    /// a project asks for one key and gets one key, never a handle to
    /// browse the rest of the vault. A query that doesn't resolve to
    /// exactly that one entry is `NotFound`, not an empty list.
    pub fn get(&self, query: &SecretQuery) -> Result<VaultEntry, VaultError> {
        let entry_path = query.group_path();
        let out = self
            .run(
                &[
                    "show", "-q", "-s", "-a", "Password", "-a", "Notes", self.db_str(),
                    &entry_path,
                ],
                &[],
            )
            .map_err(|_| VaultError::NotFound {
                project: query.project.clone(),
                label: query.label.clone(),
            })?;
        let mut lines = out.lines();
        let secret = lines.next().unwrap_or_default().to_string();
        let notes = lines.collect::<Vec<_>>().join("\n");
        let metadata = decode_metadata(&notes).ok_or_else(|| VaultError::UnparseableMetadata {
            project: query.project.clone(),
            label: query.label.clone(),
        })?;
        Ok(VaultEntry::new(query.label.clone(), metadata, secret))
    }
}

/// Serialize `EntryMetadata` into the entry's Notes field as plain
/// `key=value` lines -- readable by Josh directly in the KeePassXC GUI,
/// not just parseable by this crate.
fn encode_metadata(m: &EntryMetadata) -> String {
    let acquired_via = match &m.acquired_via {
        AcquisitionSource::GithubAppInstallationToken => "github-app-installation-token".to_string(),
        AcquisitionSource::ManualEntry => "manual-entry".to_string(),
        AcquisitionSource::Migrated { found_at } => format!("migrated:{found_at}"),
    };
    let tier = match m.tier {
        Tier::Tier0 => "0",
        Tier::Tier1 => "1",
        Tier::Tier2 => "2",
    };
    let expires_at = m.expires_at.map(|t| t.to_rfc3339()).unwrap_or_default();
    format!(
        "[custodly:metadata:v1]\nprovider={}\nproject={}\nsource_description={}\n\
         acquired_via={}\nacquired_at={}\nexpires_at={}\ntier={}",
        m.provider,
        m.project,
        m.source_description,
        acquired_via,
        m.acquired_at.to_rfc3339(),
        expires_at,
        tier,
    )
}

/// Parse a Notes block back into `EntryMetadata`. `None` for anything
/// short of a complete, valid record -- a partially-written or hand-
/// edited entry is surfaced as `VaultError::UnparseableMetadata` by the
/// caller rather than silently treated as having no provenance.
fn decode_metadata(notes: &str) -> Option<EntryMetadata> {
    let mut fields: HashMap<&str, String> = HashMap::new();
    for line in notes.lines() {
        if let Some((k, v)) = line.split_once('=') {
            fields.insert(k.trim(), v.trim().to_string());
        }
    }
    let acquired_via = match fields.get("acquired_via")?.as_str() {
        "github-app-installation-token" => AcquisitionSource::GithubAppInstallationToken,
        "manual-entry" => AcquisitionSource::ManualEntry,
        s if s.starts_with("migrated:") => AcquisitionSource::Migrated {
            found_at: s["migrated:".len()..].to_string(),
        },
        _ => return None,
    };
    let tier = match fields.get("tier")?.as_str() {
        "0" => Tier::Tier0,
        "1" => Tier::Tier1,
        "2" => Tier::Tier2,
        _ => return None,
    };
    let acquired_at: DateTime<Utc> = fields.get("acquired_at")?.parse().ok()?;
    let expires_at = fields
        .get("expires_at")
        .filter(|s| !s.is_empty())
        .and_then(|s| s.parse().ok());

    EntryMetadata::new(
        fields.get("provider")?.clone(),
        fields.get("project")?.clone(),
        fields.get("source_description")?.clone(),
        acquired_via,
        acquired_at,
        expires_at,
        tier,
    )
    .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_round_trips_through_notes_encoding() {
        let m = EntryMetadata::new(
            "github",
            "redaktly",
            "GitHub App installation token, contents:read",
            AcquisitionSource::GithubAppInstallationToken,
            Utc::now(),
            None,
            Tier::Tier1,
        )
        .unwrap();
        let notes = encode_metadata(&m);
        let decoded = decode_metadata(&notes).expect("valid metadata block should decode");
        assert_eq!(decoded.project, m.project);
        assert_eq!(decoded.tier, m.tier);
    }
}
