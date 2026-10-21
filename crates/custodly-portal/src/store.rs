//! One JSON file per pending request under a directory -- the same
//! "readable outside the code" instinct as `custodly-vault`'s Notes
//! encoding (`custodly-owner-portal.md`). No database: there is no scale
//! problem yet, and a flat file is something Josh can `cat` by hand if a
//! request needs debugging.

use std::path::PathBuf;

use thiserror::Error;

use crate::models::PendingRequest;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("no pending request {0:?}")]
    NotFound(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

pub struct PendingStore {
    dir: PathBuf,
}

impl PendingStore {
    /// Opens (creating if needed) a directory of pending-request files.
    pub fn new(dir: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    fn path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.json"))
    }

    /// Write `request`, replacing any existing file for the same id --
    /// the only way this crate ever changes a request's status (there is
    /// no partial-update path, so a reader never sees a half-written
    /// status change).
    pub fn put(&self, request: &PendingRequest) -> Result<(), StoreError> {
        let json = serde_json::to_vec_pretty(request)?;
        let tmp = self.path(&request.id).with_extension("json.tmp");
        std::fs::write(&tmp, json)?;
        std::fs::rename(&tmp, self.path(&request.id))?;
        Ok(())
    }

    /// Every readable request, newest first. Unreadable files are skipped so one bad file can't blank the home page.
    pub fn list(&self) -> Vec<PendingRequest> {
        let mut all: Vec<PendingRequest> = std::fs::read_dir(&self.dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
            .filter_map(|e| serde_json::from_slice(&std::fs::read(e.path()).ok()?).ok())
            .collect();
        all.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        all
    }

    pub fn get(&self, id: &str) -> Result<PendingRequest, StoreError> {
        let bytes = std::fs::read(self.path(id)).map_err(|_| StoreError::NotFound(id.to_string()))?;
        Ok(serde_json::from_slice(&bytes)?)
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;
    use crate::models::{PendingKind, PendingStatus};

    fn sample(id: &str) -> PendingRequest {
        PendingRequest {
            id: id.to_string(),
            owner: "josh".into(),
            project: "custodly".into(),
            kind: PendingKind::Authorize {
                provider: "slack".into(),
                resource: "acme-workspace".into(),
                scopes: vec!["chat:write".into()],
            },
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::minutes(15),
            status: PendingStatus::Pending,
        }
    }

    #[test]
    fn a_request_round_trips_through_the_store() {
        let dir = std::env::temp_dir().join(format!("custodly-portal-test-{}", crate::code::generate_id()));
        let store = PendingStore::new(&dir).unwrap();
        let req = sample("abc123");
        store.put(&req).unwrap();
        let fetched = store.get("abc123").unwrap();
        assert_eq!(fetched.id, "abc123");
        assert_eq!(fetched.owner, "josh");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_unknown_id_is_not_found_not_a_panic() {
        let dir = std::env::temp_dir().join(format!("custodly-portal-test-{}", crate::code::generate_id()));
        let store = PendingStore::new(&dir).unwrap();
        let err = store.get("does-not-exist").unwrap_err();
        assert!(matches!(err, StoreError::NotFound(_)));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn putting_the_same_id_twice_overwrites_rather_than_duplicating() {
        let dir = std::env::temp_dir().join(format!("custodly-portal-test-{}", crate::code::generate_id()));
        let store = PendingStore::new(&dir).unwrap();
        let mut req = sample("abc123");
        store.put(&req).unwrap();
        req.status = PendingStatus::Fulfilled;
        store.put(&req).unwrap();
        let fetched = store.get("abc123").unwrap();
        assert_eq!(fetched.status, PendingStatus::Fulfilled);
        std::fs::remove_dir_all(&dir).ok();
    }
}
