//! The loop that turns files in the sync folder into stored, delivered keys.
//! One `tick` is: publish what the phone needs to see, record new phones,
//! open new deposits, and retry anything that is stored but not yet delivered.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::{DateTime, SecondsFormat, Utc};
use custodly_core::contract::{AcquiredVia, DepositMetadata};
use custodly_core::{AcquisitionSource, EntryMetadata, LOCAL_OWNER, SecretQuery, Tier, VaultEntry};
use custodly_core::{client, deposit_aad, seal_for_ingestion};
use serde::{Deserialize, Serialize};

use crate::acquire::{self, Ask, Minted, Proposal, ProviderConfig};
use crate::check::Check;
use crate::devices::{DeviceRegistry, DeviceStatus, EnrollFile};
use crate::envelope::{self, DepositFile, OpenError, Payload};
use crate::keystore::IntakeKey;
use crate::route;

const RETRY_DELIVERY_EVERY: Duration = Duration::from_secs(60);
const OPERATIONAL_BACKOFF: Duration = Duration::from_secs(60);
const PARTIAL_FILE_GRACE: Duration = Duration::from_secs(600);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FerrymanConfig {
    pub base_url: String,
    /// The Ferryman project id the key is deposited into.
    pub project: String,
    /// Name of the environment variable holding that project's bearer token.
    /// The token itself is never in this file.
    pub token_env: String,
}

/// Deliver through Ferryman's own channel: `ferry channel secret set NAME --to ...`.
/// Needs no server; the sealed envelope reaches each recipient through the project's
/// synced channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FerrySecretConfig {
    /// The project directory the Ferryman channel belongs to (`ferry --workspace`).
    pub workspace: PathBuf,
    /// Agents on that project's roster that should receive the key.
    pub to: Vec<String>,
    /// Path to `ferry`. Defaults to `ferry` on the PATH.
    #[serde(default)]
    pub ferry_bin: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectConfig {
    pub id: String,
    pub label: String,
    /// Other words the owner uses for this project ("sem", "legalredact").
    #[serde(default)]
    pub aliases: Vec<String>,
    /// Preferred: seal into the project's Ferryman channel.
    #[serde(default)]
    pub ferry_secret: Option<FerrySecretConfig>,
    /// Alternative: the `boundary/v1` HTTP deposit, for a running ferryman-server.
    #[serde(default)]
    pub ferryman: Option<FerrymanConfig>,
}

impl ProjectConfig {
    #[must_use]
    pub fn has_delivery(&self) -> bool {
        self.ferry_secret.is_some() || self.ferryman.is_some()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub sync_dir: PathBuf,
    pub state_dir: PathBuf,
    pub vault_path: PathBuf,
    #[serde(default = "default_cli")]
    pub keepassxc_cli: PathBuf,
    #[serde(default = "default_keyring")]
    pub keyring_name: String,
    #[serde(default = "default_intake_name")]
    pub intake_key_name: String,
    pub projects: Vec<ProjectConfig>,
    /// Providers Custodly can mint keys from on request.
    #[serde(default)]
    pub providers: Vec<ProviderConfig>,
}

fn default_cli() -> PathBuf {
    PathBuf::from(r"C:\Program Files\KeePassXC\keepassxc-cli.exe")
}
fn default_keyring() -> String {
    "custodly-working-vault".to_string()
}
fn default_intake_name() -> String {
    "default".to_string()
}

/// Where deposited keys are kept locally. `Vault` in production; a map in tests.
pub trait SecretStore: Send + Sync {
    fn put(&self, entry: &VaultEntry) -> Result<()>;
    fn get(&self, project: &str, label: &str) -> Result<String>;
}

impl SecretStore for custodly_vault::Vault {
    fn put(&self, entry: &VaultEntry) -> Result<()> {
        custodly_vault::Vault::put(self, entry).map_err(Into::into)
    }
    fn get(&self, project: &str, label: &str) -> Result<String> {
        Ok(custodly_vault::Vault::get(self, &SecretQuery::new(project, label))?.secret)
    }
}

/// Hands a stored key to a Ferryman project.
#[async_trait]
pub trait Deliver: Send + Sync {
    /// Returns a short human description of where it went.
    async fn deliver(&self, project: &ProjectConfig, item: &DeliveryItem<'_>) -> Result<String>;

    /// A small read-only test that the key works. Default: no test.
    async fn verify(&self, _name: &str, _value: &str) -> Check {
        Check::unchecked("no test available")
    }

    /// Mint the approved proposal at the provider. Overridden in tests.
    async fn mint(&self, prop: &Proposal, providers: &[ProviderConfig], store: &(dyn SecretStore + Sync)) -> Result<Minted, String> {
        acquire::mint(prop, providers, store).await
    }
}

/// Extra facts about one deposit that are not in the payload.
struct Ctx<'a> {
    asked_for: &'a str,
    why_not: &'a str,
    expires: Option<DateTime<Utc>>,
    tier: Tier,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredProposal {
    proposal: Proposal,
    device_id: String,
    created: DateTime<Utc>,
    purpose: String,
}

const PROPOSAL_LIFETIME_MINUTES: i64 = 60;

pub struct DeliveryItem<'a> {
    pub deposit_id: &'a str,
    pub project: &'a str,
    pub name: &'a str,
    pub label: &'a str,
    pub provider: &'a str,
    pub value: &'a str,
}

/// Production delivery: `ferry channel secret set` when the project has a `ferry_secret`
/// target, otherwise the `boundary/v1` HTTP deposit.
pub struct ProjectDeliver;

#[async_trait]
impl Deliver for ProjectDeliver {
    async fn verify(&self, name: &str, value: &str) -> Check {
        crate::check::http_check(name, value).await
    }

    async fn deliver(&self, project: &ProjectConfig, item: &DeliveryItem<'_>) -> Result<String> {
        if let Some(t) = &project.ferry_secret {
            return FerrySecretDeliver.deliver_to(t, item).await;
        }
        if let Some(t) = &project.ferryman {
            FerrymanDeliver.deliver_to(t, item).await?;
            return Ok(format!("delivered to {}", t.project));
        }
        anyhow::bail!("no delivery target configured")
    }
}

/// Seals into the project's Ferryman channel with `ferry channel secret set`.
/// The value goes to the process on stdin only, never on a command line.
pub struct FerrySecretDeliver;

impl FerrySecretDeliver {
    pub async fn deliver_to(&self, t: &FerrySecretConfig, item: &DeliveryItem<'_>) -> Result<String> {
        use tokio::io::AsyncWriteExt;
        let bin = t.ferry_bin.clone().unwrap_or_else(|| PathBuf::from("ferry"));
        let mut child = tokio::process::Command::new(&bin)
            .args(["channel", "secret", "set", item.name, "--to", &t.to.join(","), "--workspace"])
            .arg(&t.workspace)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("starting {}", bin.display()))?;
        let mut stdin = child.stdin.take().context("no stdin")?;
        stdin.write_all(item.value.as_bytes()).await?;
        drop(stdin);
        let out = tokio::time::timeout(Duration::from_secs(60), child.wait_with_output())
            .await
            .context("ferry did not finish in 60s")??;
        if !out.status.success() {
            let msg = String::from_utf8_lossy(&out.stderr);
            anyhow::bail!("ferry refused: {}", msg.trim().lines().last().unwrap_or("no message"));
        }
        Ok(format!("sealed into the {} channel for {}", item.project, t.to.join(", ")))
    }
}

/// The `boundary/v1` HTTP deposit, sealed to the
/// project's ingestion key. `boundary/v1` only knows two acquisition tracks and
/// a phone deposit is neither; `Track2Recipe` (a human-driven path) is the
/// closest and the label says what it really was. A proper `owner_deposit`
/// value is a contract change for a later `boundary/v1.1`.
pub struct FerrymanDeliver;

impl FerrymanDeliver {
    pub async fn deliver_to(&self, t: &FerrymanConfig, item: &DeliveryItem<'_>) -> Result<()> {
        let token = std::env::var(&t.token_env).with_context(|| format!("{} is not set", t.token_env))?;
        let key = client::fetch_ingestion_key(&t.base_url, &t.project, &token).await?;
        let sealed = seal_for_ingestion(&key, &deposit_aad(&t.project), item.value)?;
        let metadata = DepositMetadata {
            project: item.project.to_string(),
            provider: item.provider.to_string(),
            scope: "owner-supplied key (scope not verified)".to_string(),
            tier: 1,
            acquired_via: AcquiredVia::Track2Recipe,
            acquired_at: Utc::now(),
            expires_at: None,
            label: item.name.to_string(),
        };
        client::deposit(&t.base_url, &t.project, &token, item.deposit_id.to_string(), sealed, metadata).await?;
        Ok(())
    }
}

/// What the phone is told about a deposit. Never contains the value.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Receipt {
    pub id: String,
    pub device_id: String,
    /// `delivered`, `stored` or `rejected`.
    pub status: String,
    pub detail: String,
    pub project: String,
    pub name: String,
    /// What the owner said the key was for, as typed on the phone.
    #[serde(default)]
    pub purpose: String,
    /// `valid`, `invalid`, `unchecked` or `error`: the result of testing the key.
    #[serde(default)]
    pub check: String,
    #[serde(default)]
    pub check_detail: String,
    /// For `needs_approval`: the digest the phone must echo back to approve this proposal.
    #[serde(default)]
    pub digest: String,
    pub at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Undelivered {
    id: String,
    device_id: String,
    project: String,
    name: String,
    #[serde(default)]
    purpose: String,
    label: String,
    provider: String,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct TickReport {
    pub enrollments_seen: usize,
    pub deposits_stored: usize,
    pub deposits_rejected: usize,
    pub deposits_waiting: usize,
}

pub struct Intake<S: SecretStore, D: Deliver> {
    cfg: Config,
    key: IntakeKey,
    devices: DeviceRegistry,
    store: S,
    deliverer: D,
    backoff: Mutex<HashMap<PathBuf, Instant>>,
    last_retry: Mutex<Option<Instant>>,
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn now_string(now: DateTime<Utc>) -> String {
    now.to_rfc3339_opts(SecondsFormat::Secs, true)
}

enum Read<T> {
    Ok(T),
    /// Not valid yet (a sync can show half a file); try again later.
    Retry,
    /// Has stayed unreadable past the grace period; moved aside.
    Quarantined,
}

impl<S: SecretStore, D: Deliver> Intake<S, D> {
    pub fn new(cfg: Config, key: IntakeKey, store: S, deliverer: D) -> Result<Self> {
        for d in [cfg.sync_dir.join("inbox"), cfg.sync_dir.join("outbox")] {
            std::fs::create_dir_all(d)?;
        }
        for d in ["processed", "undelivered", "quarantine", "proposals"] {
            std::fs::create_dir_all(cfg.state_dir.join(d))?;
        }
        let devices = DeviceRegistry::new(cfg.state_dir.join("devices"))?;
        Ok(Self {
            cfg,
            key,
            devices,
            store,
            deliverer,
            backoff: Mutex::new(HashMap::new()),
            last_retry: Mutex::new(None),
        })
    }

    #[must_use]
    pub fn devices(&self) -> &DeviceRegistry {
        &self.devices
    }

    #[must_use]
    pub fn fingerprint(&self) -> String {
        envelope::fingerprint(&self.key.public())
    }

    fn inbox(&self) -> PathBuf {
        self.cfg.sync_dir.join("inbox")
    }
    fn outbox(&self) -> PathBuf {
        self.cfg.sync_dir.join("outbox")
    }

    fn publish(&self) -> Result<()> {
        let pairing = serde_json::json!({
            "v": "custodly-pairing/v1",
            "intake_name": "beastly",
            "intake_pub": hex::encode(self.key.public()),
            "fingerprint": self.fingerprint(),
        });
        write_atomic(&self.cfg.sync_dir.join("pairing.json"), &serde_json::to_vec_pretty(&pairing)?)?;
        let projects: Vec<_> =
            self.cfg.projects.iter().map(|p| serde_json::json!({"id": p.id, "label": p.label})).collect();
        write_atomic(
            &self.outbox().join("projects.json"),
            &serde_json::to_vec_pretty(&serde_json::json!({"projects": projects}))?,
        )
    }

    fn read_inbox_json<T: for<'de> Deserialize<'de>>(&self, path: &Path) -> Read<T> {
        if let Some(t) = std::fs::read(path).ok().and_then(|b| serde_json::from_slice(&b).ok()) {
            return Read::Ok(t);
        }
        let age = std::fs::metadata(path)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|m| SystemTime::now().duration_since(m).ok())
            .unwrap_or_default();
        if age > PARTIAL_FILE_GRACE {
            let name = path.file_name().map(|n| n.to_owned()).unwrap_or_default();
            let _ = std::fs::rename(path, self.cfg.state_dir.join("quarantine").join(name));
            tracing::warn!(file = %path.display(), "unreadable inbox file moved to quarantine");
            Read::Quarantined
        } else {
            Read::Retry
        }
    }

    fn inbox_files(&self, prefix: &str) -> Vec<PathBuf> {
        let mut v: Vec<PathBuf> = std::fs::read_dir(self.inbox())
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with(prefix) && n.ends_with(".json"))
            })
            .collect();
        v.sort();
        v
    }

    fn process_enrollments(&self) -> usize {
        let mut seen = 0;
        for path in self.inbox_files("enroll-") {
            if let Read::Ok(e) = self.read_inbox_json::<EnrollFile>(&path) {
                match self.devices.record_pending(&e) {
                    Ok(status) => {
                        seen += 1;
                        tracing::info!(device = %e.device_id, ?status, "enrollment file seen");
                    }
                    Err(err) => tracing::warn!(file = %path.display(), %err, "ignored enrollment file"),
                }
                let _ = std::fs::remove_file(&path);
            }
        }
        seen
    }

    /// Tell each phone where it stands, so its app can show "waiting for
    /// approval" or "enrolled".
    fn sync_device_status(&self, now: DateTime<Utc>) {
        let groups = [
            ("pending", self.devices.list_pending()),
            ("enrolled", self.devices.list_enrolled()),
            ("rejected", self.devices.list_rejected()),
        ];
        for (status, list) in groups {
            for d in list {
                let path = self.outbox().join(format!("device-{}.json", d.device_id));
                let current: Option<serde_json::Value> =
                    std::fs::read(&path).ok().and_then(|b| serde_json::from_slice(&b).ok());
                if current.as_ref().and_then(|v| v["status"].as_str()) == Some(status) {
                    continue;
                }
                let body = serde_json::json!({"device_id": d.device_id, "status": status, "at": now_string(now)});
                if let Ok(bytes) = serde_json::to_vec_pretty(&body) {
                    let _ = write_atomic(&path, &bytes);
                }
            }
        }
    }

    fn write_receipt(&self, r: &Receipt) {
        let path = self.outbox().join(format!("receipt-{}.json", r.id));
        match serde_json::to_vec_pretty(r) {
            Ok(b) => {
                if let Err(e) = write_atomic(&path, &b) {
                    tracing::error!(%e, "could not write receipt");
                }
            }
            Err(e) => tracing::error!(%e, "could not encode receipt"),
        }
    }

    fn reject(&self, f: &DepositFile, path: &Path, detail: &str, now: DateTime<Utc>) {
        self.write_receipt(&Receipt {
            id: f.id.clone(),
            device_id: f.device_id.clone(),
            status: "rejected".into(),
            detail: detail.to_string(),
            project: String::new(),
            name: String::new(),
            at: now_string(now),
            ..Receipt::default()
        });
        let _ = std::fs::write(self.cfg.state_dir.join("processed").join(&f.id), b"");
        let _ = std::fs::remove_file(path);
        tracing::warn!(id = %f.id, device = %f.device_id, %detail, "deposit rejected");
    }

    fn on_backoff(&self, path: &Path) -> bool {
        self.backoff
            .lock()
            .map(|m| m.get(path).is_some_and(|until| Instant::now() < *until))
            .unwrap_or(false)
    }

    async fn process_deposits(&self, now: DateTime<Utc>, report: &mut TickReport) {
        for path in self.inbox_files("dep-") {
            if self.on_backoff(&path) {
                continue;
            }
            let Read::Ok(f) = self.read_inbox_json::<DepositFile>(&path) else { continue };
            if f.id.len() != 32 || !f.id.chars().all(|c| c.is_ascii_hexdigit()) {
                let _ = std::fs::rename(&path, self.cfg.state_dir.join("quarantine").join(format!("bad-id-{}", hex::encode(rand::random::<[u8; 4]>()))));
                continue;
            }
            if self.cfg.state_dir.join("processed").join(&f.id).exists() {
                let _ = std::fs::remove_file(&path);
                continue;
            }
            let device_key = match self.devices.status(&f.device_id) {
                DeviceStatus::Enrolled => self.devices.verifying_key(&f.device_id),
                DeviceStatus::Pending => {
                    report.deposits_waiting += 1;
                    continue; // wait for the owner to enroll the phone
                }
                DeviceStatus::Rejected | DeviceStatus::Unknown => None,
            };
            let Some(device_key) = device_key else {
                self.reject(&f, &path, "this phone is not enrolled", now);
                report.deposits_rejected += 1;
                continue;
            };
            let mut payload = match envelope::open(self.key.secret(), &device_key, &f, now) {
                Ok(p) => p,
                Err(e) => {
                    let detail = match e {
                        OpenError::Stale => "too old or dated in the future; send it again".to_string(),
                        other => other.to_string(),
                    };
                    self.reject(&f, &path, &detail, now);
                    report.deposits_rejected += 1;
                    continue;
                }
            };
            if matches!(payload.kind.as_str(), "request" | "approve" | "deny") {
                self.handle_action(&f, &payload, now).await;
                let _ = std::fs::write(self.cfg.state_dir.join("processed").join(&f.id), b"");
                let _ = std::fs::remove_file(&path);
                report.deposits_stored += 1;
                continue;
            }
            // The phone said what the key is for in plain words; work out where it goes.
            // Anything unclear is still kept safely, just not delivered.
            let asked_for = std::mem::take(&mut payload.project);
            let (project, why_not) = match route::resolve(&asked_for, &self.cfg.projects) {
                route::Route::Project(p) => (Some(p), String::new()),
                route::Route::Ambiguous(ids) => (None, format!("\"{asked_for}\" fits more than one project ({})", ids.join(", "))),
                route::Route::Unknown => (None, format!("I could not tell which project \"{asked_for}\" is")),
            };
            payload.project = project.map_or_else(|| route::UNROUTED.to_string(), |p| p.id.clone());
            if payload.name.is_empty() {
                payload.name = route::derive_name(&asked_for, &payload.value, project);
            }
            let ctx = Ctx { asked_for: &asked_for, why_not: &why_not, expires: None, tier: Tier::Tier1 };
            match self.store_and_deliver(&f, &payload, project, &ctx, now).await {
                Ok(()) => {
                    report.deposits_stored += 1;
                    let _ = std::fs::write(self.cfg.state_dir.join("processed").join(&f.id), b"");
                    let _ = std::fs::remove_file(&path);
                }
                Err(e) => {
                    // The vault itself failed (locked, CLI missing): keep the file, try later.
                    tracing::error!(id = %f.id, error = %e, "could not store deposit; will retry");
                    if let Ok(mut m) = self.backoff.lock() {
                        m.insert(path.clone(), Instant::now() + OPERATIONAL_BACKOFF);
                    }
                }
            }
        }
    }

    fn note_receipt(&self, id: &str, device_id: &str, status: &str, detail: String, now: DateTime<Utc>) -> Receipt {
        Receipt {
            id: id.into(),
            device_id: device_id.into(),
            status: status.into(),
            detail,
            at: now_string(now),
            ..Receipt::default()
        }
    }

    /// A request for a key, or an approval/denial of a proposal. Never fails the file:
    /// every outcome, including problems, becomes a receipt the phone can show.
    async fn handle_action(&self, f: &DepositFile, p: &Payload, now: DateTime<Utc>) {
        match p.kind.as_str() {
            "request" => self.handle_request(f, p, now),
            _ => self.handle_decision(f, p, now).await,
        }
    }

    fn handle_request(&self, f: &DepositFile, p: &Payload, now: DateTime<Utc>) {
        let reply = |status: &str, detail: String| {
            let mut r = self.note_receipt(&f.id, &f.device_id, status, detail, now);
            r.purpose = format!("{} for {}", p.provider.clone().unwrap_or_default(), p.project);
            r
        };
        let project = match route::resolve(&p.project, &self.cfg.projects) {
            route::Route::Project(x) if x.has_delivery() => x,
            route::Route::Project(x) => {
                self.write_receipt(&reply("rejected", format!("{} has no Ferryman delivery set up, so there is nowhere to send a new key", x.label)));
                return;
            }
            route::Route::Ambiguous(ids) => {
                self.write_receipt(&reply("rejected", format!("\"{}\" fits more than one project ({})", p.project, ids.join(", "))));
                return;
            }
            route::Route::Unknown => {
                self.write_receipt(&reply("rejected", format!("I could not tell which project \"{}\" is", p.project)));
                return;
            }
        };
        let ask = Ask {
            provider_text: p.provider.clone().unwrap_or_default(),
            project_id: project.id.clone(),
            project_label: project.label.clone(),
            ttl_hours: p.ttl_hours.unwrap_or(24),
            budget_usd: p.budget_usd,
            requester: format!("phone:{}", f.device_id),
        };
        match acquire::propose(&ask, &self.cfg.providers, &self.store) {
            Err(why) => self.write_receipt(&reply("rejected", why)),
            Ok(prop) => {
                let stored = StoredProposal {
                    proposal: prop.clone(),
                    device_id: f.device_id.clone(),
                    created: now,
                    purpose: format!("{} for {}", ask.provider_text, p.project),
                };
                let path = self.cfg.state_dir.join("proposals").join(format!("{}.json", f.id));
                let saved = serde_json::to_vec(&stored).map_err(anyhow::Error::from).and_then(|b| write_atomic(&path, &b));
                if let Err(e) = saved {
                    self.write_receipt(&reply("rejected", format!("could not hold the proposal: {e}")));
                    return;
                }
                let mut r = reply("needs_approval", format!("{} Approve within {PROPOSAL_LIFETIME_MINUTES} minutes.", prop.summary));
                r.project = prop.project.clone();
                r.digest = prop.digest;
                self.write_receipt(&r);
            }
        }
    }

    async fn handle_decision(&self, f: &DepositFile, p: &Payload, now: DateTime<Utc>) {
        let rid = p.name.clone();
        let said = |status: &str, detail: &str| {
            let mut r = self.note_receipt(&rid, &f.device_id, status, detail.to_string(), now);
            r.purpose = String::new();
            r
        };
        let path = self.cfg.state_dir.join("proposals").join(format!("{rid}.json"));
        let Some(held) = std::fs::read(&path).ok().and_then(|b| serde_json::from_slice::<StoredProposal>(&b).ok()) else {
            // Do not overwrite the original receipt with a failure about a repeat tap.
            tracing::warn!(request = %rid, "approval for a proposal that is not pending");
            return;
        };
        let mut r = said("rejected", "");
        r.project = held.proposal.project.clone();
        r.purpose = held.purpose.clone();
        if held.device_id != f.device_id {
            r.detail = "that proposal was made for a different phone".into();
            self.write_receipt(&r);
            return;
        }
        if p.note.as_deref() != Some(held.proposal.digest.as_str()) {
            r.detail = "that answer was for a different proposal; nothing was minted".into();
            self.write_receipt(&r);
            return;
        }
        // Single use from here on, whatever happens next.
        let _ = std::fs::remove_file(&path);
        if now - held.created > chrono::Duration::minutes(PROPOSAL_LIFETIME_MINUTES) {
            r.detail = "that proposal expired; ask again".into();
            self.write_receipt(&r);
            return;
        }
        if p.kind == "deny" {
            r.status = "denied".into();
            r.detail = "you declined; nothing was minted".into();
            self.write_receipt(&r);
            return;
        }
        let minted = match self.deliverer.mint(&held.proposal, &self.cfg.providers, &self.store).await {
            Ok(m) => m,
            Err(e) => {
                r.status = "failed".into();
                r.detail = format!("nothing was minted: {e}");
                self.write_receipt(&r);
                return;
            }
        };
        let project = self.cfg.projects.iter().find(|x| x.id == held.proposal.project);
        let payload = Payload {
            project: held.proposal.project.clone(),
            name: minted.name.clone(),
            value: minted.value.clone(),
            provider: Some(held.proposal.provider.clone()),
            ..Payload::default()
        };
        let g = DepositFile { id: rid.clone(), ..f.clone() };
        let ctx = Ctx { asked_for: &held.purpose, why_not: "", expires: minted.expires_at, tier: minted.tier };
        if let Err(e) = self.store_and_deliver(&g, &payload, project, &ctx, now).await {
            tracing::error!(request = %rid, error = %e, "minted a key but could not store it");
            r.status = "failed".into();
            r.detail = format!("a key was minted but beastly could not store it ({e}); it expires on its own and is spend-capped");
            self.write_receipt(&r);
        }
    }

    async fn store_and_deliver(
        &self,
        f: &DepositFile,
        payload: &Payload,
        project: Option<&ProjectConfig>,
        ctx: &Ctx<'_>,
        now: DateTime<Utc>,
    ) -> Result<()> {
        let (asked_for, why_not) = (ctx.asked_for, ctx.why_not);
        let label = payload.label.clone().unwrap_or_else(|| payload.name.to_lowercase().replace('_', "-"));
        let provider = payload.provider.clone().unwrap_or_else(|| "other".to_string());
        let metadata = EntryMetadata::for_owner(
            LOCAL_OWNER,
            &provider,
            &payload.project,
            format!("{} (for: {asked_for}) -- sent from phone {}", payload.name, f.device_id),
            AcquisitionSource::PhoneDeposit { device_id: f.device_id.clone() },
            now,
            ctx.expires,
            ctx.tier,
        )?;
        self.store.put(&VaultEntry::new(label.clone(), metadata, payload.value.clone()))?;

        let mut receipt = Receipt {
            id: f.id.clone(),
            device_id: f.device_id.clone(),
            status: "stored".into(),
            detail: String::new(),
            project: payload.project.clone(),
            name: payload.name.clone(),
            purpose: asked_for.to_string(),
            at: now_string(now),
            ..Receipt::default()
        };
        // A quick, read-only test that the key works, before anything uses it.
        let check = self.deliverer.verify(&payload.name, &payload.value).await;
        receipt.check = check.state.clone();
        receipt.check_detail = check.detail.clone();
        let item = DeliveryItem {
            deposit_id: &f.id,
            project: &payload.project,
            name: &payload.name,
            label: &label,
            provider: &provider,
            value: &payload.value,
        };
        match project.filter(|p| p.has_delivery()) {
            // A dead key is never handed to an agent; it stays in the vault for the owner.
            _ if check.is_invalid() => {
                receipt.detail = format!("kept in the vault, NOT delivered: {}", check.detail);
            }
            None if project.is_none() => {
                receipt.detail = format!("kept safe in the vault, not delivered: {why_not}");
            }
            None => {
                receipt.detail = "kept in the vault; this project has no Ferryman delivery set up".into();
            }
            Some(project) => match self.deliverer.deliver(project, &item).await {
                Ok(detail) => {
                    receipt.status = "delivered".into();
                    receipt.detail = format!("{detail} as {}", payload.name);
                }
                Err(e) => {
                    receipt.detail = format!("kept in the vault; delivery to {} failed, will retry ({e})", project.label);
                    let u = Undelivered {
                        id: f.id.clone(),
                        device_id: f.device_id.clone(),
                        project: payload.project.clone(),
                        name: payload.name.clone(),
                        purpose: asked_for.to_string(),
                        label: label.clone(),
                        provider: provider.clone(),
                    };
                    write_atomic(&self.cfg.state_dir.join("undelivered").join(format!("{}.json", f.id)), &serde_json::to_vec(&u)?)?;
                }
            },
        }
        self.write_receipt(&receipt);
        Ok(())
    }

    async fn retry_undelivered(&self, now: DateTime<Utc>) {
        {
            let Ok(mut last) = self.last_retry.lock() else { return };
            if last.is_some_and(|t| t.elapsed() < RETRY_DELIVERY_EVERY) {
                return;
            }
            *last = Some(Instant::now());
        }
        let dir = self.cfg.state_dir.join("undelivered");
        for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let path = entry.path();
            let Some(u) = std::fs::read(&path).ok().and_then(|b| serde_json::from_slice::<Undelivered>(&b).ok()) else {
                continue;
            };
            let Some(project) = self.cfg.projects.iter().find(|p| p.id == u.project).filter(|p| p.has_delivery()) else {
                continue;
            };
            let Ok(value) = self.store.get(&u.project, &u.label) else { continue };
            let item = DeliveryItem {
                deposit_id: &u.id,
                project: &u.project,
                name: &u.name,
                label: &u.label,
                provider: &u.provider,
                value: &value,
            };
            if let Ok(detail) = self.deliverer.deliver(project, &item).await {
                let check = self.deliverer.verify(&u.name, &value).await;
                self.write_receipt(&Receipt {
                    id: u.id.clone(),
                    device_id: u.device_id.clone(),
                    status: "delivered".into(),
                    detail: format!("{detail} as {}", u.name),
                    project: u.project.clone(),
                    name: u.name.clone(),
                    purpose: u.purpose.clone(),
                    check: check.state,
                    check_detail: check.detail,
                    digest: String::new(),
                    at: now_string(now),
                });
                let _ = std::fs::remove_file(&path);
            }
        }
    }

    /// One pass over the sync folder.
    pub async fn tick(&self, now: DateTime<Utc>) -> Result<TickReport> {
        self.publish()?;
        let mut report = TickReport { enrollments_seen: self.process_enrollments(), ..TickReport::default() };
        self.sync_device_status(now);
        self.process_deposits(now, &mut report).await;
        self.retry_undelivered(now).await;
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::devices::ENROLL_VERSION;

    #[derive(Default, Clone)]
    struct MemStore(Arc<Mutex<HashMap<String, String>>>);
    impl SecretStore for MemStore {
        fn put(&self, e: &VaultEntry) -> Result<()> {
            self.0.lock().unwrap().insert(e.group_path.clone(), e.secret.clone());
            Ok(())
        }
        fn get(&self, project: &str, label: &str) -> Result<String> {
            self.0.lock().unwrap().get(&format!("{project}/{label}")).cloned().context("missing")
        }
    }

    #[derive(Clone)]
    struct FakeDeliver {
        up: Arc<Mutex<bool>>,
        got: Arc<Mutex<Vec<String>>>,
        check: Arc<Mutex<Check>>,
        mints: Arc<Mutex<u32>>,
    }
    #[async_trait]
    impl Deliver for FakeDeliver {
        async fn mint(&self, _p: &Proposal, _pr: &[ProviderConfig], _s: &(dyn SecretStore + Sync)) -> Result<Minted, String> {
            *self.mints.lock().unwrap() += 1;
            Ok(Minted {
                value: "sk-or-v1-minted".into(),
                name: "OPENROUTER_API_KEY".into(),
                expires_at: Some(Utc::now() + chrono::Duration::hours(24)),
                tier: Tier::Tier2,
                scope: "limit_usd:5.00".into(),
            })
        }

        async fn verify(&self, _n: &str, _v: &str) -> Check {
            self.check.lock().unwrap().clone()
        }

        async fn deliver(&self, _p: &ProjectConfig, item: &DeliveryItem<'_>) -> Result<String> {
            if *self.up.lock().unwrap() {
                self.got.lock().unwrap().push(format!("{}={}", item.name, item.value));
                Ok("delivered to custodly".to_string())
            } else {
                anyhow::bail!("ferryman is down")
            }
        }
    }

    struct Rig {
        intake: Intake<MemStore, FakeDeliver>,
        store: MemStore,
        deliver: FakeDeliver,
        sync: PathBuf,
        root: PathBuf,
        device: SigningKey,
    }

    fn rig(with_ferryman: bool) -> Rig {
        let root = std::env::temp_dir().join(format!("custodly-intake-test-{}", hex::encode(rand::random::<[u8; 8]>())));
        let cfg = Config {
            sync_dir: root.join("sync"),
            state_dir: root.join("state"),
            vault_path: root.join("v.kdbx"),
            keepassxc_cli: default_cli(),
            keyring_name: "t".into(),
            intake_key_name: "t".into(),
            projects: vec![ProjectConfig {
                id: "custodly".into(),
                label: "Custodly".into(),
                aliases: vec![],
                ferry_secret: with_ferryman.then(|| FerrySecretConfig {
                    workspace: PathBuf::from("w"),
                    to: vec!["beastly".into()],
                    ferry_bin: None,
                }),
                ferryman: None,
            }],
            providers: vec![ProviderConfig {
                id: "openrouter".into(),
                aliases: vec![],
                parent_project: "openrouter".into(),
                parent_label: "management-key".into(),
            }],
        };
        let store = MemStore::default();
        store.0.lock().unwrap().insert("openrouter/management-key".into(), "parent-secret".into());
        let deliver = FakeDeliver {
            up: Arc::new(Mutex::new(true)),
            got: Arc::default(),
            check: Arc::new(Mutex::new(Check::new("valid", "TestCo accepted the key"))),
            mints: Arc::default(),
        };
        let intake = Intake::new(cfg.clone(), IntakeKey::from_seed([5; 32]), store.clone(), deliver.clone()).unwrap();
        Rig { intake, store, deliver, sync: cfg.sync_dir, root, device: SigningKey::from_bytes(&[6; 32]) }
    }

    fn enroll(r: &Rig) -> String {
        let key = r.device.verifying_key().to_bytes();
        let e = EnrollFile {
            v: ENROLL_VERSION.into(),
            device_id: envelope::device_id(&key),
            device_pub: hex::encode(key),
            name: "Pixel".into(),
            created: "2026-10-08T00:00:00Z".into(),
        };
        std::fs::write(r.sync.join("inbox").join(format!("enroll-{}.json", e.device_id)), serde_json::to_vec(&e).unwrap()).unwrap();
        e.device_id
    }

    fn send(r: &Rig, project: &str, id: &str) {
        let payload = Payload {
            project: project.into(),
            name: "OPENROUTER_API_KEY".into(),
            value: "sk-secret-value".into(),
            label: None,
            provider: Some("openrouter".into()),
            note: None,
            ..Payload::default()
        };
        let f = envelope::seal(&r.intake.key.public(), &r.device, &payload, id, Utc::now()).unwrap();
        std::fs::write(r.sync.join("inbox").join(format!("dep-{id}.json")), serde_json::to_vec(&f).unwrap()).unwrap();
    }

    const ID1: &str = "00000000000000000000000000000001";
    const ID2: &str = "00000000000000000000000000000002";

    fn receipt(r: &Rig, id: &str) -> Receipt {
        serde_json::from_slice(&std::fs::read(r.sync.join("outbox").join(format!("receipt-{id}.json"))).unwrap()).unwrap()
    }

    #[tokio::test]
    async fn an_enrolled_phones_deposit_is_stored_delivered_and_receipted_without_the_value() {
        let r = rig(true);
        let dev = enroll(&r);
        r.intake.tick(Utc::now()).await.unwrap();
        let code = r.intake.devices().list_pending()[0].code();
        r.intake.devices().enroll(&dev, &code).unwrap();
        send(&r, "custodly", ID1);
        let rep = r.intake.tick(Utc::now()).await.unwrap();
        assert_eq!(rep.deposits_stored, 1);
        assert_eq!(r.store.get("custodly", "openrouter-api-key").unwrap(), "sk-secret-value");
        assert_eq!(r.deliver.got.lock().unwrap().as_slice(), ["OPENROUTER_API_KEY=sk-secret-value"]);
        let rc = receipt(&r, ID1);
        assert_eq!(rc.status, "delivered");
        // The phone learns where it went, what for, and that the key was tested.
        assert!(rc.detail.contains("custodly") && rc.detail.ends_with("as OPENROUTER_API_KEY"), "{}", rc.detail);
        assert_eq!(rc.purpose, "custodly");
        assert_eq!((rc.check.as_str(), rc.check_detail.as_str()), ("valid", "TestCo accepted the key"));
        assert!(!serde_json::to_string(&rc).unwrap().contains("sk-secret"));
        assert!(!r.sync.join("inbox").join(format!("dep-{ID1}.json")).exists());
        std::fs::remove_dir_all(&r.root).ok();
    }

    #[tokio::test]
    async fn a_deposit_from_a_phone_nobody_enrolled_waits_and_then_is_rejected_if_refused() {
        let r = rig(false);
        let dev = enroll(&r);
        send(&r, "custodly", ID1);
        let rep = r.intake.tick(Utc::now()).await.unwrap();
        assert_eq!(rep.deposits_waiting, 1);
        assert!(r.store.get("custodly", "openrouter-api-key").is_err());
        r.intake.devices().reject(&dev).unwrap();
        let rep = r.intake.tick(Utc::now()).await.unwrap();
        assert_eq!(rep.deposits_rejected, 1);
        assert_eq!(receipt(&r, ID1).status, "rejected");
        std::fs::remove_dir_all(&r.root).ok();
    }

    #[tokio::test]
    async fn a_key_for_an_unrecognised_project_is_kept_safe_but_not_delivered() {
        let r = rig(true);
        let dev = enroll(&r);
        r.intake.tick(Utc::now()).await.unwrap();
        let code = r.intake.devices().list_pending()[0].code();
        r.intake.devices().enroll(&dev, &code).unwrap();
        send(&r, "some thing nobody set up", ID1);
        r.intake.tick(Utc::now()).await.unwrap();
        let rc = receipt(&r, ID1);
        assert_eq!(rc.status, "stored");
        assert!(rc.detail.contains("could not tell which project"), "{}", rc.detail);
        assert_eq!(r.store.get("unrouted", "openrouter-api-key").unwrap(), "sk-secret-value");
        assert!(r.deliver.got.lock().unwrap().is_empty());
        assert!(!serde_json::to_string(&rc).unwrap().contains("sk-secret"));
        std::fs::remove_dir_all(&r.root).ok();
    }

    fn send_payload(r: &Rig, payload: &Payload, id: &str) {
        let f = envelope::seal(&r.intake.key.public(), &r.device, payload, id, Utc::now()).unwrap();
        std::fs::write(r.sync.join("inbox").join(format!("dep-{id}.json")), serde_json::to_vec(&f).unwrap()).unwrap();
    }

    fn ask_openrouter(r: &Rig, id: &str) {
        let p = Payload {
            kind: "request".into(),
            project: "custodly".into(),
            provider: Some("OpenRouter".into()),
            ttl_hours: Some(24),
            budget_usd: Some(5),
            ..Payload::default()
        };
        send_payload(r, &p, id);
    }

    fn answer(r: &Rig, kind: &str, request_id: &str, digest: &str, id: &str) {
        let p = Payload { kind: kind.into(), name: request_id.into(), note: Some(digest.into()), ..Payload::default() };
        send_payload(r, &p, id);
    }

    async fn enrolled_rig() -> Rig {
        let r = rig(true);
        let dev = enroll(&r);
        r.intake.tick(Utc::now()).await.unwrap();
        let code = r.intake.devices().list_pending()[0].code();
        r.intake.devices().enroll(&dev, &code).unwrap();
        r
    }

    const ID3: &str = "00000000000000000000000000000003";

    #[tokio::test]
    async fn a_request_becomes_a_proposal_and_nothing_is_minted_until_it_is_approved() {
        let r = enrolled_rig().await;
        ask_openrouter(&r, ID1);
        r.intake.tick(Utc::now()).await.unwrap();
        let rc = receipt(&r, ID1);
        assert_eq!(rc.status, "needs_approval");
        assert_eq!(rc.digest.len(), 64);
        assert!(rc.detail.contains("$5") && rc.detail.contains("24h") && rc.detail.contains("real money"), "{}", rc.detail);
        assert_eq!(*r.deliver.mints.lock().unwrap(), 0);

        answer(&r, "approve", ID1, &rc.digest, ID2);
        r.intake.tick(Utc::now()).await.unwrap();
        let done = receipt(&r, ID1);
        assert_eq!(done.status, "delivered", "{}", done.detail);
        assert!(done.detail.ends_with("as OPENROUTER_API_KEY"), "{}", done.detail);
        assert_eq!(done.check, "valid");
        assert_eq!(r.store.get("custodly", "openrouter-api-key").unwrap(), "sk-or-v1-minted");
        assert_eq!(r.deliver.got.lock().unwrap().as_slice(), ["OPENROUTER_API_KEY=sk-or-v1-minted"]);
        assert!(!serde_json::to_string(&done).unwrap().contains("sk-or-v1-minted"));

        // Tapping approve again does not mint a second key.
        answer(&r, "approve", ID1, &rc.digest, ID3);
        r.intake.tick(Utc::now()).await.unwrap();
        assert_eq!(*r.deliver.mints.lock().unwrap(), 1);
        std::fs::remove_dir_all(&r.root).ok();
    }

    #[tokio::test]
    async fn an_approval_for_the_wrong_proposal_or_a_denial_mints_nothing() {
        let r = enrolled_rig().await;
        ask_openrouter(&r, ID1);
        r.intake.tick(Utc::now()).await.unwrap();
        let rc = receipt(&r, ID1);
        answer(&r, "approve", ID1, &"0".repeat(64), ID2);
        r.intake.tick(Utc::now()).await.unwrap();
        assert_eq!(receipt(&r, ID1).status, "rejected");
        assert_eq!(*r.deliver.mints.lock().unwrap(), 0);
        // The right digest still works afterwards only if the proposal is still pending.
        answer(&r, "deny", ID1, &rc.digest, ID3);
        r.intake.tick(Utc::now()).await.unwrap();
        assert_eq!(receipt(&r, ID1).status, "denied");
        assert_eq!(*r.deliver.mints.lock().unwrap(), 0);
        std::fs::remove_dir_all(&r.root).ok();
    }

    #[tokio::test]
    async fn requests_that_cannot_be_served_say_why() {
        let r = enrolled_rig().await;
        // Unknown service.
        let p = Payload { kind: "request".into(), project: "custodly".into(), provider: Some("Acme Cloud".into()), ttl_hours: Some(24), budget_usd: Some(5), ..Payload::default() };
        send_payload(&r, &p, ID1);
        // No management key stored.
        r.store.0.lock().unwrap().clear();
        ask_openrouter(&r, ID2);
        r.intake.tick(Utc::now()).await.unwrap();
        let a = receipt(&r, ID1);
        assert_eq!(a.status, "rejected");
        assert!(a.detail.contains("Acme Cloud"), "{}", a.detail);
        let b = receipt(&r, ID2);
        assert_eq!(b.status, "rejected");
        assert!(b.detail.contains("management key"), "{}", b.detail);
        std::fs::remove_dir_all(&r.root).ok();
    }

    #[tokio::test]
    async fn a_key_that_fails_its_test_is_kept_but_never_delivered_and_the_phone_is_told() {
        let r = rig(true);
        let dev = enroll(&r);
        r.intake.tick(Utc::now()).await.unwrap();
        let code = r.intake.devices().list_pending()[0].code();
        r.intake.devices().enroll(&dev, &code).unwrap();
        *r.deliver.check.lock().unwrap() = Check::new("invalid", "TestCo rejected the key (401)");
        send(&r, "custodly", ID1);
        r.intake.tick(Utc::now()).await.unwrap();
        let rc = receipt(&r, ID1);
        assert_eq!(rc.status, "stored");
        assert_eq!(rc.check, "invalid");
        assert!(rc.detail.contains("NOT delivered") && rc.detail.contains("401"), "{}", rc.detail);
        assert!(r.deliver.got.lock().unwrap().is_empty());
        assert!(r.store.get("custodly", "openrouter-api-key").is_ok());
        std::fs::remove_dir_all(&r.root).ok();
    }

    #[tokio::test]
    async fn a_failed_delivery_says_where_it_failed() {
        let r = rig(true);
        let dev = enroll(&r);
        r.intake.tick(Utc::now()).await.unwrap();
        let code = r.intake.devices().list_pending()[0].code();
        r.intake.devices().enroll(&dev, &code).unwrap();
        *r.deliver.up.lock().unwrap() = false;
        send(&r, "custodly", ID1);
        r.intake.tick(Utc::now()).await.unwrap();
        let rc = receipt(&r, ID1);
        assert_eq!(rc.status, "stored");
        assert!(rc.detail.contains("delivery to Custodly failed"), "{}", rc.detail);
        std::fs::remove_dir_all(&r.root).ok();
    }

    #[tokio::test]
    async fn plain_words_and_no_name_are_enough_to_route_and_name_a_key() {
        let r = rig(true);
        let dev = enroll(&r);
        r.intake.tick(Utc::now()).await.unwrap();
        let code = r.intake.devices().list_pending()[0].code();
        r.intake.devices().enroll(&dev, &code).unwrap();
        let payload = Payload {
            project: "openrouter for Custodly please".into(),
            name: String::new(),
            value: "sk-or-v1-abc".into(),
            label: None,
            provider: None,
            note: None,
            ..Payload::default()
        };
        let f = envelope::seal(&r.intake.key.public(), &r.device, &payload, ID1, Utc::now()).unwrap();
        std::fs::write(r.sync.join("inbox").join(format!("dep-{ID1}.json")), serde_json::to_vec(&f).unwrap()).unwrap();
        r.intake.tick(Utc::now()).await.unwrap();
        assert_eq!(receipt(&r, ID1).status, "delivered");
        assert_eq!(r.deliver.got.lock().unwrap().as_slice(), ["OPENROUTER_API_KEY=sk-or-v1-abc"]);
        std::fs::remove_dir_all(&r.root).ok();
    }

    #[tokio::test]
    async fn a_replayed_deposit_id_is_not_stored_twice() {
        let r = rig(false);
        let dev = enroll(&r);
        r.intake.tick(Utc::now()).await.unwrap();
        let code = r.intake.devices().list_pending()[0].code();
        r.intake.devices().enroll(&dev, &code).unwrap();
        send(&r, "custodly", ID1);
        r.intake.tick(Utc::now()).await.unwrap();
        r.store.0.lock().unwrap().clear();
        send(&r, "custodly", ID1);
        r.intake.tick(Utc::now()).await.unwrap();
        assert!(r.store.0.lock().unwrap().is_empty());
        std::fs::remove_dir_all(&r.root).ok();
    }

    #[tokio::test]
    async fn when_ferryman_is_down_the_key_is_kept_and_delivered_on_a_later_pass() {
        let r = rig(true);
        let dev = enroll(&r);
        r.intake.tick(Utc::now()).await.unwrap();
        let code = r.intake.devices().list_pending()[0].code();
        r.intake.devices().enroll(&dev, &code).unwrap();
        *r.deliver.up.lock().unwrap() = false;
        send(&r, "custodly", ID2);
        r.intake.tick(Utc::now()).await.unwrap();
        assert_eq!(receipt(&r, ID2).status, "stored");
        *r.deliver.up.lock().unwrap() = true;
        *r.intake.last_retry.lock().unwrap() = None;
        r.intake.tick(Utc::now()).await.unwrap();
        assert_eq!(receipt(&r, ID2).status, "delivered");
        assert_eq!(r.deliver.got.lock().unwrap().len(), 1);
        std::fs::remove_dir_all(&r.root).ok();
    }

    #[tokio::test]
    async fn pairing_and_project_list_are_published_for_the_phone() {
        let r = rig(false);
        r.intake.tick(Utc::now()).await.unwrap();
        let pairing: serde_json::Value = serde_json::from_slice(&std::fs::read(r.sync.join("pairing.json")).unwrap()).unwrap();
        assert_eq!(pairing["fingerprint"], r.intake.fingerprint());
        let projects: serde_json::Value =
            serde_json::from_slice(&std::fs::read(r.sync.join("outbox/projects.json")).unwrap()).unwrap();
        assert_eq!(projects["projects"][0]["id"], "custodly");
        std::fs::remove_dir_all(&r.root).ok();
    }
}