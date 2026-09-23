//! The Custodly-side caller of Ferryman's `boundary/v1` routes
//! (`ferryman-server`'s `GET .../boundary/ingestion-key` and
//! `POST .../boundary/deposit`, see `docs/BOUNDARY.md`). This is the
//! client half of the walking skeleton `START-HERE.md` step 5 asks for:
//! request to sealed deposit, end to end, one provider.
//!
//! Authenticates with the project's own Ferryman bearer token - the same
//! one used for every other project-scoped Ferryman call, per how
//! `ferryman-server` currently authorizes `boundary/v1` (see that route's
//! own doc comment). A Custodly-specific, narrower-scoped credential is a
//! reasonable future refinement, not something to invent unasked here.

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::contract::{DepositMetadata, DepositReceipt, SealedSecret};

/// Fetch a project's ingestion public key from Ferryman, hex-encoded -
/// what [`crate::seal::seal_for_ingestion`] needs as its recipient.
pub async fn fetch_ingestion_key(base_url: &str, project: &str, token: &str) -> Result<String> {
    #[derive(Deserialize)]
    struct Response {
        public_key_hex: String,
        contract_version: String,
    }
    let url = format!("{base_url}/v1/projects/{project}/boundary/ingestion-key");
    let response = reqwest::Client::new()
        .get(&url)
        .bearer_auth(token)
        .send()
        .await
        .with_context(|| format!("requesting ingestion key from {url}"))?;
    if !response.status().is_success() {
        bail!(
            "ingestion key request to {url} failed: {}",
            response.status()
        )
    }
    let body: Response = response.json().await.context("parsing ingestion key response")?;
    if body.contract_version != crate::CONTRACT_VERSION {
        bail!(
            "Ferryman answered with contract version {:?}, expected {:?}",
            body.contract_version,
            crate::CONTRACT_VERSION
        )
    }
    Ok(body.public_key_hex)
}

/// Deposit a sealed secret with Ferryman for `project`. `deposit_id` is
/// Custodly's own id for its audit record - see [`DepositReceipt`].
pub async fn deposit(
    base_url: &str,
    project: &str,
    token: &str,
    deposit_id: String,
    sealed_secret: SealedSecret,
    metadata: DepositMetadata,
) -> Result<DepositReceipt> {
    let url = format!("{base_url}/v1/projects/{project}/boundary/deposit");
    let response = reqwest::Client::new()
        .post(&url)
        .bearer_auth(token)
        .json(&serde_json::json!({
            "deposit_id": deposit_id,
            "sealed_secret": sealed_secret,
            "metadata": metadata,
        }))
        .send()
        .await
        .with_context(|| format!("depositing with {url}"))?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        bail!("deposit to {url} failed: {status}: {body}")
    }
    response.json().await.context("parsing deposit receipt")
}
