//! Minting a key on request, as opposed to receiving one.
//!
//! The phone only ever *asks*. Custodly assembles the exact proposal (provider, project,
//! lifetime, spend cap), the owner approves that proposal and nothing else, and only then
//! does the mint happen. See `custodly-remote-approval.md`: the remote channel can answer
//! something Custodly built, never originate an open-ended mint.

use chrono::{DateTime, Utc};
use custodly_core::{Budget, CredentialRequest, ParentCredential, ProviderAdapter, Tier};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::intake::SecretStore;

/// A provider Custodly can mint for, and where its parent (management) credential lives.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderConfig {
    /// `openrouter`. Only providers with a built adapter work; others say so.
    pub id: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    /// Vault group and label of the parent credential used to mint children.
    pub parent_project: String,
    pub parent_label: String,
}

/// What the owner asked for, after the project text has been resolved.
#[derive(Debug, Clone)]
pub struct Ask {
    pub provider_text: String,
    pub project_id: String,
    pub project_label: String,
    pub ttl_hours: u32,
    pub budget_usd: Option<u32>,
    pub requester: String,
}

/// Exactly what would be minted. The digest binds an approval to this and nothing else.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proposal {
    pub provider: String,
    pub project: String,
    pub resource: String,
    pub ttl_seconds: u64,
    pub budget_usd: Option<u32>,
    pub requester: String,
    pub summary: String,
    pub digest: String,
}

#[derive(Debug)]
pub struct Minted {
    pub value: String,
    /// The Ferryman secret name, e.g. `OPENROUTER_API_KEY`.
    pub name: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub tier: Tier,
    pub scope: String,
}

#[must_use]
pub fn match_provider<'a>(text: &str, providers: &'a [ProviderConfig]) -> Option<&'a ProviderConfig> {
    let t = format!(" {} ", crate::route::words(text));
    providers.iter().find(|p| {
        std::iter::once(p.id.as_str())
            .chain(p.aliases.iter().map(String::as_str))
            .map(crate::route::words)
            .any(|w| !w.is_empty() && t.contains(&format!(" {w} ")))
    })
}

fn digest(p: &Proposal) -> String {
    let canon = format!(
        "custodly-proposal/v1\n{}\n{}\n{}\n{}\n{}\n{}",
        p.provider,
        p.project,
        p.resource,
        p.ttl_seconds,
        p.budget_usd.map_or_else(String::new, |b| b.to_string()),
        p.requester
    );
    hex::encode(Sha256::digest(canon.as_bytes()))
}

/// Builds the proposal, or says in plain words why nothing can be minted.
pub fn propose(ask: &Ask, providers: &[ProviderConfig], store: &dyn SecretStore) -> Result<Proposal, String> {
    let Some(p) = match_provider(&ask.provider_text, providers) else {
        return Err(format!("I do not know how to get keys from \"{}\" yet", ask.provider_text));
    };
    if p.id != "openrouter" {
        return Err(format!("{} is listed but has no adapter built yet", p.id));
    }
    let Some(budget) = ask.budget_usd else {
        return Err("OpenRouter keys need a spend cap; say how many dollars".into());
    };
    if store.get(&p.parent_project, &p.parent_label).is_err() {
        return Err(format!(
            "no OpenRouter management key is stored on beastly (expected {}/{}); add one first",
            p.parent_project, p.parent_label
        ));
    }
    let resource = ask.project_id.clone();
    let ttl_seconds = u64::from(ask.ttl_hours) * 3600;
    let mut prop = Proposal {
        provider: p.id.clone(),
        project: ask.project_id.clone(),
        resource,
        ttl_seconds,
        budget_usd: Some(budget),
        requester: ask.requester.clone(),
        summary: format!(
            "Mint an {} key for {}: capped at ${budget}, expires in {}h, then deliver it to {} as OPENROUTER_API_KEY. This spends real money up to the cap.",
            p.id, ask.project_label, ask.ttl_hours, ask.project_label
        ),
        digest: String::new(),
    };
    prop.digest = digest(&prop);
    Ok(prop)
}

/// Mints, verifies and scores. Only called after the owner approved `prop`'s digest.
pub async fn mint(prop: &Proposal, providers: &[ProviderConfig], store: &dyn SecretStore) -> Result<Minted, String> {
    let Some(p) = providers.iter().find(|p| p.id == prop.provider) else {
        return Err("that provider is no longer configured".into());
    };
    let parent = store.get(&p.parent_project, &p.parent_label).map_err(|e| format!("could not read the management key: {e}"))?;
    let budget = prop.budget_usd.map(|b| Budget { limit_minor_units: u64::from(b) * 100, currency: "USD".into() });
    let req = CredentialRequest::new(
        &prop.provider,
        &prop.resource,
        vec!["inference".into()],
        prop.ttl_seconds,
        budget,
        &prop.requester,
    )
    .map_err(|e| e.to_string())?;
    let adapter = custodly_openrouter::OpenRouterAdapter::new("https://openrouter.ai", &prop.resource, reqwest::Client::new());
    let parent = ParentCredential { secret: parent };
    let child = adapter.mint(&parent, &req).await.map_err(|e| format!("OpenRouter refused: {e}"))?;
    let tier = match adapter.verify(&child, &req).await {
        Ok(a) => Tier::score(Some(&a)),
        Err(_) => Tier::score(None),
    };
    Ok(Minted {
        value: child.secret,
        name: "OPENROUTER_API_KEY".into(),
        expires_at: child.expires_at,
        tier,
        scope: child.granted_actions.join(","),
    })
}
