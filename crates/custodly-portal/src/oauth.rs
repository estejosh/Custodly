//! `OAuthProvider`: what `custodly-portal` needs from a provider's OAuth
//! flow to run the "Authorize" pending-kind end to end. One real
//! implementation exists here (`SlackOAuth`) -- confirmed live against
//! Slack's own docs (`docs.slack.dev/authentication/installing-with-oauth`,
//! researched 28 Sep 2026): the `oauth.v2.access` token-exchange endpoint,
//! its `scope`/`user_scope` params, and its response shape. Every other
//! provider named in `custodly-provider-roadmap.md`'s Phase 2 (Zoho, Keap,
//! Google Workspace, Zoom) needs the same confirmation pass before it gets
//! a real impl -- not guessed from "it's OAuth, they're all the same,"
//! which is exactly the assumption that turned out wrong for Slack's
//! *narrowing* behavior (see `custodly-owner-portal.md`).

use async_trait::async_trait;
use custodly_core::ParentCredential;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum OAuthError {
    #[error("no confirmed OAuth flow for provider {0:?} yet -- see custodly-owner-portal.md")]
    Unsupported(String),
    #[error("http request to provider failed: {0}")]
    Http(String),
    #[error("provider rejected the exchange: {0}")]
    Rejected(String),
}

#[async_trait]
pub trait OAuthProvider: Send + Sync {
    fn provider(&self) -> &str;

    /// Build the URL to send the owner to. `state` is the pending
    /// request's own id (`crate::code::generate_id`, already unguessable)
    /// -- reused as the OAuth `state` param rather than inventing a
    /// second random value, and checked again at the callback.
    fn authorize_url(&self, state: &str, redirect_uri: &str) -> String;

    /// Exchange a callback `code` for a parent credential. Never called
    /// with anything other than a code the provider itself just issued
    /// to that redirect.
    async fn exchange(&self, code: &str, redirect_uri: &str) -> Result<ParentCredential, OAuthError>;
}

/// Slack OAuth v2 (`oauth.v2.access`). Confirmed 28 Sep 2026: bot tokens
/// (`xoxb-...`) don't expire by default, and there is no API to mint a
/// *narrower* token from an already-granted scope ceiling -- scope is
/// fixed at the moment this exchange runs and stays fixed until the
/// workspace owner re-authorizes with different scopes through this same
/// flow. That's exactly what this type is for: the one-time (or
/// re-consent-time) owner click, not a repeatable per-request mint.
pub struct SlackOAuth {
    client_id: String,
    client_secret: String,
    bot_scopes: Vec<String>,
    client: reqwest::Client,
}

impl SlackOAuth {
    #[must_use]
    pub fn new(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        bot_scopes: Vec<String>,
        client: reqwest::Client,
    ) -> Self {
        Self { client_id: client_id.into(), client_secret: client_secret.into(), bot_scopes, client }
    }
}

#[async_trait]
impl OAuthProvider for SlackOAuth {
    fn provider(&self) -> &str {
        "slack"
    }

    fn authorize_url(&self, state: &str, redirect_uri: &str) -> String {
        format!(
            "https://slack.com/oauth/v2/authorize?client_id={}&scope={}&redirect_uri={}&state={}",
            urlencoding::encode(&self.client_id),
            urlencoding::encode(&self.bot_scopes.join(",")),
            urlencoding::encode(redirect_uri),
            urlencoding::encode(state),
        )
    }

    async fn exchange(&self, code: &str, redirect_uri: &str) -> Result<ParentCredential, OAuthError> {
        #[derive(serde::Deserialize)]
        struct SlackResponse {
            ok: bool,
            access_token: Option<String>,
            error: Option<String>,
        }

        let response = self
            .client
            .post("https://slack.com/api/oauth.v2.access")
            .form(&[
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
                ("code", code),
                ("redirect_uri", redirect_uri),
            ])
            .send()
            .await
            .map_err(|e| OAuthError::Http(e.to_string()))?;

        let body: SlackResponse =
            response.json().await.map_err(|e| OAuthError::Http(format!("parsing Slack's response: {e}")))?;

        if !body.ok {
            return Err(OAuthError::Rejected(body.error.unwrap_or_else(|| "unknown error".to_string())));
        }
        let token = body
            .access_token
            .ok_or_else(|| OAuthError::Rejected("ok:true response had no access_token".to_string()))?;
        Ok(ParentCredential { secret: token })
    }
}

/// Looks up an [`OAuthProvider`] by name. Deliberately not backed by a
/// trait-object `HashMap` with dynamic registration from outside this
/// crate -- every provider this portal can authorize is named here, in
/// code, so "which providers can an owner authorize through this portal"
/// is answerable by reading this one function, not by inspecting runtime
/// config.
#[must_use]
pub fn lookup<'a>(provider: &str, slack: Option<&'a SlackOAuth>) -> Option<&'a dyn OAuthProvider> {
    match provider {
        "slack" => slack.map(|s| s as &dyn OAuthProvider),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slack() -> SlackOAuth {
        SlackOAuth::new(
            "client123",
            "secret-not-real",
            vec!["chat:write".to_string(), "channels:read".to_string()],
            reqwest::Client::new(),
        )
    }

    #[test]
    fn authorize_url_percent_encodes_the_redirect_uri_and_carries_the_state() {
        let url = slack().authorize_url("req-abc", "https://portal.example/oauth/callback/slack");
        assert!(url.starts_with("https://slack.com/oauth/v2/authorize?"));
        assert!(url.contains("client_id=client123"));
        assert!(url.contains("scope=chat%3Awrite%2Cchannels%3Aread"));
        assert!(url.contains("redirect_uri=https%3A%2F%2Fportal.example%2Foauth%2Fcallback%2Fslack"));
        assert!(url.contains("state=req-abc"));
    }

    #[test]
    fn lookup_finds_slack_when_configured_and_nothing_else() {
        let s = slack();
        assert!(lookup("slack", Some(&s)).is_some());
        assert!(lookup("slack", None).is_none());
        assert!(lookup("zoho", Some(&s)).is_none());
    }
}
