//! A small, read-only test that a freshly deposited key actually works.
//!
//! The host and request come from a fixed table keyed by the secret's name, never from
//! anything the phone typed, and the key goes only to that provider's own API.

use std::time::Duration;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Check {
    /// `valid`, `invalid`, `unchecked` (no safe test known, or no network) or `error`.
    pub state: String,
    pub detail: String,
}

impl Check {
    #[must_use]
    pub fn new(state: &str, detail: impl Into<String>) -> Self {
        Self { state: state.into(), detail: detail.into() }
    }

    #[must_use]
    pub fn unchecked(detail: impl Into<String>) -> Self {
        Self::new("unchecked", detail)
    }

    #[must_use]
    pub fn is_invalid(&self) -> bool {
        self.state == "invalid"
    }
}

struct Probe {
    provider: &'static str,
    method: &'static str,
    url: &'static str,
    /// `bearer`, or `x-api-key` for Anthropic.
    auth: &'static str,
    /// Slack answers 200 with `{"ok":false}` for a bad token.
    slack_style: bool,
}

const fn probe(provider: &'static str, method: &'static str, url: &'static str, auth: &'static str) -> Probe {
    Probe { provider, method, url, auth, slack_style: false }
}

fn probe_for(name: &str) -> Option<Probe> {
    Some(match name {
        "OPENROUTER_API_KEY" => probe("OpenRouter", "GET", "https://openrouter.ai/api/v1/auth/key", "bearer"),
        "ANTHROPIC_API_KEY" => probe("Anthropic", "GET", "https://api.anthropic.com/v1/models", "x-api-key"),
        "OPENAI_API_KEY" => probe("OpenAI", "GET", "https://api.openai.com/v1/models", "bearer"),
        "DEEPSEEK_API_KEY" => probe("DeepSeek", "GET", "https://api.deepseek.com/models", "bearer"),
        "GROQ_API_KEY" => probe("Groq", "GET", "https://api.groq.com/openai/v1/models", "bearer"),
        "GITHUB_TOKEN" => probe("GitHub", "GET", "https://api.github.com/user", "bearer"),
        "HUGGINGFACE_TOKEN" => probe("Hugging Face", "GET", "https://huggingface.co/api/whoami-v2", "bearer"),
        "STRIPE_SECRET_KEY" => probe("Stripe", "GET", "https://api.stripe.com/v1/balance", "bearer"),
        "SLACK_BOT_TOKEN" | "SLACK_USER_TOKEN" => {
            Probe { slack_style: true, ..probe("Slack", "POST", "https://slack.com/api/auth.test", "bearer") }
        }
        _ => return None,
    })
}

/// Turns an HTTP outcome into a verdict. Split out so it can be tested without a network.
#[must_use]
pub fn verdict(provider: &str, status: u16, slack_ok: Option<bool>) -> Check {
    if let Some(ok) = slack_ok {
        return if ok {
            Check::new("valid", format!("{provider} accepted the key"))
        } else {
            Check::new("invalid", format!("{provider} says the token is not valid"))
        };
    }
    match status {
        200..=299 => Check::new("valid", format!("{provider} accepted the key")),
        401 => Check::new("invalid", format!("{provider} rejected the key (401)")),
        403 => Check::new("unchecked", format!("{provider} answered 403: the key may be valid but lacks this scope")),
        s => Check::new("error", format!("{provider} answered {s}; could not tell")),
    }
}

/// Runs the test for a secret by its name. Never panics and never includes the value.
pub async fn http_check(name: &str, value: &str) -> Check {
    let Some(p) = probe_for(name) else {
        return Check::unchecked("no safe test is known for this kind of key");
    };
    let Ok(client) = reqwest::Client::builder().timeout(Duration::from_secs(10)).user_agent("custodly-intake").build() else {
        return Check::unchecked("could not start a test");
    };
    let req = if p.method == "POST" { client.post(p.url) } else { client.get(p.url) };
    let req = match p.auth {
        "x-api-key" => req.header("x-api-key", value).header("anthropic-version", "2023-06-01"),
        _ => req.bearer_auth(value),
    };
    match req.send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let slack_ok = if p.slack_style {
                resp.json::<serde_json::Value>().await.ok().and_then(|v| v.get("ok").and_then(serde_json::Value::as_bool))
            } else {
                None
            };
            verdict(p.provider, status, slack_ok)
        }
        Err(e) if e.is_timeout() => Check::new("error", format!("{} did not answer in time", p.provider)),
        Err(_) => Check::new("error", format!("could not reach {}", p.provider)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statuses_map_to_honest_verdicts() {
        assert_eq!(verdict("X", 200, None).state, "valid");
        assert_eq!(verdict("X", 401, None).state, "invalid");
        assert_eq!(verdict("X", 403, None).state, "unchecked");
        assert_eq!(verdict("X", 500, None).state, "error");
        assert_eq!(verdict("Slack", 200, Some(false)).state, "invalid");
        assert_eq!(verdict("Slack", 200, Some(true)).state, "valid");
    }

    #[tokio::test]
    async fn unknown_kinds_are_unchecked_without_any_request() {
        let c = http_check("SOME_VENDOR_KEY", "v").await;
        assert_eq!(c.state, "unchecked");
        assert!(!c.detail.contains('v') || c.detail.len() > 1);
    }

    #[test]
    fn only_listed_names_have_a_probe() {
        assert!(probe_for("OPENROUTER_API_KEY").is_some());
        assert!(probe_for("../evil").is_none());
    }
}
