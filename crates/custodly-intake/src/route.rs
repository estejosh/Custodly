//! Works out, on the desktop, where a phone-deposited key belongs.
//!
//! The phone only says what the key is "for" in plain words ("deepseek for redaktly").
//! Nothing here trusts that text with a path or a command: it is matched against the
//! projects the owner configured, and anything that does not match stays in the vault.

use crate::intake::ProjectConfig;

/// Group the vault uses for keys whose project could not be worked out.
pub const UNROUTED: &str = "unrouted";

#[derive(Debug)]
pub enum Route<'a> {
    Project(&'a ProjectConfig),
    /// More than one project fits; the owner has to choose.
    Ambiguous(Vec<String>),
    Unknown,
}

pub(crate) fn words(s: &str) -> String {
    let mapped: String = s.chars().map(|c| if c.is_alphanumeric() { c.to_ascii_lowercase() } else { ' ' }).collect();
    mapped.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// A project matches when its id, label or an alias appears in the text as whole words.
/// If several match, the most specific (longest) wins; a tie between different projects
/// is ambiguous.
#[must_use]
pub fn resolve<'a>(for_text: &str, projects: &'a [ProjectConfig]) -> Route<'a> {
    let text = format!(" {} ", words(for_text));
    let mut best: Vec<(&ProjectConfig, usize)> = Vec::new();
    for p in projects {
        let longest = std::iter::once(p.id.as_str())
            .chain(std::iter::once(p.label.as_str()))
            .chain(p.aliases.iter().map(String::as_str))
            .map(words)
            .filter(|w| !w.is_empty() && text.contains(&format!(" {w} ")))
            .map(|w| w.len())
            .max();
        if let Some(n) = longest {
            best.push((p, n));
        }
    }
    let Some(top) = best.iter().map(|(_, n)| *n).max() else { return Route::Unknown };
    let top: Vec<_> = best.into_iter().filter(|(_, n)| *n == top).map(|(p, _)| p).collect();
    match top.as_slice() {
        [one] => Route::Project(one),
        many => Route::Ambiguous(many.iter().map(|p| p.id.clone()).collect()),
    }
}

/// Well-known key shapes, so `sk-or-v1-...` is named OPENROUTER_API_KEY without being told.
const PREFIXES: &[(&str, &str)] = &[
    ("sk-or-", "OPENROUTER_API_KEY"),
    ("sk-ant-", "ANTHROPIC_API_KEY"),
    ("sk-proj-", "OPENAI_API_KEY"),
    ("github_pat_", "GITHUB_TOKEN"),
    ("ghp_", "GITHUB_TOKEN"),
    ("gho_", "GITHUB_TOKEN"),
    ("xoxb-", "SLACK_BOT_TOKEN"),
    ("xoxp-", "SLACK_USER_TOKEN"),
    ("sk_live_", "STRIPE_SECRET_KEY"),
    ("sk_test_", "STRIPE_SECRET_KEY"),
    ("AKIA", "AWS_ACCESS_KEY_ID"),
    ("AIza", "GOOGLE_API_KEY"),
    ("hf_", "HUGGINGFACE_TOKEN"),
    ("gsk_", "GROQ_API_KEY"),
    ("npm_", "NPM_TOKEN"),
];

/// Words that say "this is a key" rather than which one.
const FILLER: &[&str] = &["key", "api", "token", "secret", "for", "the", "a", "my", "new", "to", "use", "in", "on"];

/// An uppercase secret name Ferryman accepts, from the key's shape or what it is for.
/// `resolved` is the project's id when one matched, so "deepseek for redaktly" becomes
/// DEEPSEEK_API_KEY rather than DEEPSEEK_REDAKTLY_API_KEY.
#[must_use]
pub fn derive_name(for_text: &str, value: &str, resolved: Option<&ProjectConfig>) -> String {
    if let Some((_, name)) = PREFIXES.iter().find(|(p, _)| value.starts_with(p)) {
        return (*name).to_string();
    }
    let project_words = resolved
        .map(|p| {
            std::iter::once(p.id.as_str())
                .chain(std::iter::once(p.label.as_str()))
                .chain(p.aliases.iter().map(String::as_str))
                .flat_map(|w| words(w).split(' ').map(str::to_string).collect::<Vec<_>>())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let parts: Vec<String> = words(for_text)
        .split(' ')
        .filter(|w| !w.is_empty() && !FILLER.contains(w) && !project_words.iter().any(|p| p == w))
        .take(3)
        .map(str::to_uppercase)
        .collect();
    let mut name = if parts.is_empty() { "API_KEY".to_string() } else { format!("{}_API_KEY", parts.join("_")) };
    if !name.starts_with(|c: char| c.is_ascii_uppercase()) {
        name.insert(0, 'K');
    }
    name.truncate(64);
    name
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(id: &str, label: &str, aliases: &[&str]) -> ProjectConfig {
        ProjectConfig {
            id: id.into(),
            label: label.into(),
            aliases: aliases.iter().map(|s| (*s).to_string()).collect(),
            ferry_secret: None,
            ferryman: None,
        }
    }

    fn set() -> Vec<ProjectConfig> {
        vec![
            p("custodly", "Custodly", &[]),
            p("redaktly", "Redaktly", &["legalredact"]),
            p("speakeasy-automations", "Speakeasy Automations", &["speakeasy", "sem"]),
            p("speakeasy-podcasts", "Speakeasy Podcasts", &["speakeasy podcasts"]),
        ]
    }

    #[test]
    fn matches_on_id_label_or_alias_as_whole_words() {
        let ps = set();
        assert!(matches!(resolve("deepseek for Redaktly", &ps), Route::Project(x) if x.id == "redaktly"));
        assert!(matches!(resolve("legalredact stuff", &ps), Route::Project(x) if x.id == "redaktly"));
        assert!(matches!(resolve("sem zoho", &ps), Route::Project(x) if x.id == "speakeasy-automations"));
        assert!(matches!(resolve("semantic search", &ps), Route::Unknown)); // "sem" is not a word there
    }

    #[test]
    fn the_longer_match_wins_and_real_ties_are_ambiguous() {
        let ps = set();
        assert!(matches!(resolve("speakeasy podcasts whisper", &ps), Route::Project(x) if x.id == "speakeasy-podcasts"));
        assert!(matches!(resolve("redaktly and custodly", &ps), Route::Ambiguous(v) if v.len() == 2));
        assert!(matches!(resolve("something else", &ps), Route::Unknown));
    }

    #[test]
    fn names_come_from_the_key_shape_first_then_the_words() {
        let ps = set();
        assert_eq!(derive_name("anything", "sk-or-v1-abc", None), "OPENROUTER_API_KEY");
        assert_eq!(derive_name("anything", "ghp_abc", None), "GITHUB_TOKEN");
        let red = ps.iter().find(|x| x.id == "redaktly");
        assert_eq!(derive_name("deepseek for redaktly", "sk-123", red), "DEEPSEEK_API_KEY");
        assert_eq!(derive_name("the zoho api key", "x", None), "ZOHO_API_KEY");
        assert_eq!(derive_name("key", "x", None), "API_KEY");
        assert_eq!(derive_name("3commas", "x", None), "K3COMMAS_API_KEY");
    }
}
