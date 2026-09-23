//! `policy()`: Custodly's answer, over HTTP (`custodly-core::server`), to
//! "how sensitive is this provider+scope" - see `docs/BOUNDARY.md`. This
//! module is the pure logic (provider dispatch -> [`crate::tier::Tier`]);
//! the HTTP wrapper is `server.rs`, deliberately kept thin so this part is
//! testable without a listening socket.

use crate::contract::PolicyResponse;
use crate::tier::{Tier, assess_github_scope};

/// Score one provider+scope request into the `PolicyResponse` shape
/// Ferryman's grant UI needs.
///
/// Only `"github"` is dispatched to a real assessment (the pilot provider,
/// `docs/mvp-scope.md`); every other provider name scores `None`, which
/// [`Tier::score`] fails closed to Tier 2 for - a provider Custodly has no
/// adapter for yet should stop for a human, not be silently trusted.
#[must_use]
pub fn evaluate(provider: &str, scope: &str) -> PolicyResponse {
    let assessment = match provider {
        "github" => assess_github_scope(scope),
        _ => None,
    };
    let tier = Tier::score(assessment.as_ref());
    let mut requires = Vec::new();
    if assessment.is_none() {
        requires.push("onboarding_complete".to_string());
    }
    if tier == Tier::Tier2 {
        requires.push("gate:human_approval".to_string());
    }
    PolicyResponse {
        tier: tier.as_u8(),
        requires,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_github_read_only_scope_is_tier_0_with_no_requirements() {
        let response = evaluate("github", "repo:read");
        assert_eq!(response.tier, 0);
        assert!(response.requires.is_empty());
    }

    #[test]
    fn known_github_write_scope_is_tier_1() {
        let response = evaluate("github", "pr:write");
        assert_eq!(response.tier, 1);
        assert!(response.requires.is_empty());
    }

    #[test]
    fn github_admin_scope_requires_human_approval() {
        let response = evaluate("github", "admin:write");
        assert_eq!(response.tier, 2);
        assert_eq!(response.requires, vec!["gate:human_approval".to_string()]);
    }

    #[test]
    fn unknown_provider_fails_closed_with_onboarding_and_approval() {
        let response = evaluate("stripe", "charges:read");
        assert_eq!(response.tier, 2);
        assert_eq!(
            response.requires,
            vec!["onboarding_complete".to_string(), "gate:human_approval".to_string()]
        );
    }

    #[test]
    fn unparseable_github_scope_fails_closed_the_same_way() {
        let response = evaluate("github", "not-a-valid-scope");
        assert_eq!(response.tier, 2);
        assert_eq!(
            response.requires,
            vec!["onboarding_complete".to_string(), "gate:human_approval".to_string()]
        );
    }
}
