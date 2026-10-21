//! The risk-tiering model: turns one requested provider grant into Tier 0,
//! 1, or 2 from its reversibility, blast radius, and financial exposure -
//! never a per-provider allowlist or a hand-maintained "dangerous scopes"
//! list, both of which go stale the moment a provider adds a permission
//! type nobody's listed yet. See `docs/design-brief.md`, "Risk tiering",
//! for the full reasoning; this module is that model, not a
//! reinterpretation of it.

use serde::{Deserialize, Serialize};

/// Can the action be undone without the affected party's help (revoke,
/// refund, restore), or not (funds sent, permanent delete, no backup)?
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reversibility {
    Reversible,
    Irreversible,
}

/// Does the grant reach only resources this integration owns or created,
/// or does it reach shared, production, or other-tenant resources?
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlastRadius {
    Own,
    Shared,
}

/// Can the action move money or create spend liability?
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinancialExposure {
    None,
    CanMoveMoney,
}

/// Did the provider's own API actually confirm what got granted, or is
/// this just what was asked for? Added for the multi-provider
/// restructure (25 Sep 2026): not every adapter has a verify-after-mint
/// call the way GitHub's `verify_no_scope_creep` does (e.g. a provider
/// with no read-back endpoint for a just-created key). A request this
/// module has never confirmed the real scope of is exactly the
/// "unrecognized scope" case the design brief already says to fail
/// closed on -- so it scores the same way: as if it had the widest
/// possible scope, not as whatever was merely requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Enforcement {
    /// The provider's own API confirmed the actual granted scope is what
    /// was requested (or narrower) -- GitHub's `verify_no_scope_creep`
    /// against the mint response is the reference case.
    Verified,
    /// Minted (or about to be), but nothing confirmed the real scope --
    /// no verify-after-mint call exists for this provider, or the
    /// adapter hasn't implemented one. Forces Tier 2 regardless of the
    /// other three axes; see [`Tier::score`].
    Unverified,
}

/// The scoring inputs for one requested provider+scope grant.
///
/// `read_only` is not one of the three axes `design-brief.md` names
/// (reversibility, blast radius, financial exposure) - those three are
/// exactly what separates Tier 2 from everything else, but the brief does
/// not fully operationalize what separates Tier 0 from Tier 1 beyond
/// calling Tier 0 "narrow scope" and Tier 1 "bounded write access". This
/// field is that missing signal, added here rather than left undecided:
/// read-only + reversible + own + no money is Tier 0; the same three but
/// with write access is Tier 1. **This is an interpretation, not something
/// the brief states outright - confirm it matches intent before relying on
/// the Tier 0/1 boundary in a gating decision.**
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeAssessment {
    pub reversibility: Reversibility,
    pub blast_radius: BlastRadius,
    pub financial_exposure: FinancialExposure,
    pub read_only: bool,
    /// Defaults to `Verified` on deserialize so every `ScopeAssessment`
    /// written before this field existed (there is no persisted form of
    /// this type today, but tests and future callers may still construct
    /// one without it) reads as the old, already-checked behavior rather
    /// than silently downgrading to Tier 2.
    #[serde(default = "default_enforcement")]
    pub enforcement: Enforcement,
}

fn default_enforcement() -> Enforcement {
    Enforcement::Verified
}

/// The gating decision for one requested grant.
///
/// Ordered so `Tier2 > Tier1 > Tier0` compares the way "more sensitive"
/// reads. Tier 2 is sticky: nothing about a provider's prior, trusted use
/// ever buys a *later* request back down from Tier 2 - scoring is per
/// request, never per provider, so there is no "prior trust" input here at
/// all for callers to accidentally thread through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    /// Reversible, narrow (read-only), own resources, no money. Never
    /// gated.
    Tier0,
    /// Reversible, own resources, no money, but writes. Automatic once the
    /// provider's initial trust is established.
    Tier1,
    /// Irreversible, OR reaches shared/production/other-tenant resources,
    /// OR has financial exposure - any single one trips it, and two or
    /// more compounding never make it worse than Tier 2. Always requires
    /// explicit human approval, every time.
    Tier2,
}

impl Tier {
    /// Score one requested grant. `assessment` is `None` for a scope the
    /// provider adapter has not classified, which fails closed to
    /// [`Tier::Tier2`] rather than being silently trusted - ambiguity
    /// should be rare (a new provider, a new scope type), not a routine
    /// tax on normal use, so failing closed here is what keeps it rare
    /// rather than routine.
    #[must_use]
    pub fn score(assessment: Option<&ScopeAssessment>) -> Self {
        let Some(assessment) = assessment else {
            return Tier::Tier2;
        };
        let trips_tier2 = assessment.enforcement == Enforcement::Unverified
            || assessment.reversibility == Reversibility::Irreversible
            || assessment.blast_radius == BlastRadius::Shared
            || assessment.financial_exposure == FinancialExposure::CanMoveMoney;
        if trips_tier2 {
            Tier::Tier2
        } else if assessment.read_only {
            Tier::Tier0
        } else {
            Tier::Tier1
        }
    }

    /// The wire value used throughout `boundary/v1` (`DepositMetadata.tier`,
    /// `PolicyResponse.tier`): a plain `0`/`1`/`2`, not this enum, so a
    /// Ferryman build that has never heard of `custodly-core` can still
    /// read it.
    #[must_use]
    pub fn as_u8(self) -> u8 {
        match self {
            Tier::Tier0 => 0,
            Tier::Tier1 => 1,
            Tier::Tier2 => 2,
        }
    }
}

/// Score a `boundary/v1` scope string (`docs/BOUNDARY.md`'s
/// `"repo:read,pr:write"` shape: comma-separated `resource:level` pairs)
/// into the axes [`Tier::score`] needs, for the GitHub App pilot
/// (`docs/mvp-scope.md`).
///
/// **Interpretation, not verified against GitHub's current App permission
/// docs** - same caveat as [`ScopeAssessment::read_only`] above. GitHub
/// permissions are actually a fixed enum of resources at `none`/`read`/
/// `write`/`admin`, not free-form strings; this is a stand-in shape until
/// that's checked against the live docs and a real provider adapter reads
/// installation permissions directly. What it gets right regardless of
/// that: fail closed. An empty scope, an unparseable pair, or an unlisted
/// resource returns `None`, which [`Tier::score`] treats as Tier 2 - an
/// unrecognized GitHub permission should stop for a human, not be
/// silently trusted because this list didn't happen to name it.
///
/// `resource == "admin"` (repository/organization administration) always
/// trips Tier 2 on its own, regardless of level: it's account-level
/// control, not a scoped write.
#[must_use]
pub fn assess_github_scope(scope: &str) -> Option<ScopeAssessment> {
    if scope.trim().is_empty() {
        return None;
    }
    let mut read_only = true;
    let mut trips_tier2 = false;
    for pair in scope.split(',') {
        let (resource, level) = pair.trim().split_once(':')?;
        let resource = resource.trim();
        let level = level.trim();
        if resource.is_empty() || level.is_empty() {
            return None;
        }
        match level {
            "read" => {}
            "write" => read_only = false,
            _ => return None,
        }
        match resource {
            // Reaches this installation's own repositories only - Tier 0/1
            // territory, decided by `read_only` alone.
            "repo" | "pr" | "issues" | "contents" | "metadata" | "actions" | "checks" => {}
            // Account-level or money-adjacent: always Tier 2, whatever the level.
            "admin" | "billing" | "secrets" => trips_tier2 = true,
            // Unrecognized resource - fail closed rather than guess.
            _ => return None,
        }
    }
    Some(ScopeAssessment {
        reversibility: if trips_tier2 {
            Reversibility::Irreversible
        } else {
            Reversibility::Reversible
        },
        blast_radius: if trips_tier2 {
            BlastRadius::Shared
        } else {
            BlastRadius::Own
        },
        financial_exposure: if scope.contains("billing") {
            FinancialExposure::CanMoveMoney
        } else {
            FinancialExposure::None
        },
        read_only,
        // This function's caller is the GitHub App pilot's mint path,
        // which always runs `verify_no_scope_creep` against the real
        // mint response before a token is ever stored -- so a scope that
        // got this far has already been checked, not merely requested.
        enforcement: Enforcement::Verified,
    })
}

/// Score a Codeberg/Forgejo repo-scoped access token's granted scopes
/// (`"write:repository"`, `"read:issue"`, ... -- Forgejo's own
/// `level:resource` vocabulary, the *reverse* order of GitHub's
/// `resource:level`) into the axes [`Tier::score`] needs.
///
/// Confirmed 25 Sep 2026 (`forgejo/forgejo#11504`): a repo-scoped token
/// can only carry `read:issue`, `write:issue`, `read:repository`, or
/// `write:repository` -- so every scope this function accepts already
/// stays within one repo's own issues/contents, never account-level
/// administration or billing. `blast_radius` and `financial_exposure`
/// are therefore fixed at `Own`/`None` for anything accepted at all; an
/// unrecognized scope still fails closed to `None`, same instinct as
/// [`assess_github_scope`].
#[must_use]
pub fn assess_codeberg_scope(scope: &str) -> Option<ScopeAssessment> {
    if scope.trim().is_empty() {
        return None;
    }
    let mut read_only = true;
    for pair in scope.split(',') {
        let (level, resource) = pair.trim().split_once(':')?;
        let level = level.trim();
        let resource = resource.trim();
        if resource.is_empty() || level.is_empty() {
            return None;
        }
        match level {
            "read" => {}
            "write" => read_only = false,
            _ => return None,
        }
        match resource {
            "issue" | "repository" => {}
            _ => return None,
        }
    }
    Some(ScopeAssessment {
        reversibility: Reversibility::Reversible,
        blast_radius: BlastRadius::Own,
        financial_exposure: FinancialExposure::None,
        read_only,
        // Same reasoning as `assess_github_scope`: this function's only
        // caller is `custodly-github`'s Codeberg adapter's `verify`,
        // which checks the granted repo against the request before ever
        // calling this -- so a scope that got this far has already been
        // checked, not merely requested.
        enforcement: Enforcement::Verified,
    })
}

/// Score an OpenRouter provisioning key's granted spend limit against
/// what was requested, into the axes [`Tier::score`] needs.
///
/// Confirmed 25 Sep 2026 (`openrouter.ai/docs/features/provisioning-api-keys`):
/// the provisioning API has no resource or model scoping at all -- a
/// minted key reaches every model on the account. The only thing that
/// narrows it is `limit`, so unlike [`assess_github_scope`]/
/// [`assess_codeberg_scope`] this takes numbers, not a `resource:level`
/// string, and it always scores `financial_exposure: CanMoveMoney` -- a
/// spend-capable key still moves money up to its cap, which per this
/// module's own definition of the axis ("can the action move money or
/// create spend liability?") is enough to trip Tier 2 regardless of how
/// tight the cap is. `granted_limit_usd` must be `Some`, positive, and no
/// larger than `requested_limit_usd` -- an uncapped key (`None`) or one
/// granted a looser cap than asked for fails closed to `None`, same
/// instinct as an unrecognized GitHub scope.
#[must_use]
pub fn assess_openrouter_scope(requested_limit_usd: f64, granted_limit_usd: Option<f64>) -> Option<ScopeAssessment> {
    let granted = granted_limit_usd?;
    if granted <= 0.0 || granted > requested_limit_usd {
        return None;
    }
    Some(ScopeAssessment {
        reversibility: Reversibility::Reversible,
        blast_radius: BlastRadius::Own,
        financial_exposure: FinancialExposure::CanMoveMoney,
        read_only: false,
        enforcement: Enforcement::Verified,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reversible_own_no_money(read_only: bool) -> ScopeAssessment {
        ScopeAssessment {
            reversibility: Reversibility::Reversible,
            blast_radius: BlastRadius::Own,
            financial_exposure: FinancialExposure::None,
            read_only,
            enforcement: Enforcement::Verified,
        }
    }

    #[test]
    fn unknown_scope_fails_closed_to_tier_2() {
        assert_eq!(Tier::score(None), Tier::Tier2);
    }

    #[test]
    fn any_single_trip_wire_is_tier_2_regardless_of_read_only() {
        let mut a = reversible_own_no_money(true);
        a.reversibility = Reversibility::Irreversible;
        assert_eq!(Tier::score(Some(&a)), Tier::Tier2);

        let mut b = reversible_own_no_money(true);
        b.blast_radius = BlastRadius::Shared;
        assert_eq!(Tier::score(Some(&b)), Tier::Tier2);

        let mut c = reversible_own_no_money(true);
        c.financial_exposure = FinancialExposure::CanMoveMoney;
        assert_eq!(Tier::score(Some(&c)), Tier::Tier2);
    }

    #[test]
    fn compounding_trip_wires_are_still_tier_2_never_worse() {
        let assessment = ScopeAssessment {
            reversibility: Reversibility::Irreversible,
            blast_radius: BlastRadius::Shared,
            financial_exposure: FinancialExposure::CanMoveMoney,
            read_only: true,
            enforcement: Enforcement::Verified,
        };
        assert_eq!(Tier::score(Some(&assessment)), Tier::Tier2);
    }

    #[test]
    fn unverified_scope_is_tier_2_even_when_everything_else_is_narrow() {
        // The multi-provider case this field exists for: an adapter
        // minted something reversible/own/no-money/read-only by its own
        // claim, but has no way to confirm that against the provider.
        let mut a = reversible_own_no_money(true);
        a.enforcement = Enforcement::Unverified;
        assert_eq!(Tier::score(Some(&a)), Tier::Tier2);
    }

    #[test]
    fn bounded_and_read_only_is_tier_0() {
        assert_eq!(Tier::score(Some(&reversible_own_no_money(true))), Tier::Tier0);
    }

    #[test]
    fn bounded_and_write_is_tier_1() {
        assert_eq!(Tier::score(Some(&reversible_own_no_money(false))), Tier::Tier1);
    }

    #[test]
    fn tier_ordering_reads_as_more_sensitive() {
        assert!(Tier::Tier0 < Tier::Tier1);
        assert!(Tier::Tier1 < Tier::Tier2);
    }

    #[test]
    fn as_u8_matches_the_wire_convention_in_boundary_v1() {
        assert_eq!(Tier::Tier0.as_u8(), 0);
        assert_eq!(Tier::Tier1.as_u8(), 1);
        assert_eq!(Tier::Tier2.as_u8(), 2);
    }

    #[test]
    fn github_read_only_scope_is_tier_0() {
        let assessment = assess_github_scope("repo:read,issues:read").unwrap();
        assert_eq!(Tier::score(Some(&assessment)), Tier::Tier0);
    }

    #[test]
    fn github_scope_with_a_write_is_tier_1() {
        let assessment = assess_github_scope("repo:read,pr:write").unwrap();
        assert_eq!(Tier::score(Some(&assessment)), Tier::Tier1);
    }

    #[test]
    fn github_admin_scope_is_always_tier_2() {
        let assessment = assess_github_scope("admin:read").unwrap();
        assert_eq!(Tier::score(Some(&assessment)), Tier::Tier2);
    }

    #[test]
    fn github_billing_scope_is_tier_2_with_financial_exposure() {
        let assessment = assess_github_scope("billing:read").unwrap();
        assert_eq!(assessment.financial_exposure, FinancialExposure::CanMoveMoney);
        assert_eq!(Tier::score(Some(&assessment)), Tier::Tier2);
    }

    #[test]
    fn github_unrecognized_resource_fails_closed() {
        assert!(assess_github_scope("nuclear_launch:write").is_none());
    }

    #[test]
    fn github_empty_or_malformed_scope_fails_closed() {
        assert!(assess_github_scope("").is_none());
        assert!(assess_github_scope("repo").is_none());
        assert!(assess_github_scope("repo:delete").is_none());
    }

    #[test]
    fn codeberg_read_only_scope_is_tier_0() {
        let assessment = assess_codeberg_scope("read:repository,read:issue").unwrap();
        assert_eq!(Tier::score(Some(&assessment)), Tier::Tier0);
    }

    #[test]
    fn codeberg_scope_with_a_write_is_tier_1_never_tier_2() {
        // Unlike GitHub, a repo-scoped Codeberg token can never reach
        // admin/billing at all (forgejo/forgejo#11504's own validation
        // rule) -- a write here is always Tier 1, never Tier 2.
        let assessment = assess_codeberg_scope("write:repository").unwrap();
        assert_eq!(Tier::score(Some(&assessment)), Tier::Tier1);
    }

    #[test]
    fn codeberg_scope_uses_level_colon_resource_the_reverse_of_github() {
        // GitHub's order (resource:level) would parse as level="repository"
        // here, which isn't "read"/"write" -- fails closed rather than
        // silently accepting the wrong field order.
        assert!(assess_codeberg_scope("repository:read").is_none());
    }

    #[test]
    fn codeberg_unrecognized_resource_fails_closed() {
        assert!(assess_codeberg_scope("write:organization").is_none());
    }

    #[test]
    fn codeberg_empty_or_malformed_scope_fails_closed() {
        assert!(assess_codeberg_scope("").is_none());
        assert!(assess_codeberg_scope("repository").is_none());
        assert!(assess_codeberg_scope("delete:repository").is_none());
    }

    #[test]
    fn openrouter_a_capped_key_is_still_tier_2_on_financial_exposure_alone() {
        // The point of this axis: even a tight, confirmed, revocable cap
        // still moves money, so it's never Tier 0/1.
        let assessment = assess_openrouter_scope(5.0, Some(5.0)).unwrap();
        assert_eq!(assessment.financial_exposure, FinancialExposure::CanMoveMoney);
        assert_eq!(Tier::score(Some(&assessment)), Tier::Tier2);
    }

    #[test]
    fn openrouter_an_uncapped_key_fails_closed() {
        assert!(assess_openrouter_scope(5.0, None).is_none());
    }

    #[test]
    fn openrouter_a_looser_cap_than_requested_fails_closed() {
        assert!(assess_openrouter_scope(5.0, Some(50.0)).is_none());
    }

    #[test]
    fn openrouter_a_zero_or_negative_cap_fails_closed() {
        assert!(assess_openrouter_scope(5.0, Some(0.0)).is_none());
        assert!(assess_openrouter_scope(5.0, Some(-1.0)).is_none());
    }
}
