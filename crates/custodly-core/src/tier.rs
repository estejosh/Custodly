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
        let trips_tier2 = assessment.reversibility == Reversibility::Irreversible
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
        };
        assert_eq!(Tier::score(Some(&assessment)), Tier::Tier2);
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
}
