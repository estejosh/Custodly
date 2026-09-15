# Custodly — Design Brief

Working name: Custodly (formerly "Secget"). Project folder: `X:\Custodly` on beastly.

## Problem

Getting a new API key/secret today is manual: log into a provider, generate it,
copy it somewhere. Slow, over-permissioned by default, and secrets end up
pasted through chat, files, or agent context on the way to wherever they're
used.

## What it does

An n8n automation + local client that, on request, acquires a new
secret/API key from a provider and drops it directly into a secrets keeper
(KeePassXC, hosted on a Ferryman box) — never through a chat log or an
agent's context. An agent supervises the system (does it still work, is it
minting the right scope, is expiry tracked) but the acquisition itself runs
through deterministic automation, not an agent driving the action live.

## Acquisition: two tracks behind one contract

Every request is: *get me a key for provider X, scoped to [permissions],
expiring in [duration]* → a key lands in the vault.

- **Track 1 — API-native providers** (Stripe, AWS, GitHub, OpenAI-style).
  Pure n8n: authenticate as the automation, call the provider's key-creation
  endpoint, verify returned scope matches the request, write to vault.
- **Track 2 — dashboard-only providers** (no key-management API). An agent
  authors and maintains a scripted flow (e.g. Playwright) per provider — a
  recipe. Deterministic automation *runs* the recipe on trigger/schedule; the
  agent only touches it to build a new recipe or fix one a provider's
  redesign broke. Keeps the "agent supervises, doesn't execute the sensitive
  action live" principle intact even on the harder path.

## Vault structure: segregated by sensitivity

- **Working store** — day-to-day scoped keys (output of both tracks).
  Agents read/write freely; this is the whole point of the system.
- **Master store** — root/dashboard logins and anything that can mint
  arbitrary new access. Sealed by default. No standing agent access.

## Trust-once, transact-many

Friction belongs at *establishing* trust with a provider, not at *using* it —
same pattern as an SSH agent unlocking once, or OAuth consent once then
silent token refresh forever.

- First time Custodly touches a new provider: one deliberate human/gated
  moment (login-allow event) establishes access — a session, a
  rotation-capable API key, whatever the provider supports.
- After that: rotations, renewals, and routine monitoring run with zero
  prompts. This is the default UX — the system must not "fight" the user on
  routine operation.
- What the unlock produces should prefer a short-lived derived session over
  handing out the raw master credential itself, where the provider supports
  it — caps the blast radius of a leak without adding friction to normal use.
- The agent only comes back to a human when something breaks the automatic
  assumption: a session that won't silently refresh, a broken recipe, a key
  that came back over-scoped, expiry approaching with no auto-renew path.

## Risk tiering (the gating decision) — decided 15 Sep 2026

Gating is **not** a flat per-provider allowlist, and **not** a hand-maintained
list of "dangerous" scopes (both go stale the moment a provider adds a new
permission type). It's a small scoring model applied to *every* requested
grant, so the system can reason about scopes it's never seen before instead
of needing a human to keep extending an enum:

- **Reversibility** — can the action be undone without the affected party's
  help (revoke, refund, restore) or not (funds sent, permanent delete, no
  backup)?
- **Blast radius** — scoped to resources this integration owns/created, or
  does it reach shared/production/other-tenant resources?
- **Financial exposure** — can it move money or create spend liability?

**Tier 0** (reversible + narrow scope) → never gated.
**Tier 1** (bounded write access, no money, no shared-resource reach) → auto
after the provider's initial trust is established.
**Tier 2** (irreversible, OR broad/shared blast radius, OR financial
exposure — any one of these trips it, two or more compounding never buys a
pass) → always gated, regardless of how many times that provider's been
used before. Prior trust never buys down Tier 2.
**Unknown/unrecognized scope** → defaults to Tier 2 until classified. Fail
closed on the rare/new case, not on the routine one — this is what keeps
"smarter" from turning into "more annoying": ambiguity should be rare
(new provider, new scope type), not a routine tax on normal use.

This makes explicit what the "agent monitors and maintains the software"
part of the original brief actually means day to day: keeping the
per-provider scope-to-tier mapping current as providers add scopes or
redesign permission models — not just watching expiry dates.

## Naming

Custodly — Custodian ("the person accountable for receipt, custody, issue,
safeguarding, and destruction of sensitive material" — a real security/
compliance job title, e.g. Key Custodian) + "-ly," matching an existing
naming convention already used elsewhere in the portfolio.

## MVP scope

See `mvp-scope.md` for the concrete first-build decisions (Track 1 pilot
provider, vault mechanism, gate implementation for v1).
