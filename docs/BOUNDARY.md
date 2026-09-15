# Custodly / Ferryman boundary

Custodly acquires and scores secrets. Ferryman identifies people, grants
access, transports, and seals at rest. Neither reimplements the other.

## The line

`working.kdbx` is a **local cache for one operator on one machine**. Every
agent on this box reads it freely — that's fine as long as "everyone with
access to this box" and "everyone Custodly trusts" are the same set,
which is true for a single operator and stops being true the moment a
second person is granted access to anything on that box.

**Anything crossing a person or machine boundary goes through Ferryman**,
sealed for that recipient, with Ferryman's grants — not Custodly — deciding
who can open it. Custodly hands Ferryman a sealed secret plus a scope
label. Ferryman decides who sees it. Custodly never learns who the
recipient is. Ferryman never learns how to talk to Stripe.

## Contract — `boundary/v1`

Every payload on either call carries `contract_version: "boundary/v1"`. A
receiver that doesn't recognize the major version rejects the call rather
than guessing at its shape — the two repos move at different speeds on
purpose.

### `deposit(sealed_secret, metadata) -> receipt`

Called by Custodly, into Ferryman, once a secret is acquired and needs to
leave the local machine (any Tier 2 grant, or any grant meant for someone
other than the local operator).

- `sealed_secret` — ciphertext, sealed by Custodly to Ferryman's
  project-scoped ingestion key (not to any individual's identity key —
  Custodly doesn't hold or know individual keys). Ferryman opens it once
  under its own sealing (PBKDF2-SHA256 600k, XChaCha20-Poly1305) and
  re-seals per recipient only at grant time, using machinery it already
  has.
- `metadata` — `provider`, `scope` (provider-native scope string), `tier`
  (0/1/2, Custodly's own scoring result — informational to Ferryman, not
  re-derived by it), `acquired_via` (`track1_api` | `track2_recipe`),
  `expires_at`, `acquired_at`, `label` (short human string for Ferryman's
  dashboard, e.g. "GitHub App install token, pilot repo, read+PR").
  Never the plaintext secret or anything it could be reconstructed from.
- `receipt` — `deposit_id`, `accepted_at`, `contract_version`. No secret
  or key material comes back. This is Custodly's own proof that custody
  transferred, for the "record of what was acquired and why" it owns.

### `policy(provider, requested_scope) -> { tier, requires }`

Called by Ferryman, into Custodly, when Ferryman needs to know how
sensitive a given provider+scope is — building its grant/approval UI, for
instance — without reimplementing the scoring model, which is Custodly's.

- `tier` — 0, 1, or 2, per the reversibility / blast-radius / financial-
  exposure model in `design-brief.md`.
- `requires` — what Custodly needs before it will treat a request for
  this provider+scope as fulfillable, e.g. `["onboarding_complete"]`, or
  for tier 2, `["onboarding_complete", "gate:human_approval"]`.

## What each side never does

- Custodly never builds identity, grants, transport, or at-rest sealing —
  that's shipped. If a Custodly PR starts adding a permission model, a
  user model, or a sync mechanism, that's the wrong repo for it.
- Ferryman never gets a provider adapter, a recipe, or scope-classification
  logic — it only sees `deposit()` calls and answers `policy()` queries.

## When the boundary hurts

If something here is awkward to build against, the fix is a Ferryman
defect report, not a workaround inside Custodly. Custodly is the first
real consumer of Ferryman's secrets-layer roadmap; friction found here now
is friction a stranger won't hit later.
