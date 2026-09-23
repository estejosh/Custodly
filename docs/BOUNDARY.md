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
  project-scoped **ingestion identity** (not to any individual's identity
  key — Custodly doesn't hold or know individual keys). This identity did
  not pre-exist; it is a project-scoped `secrets::EncryptionIdentity` added
  specifically to receive deposits (`ferryman_channel::boundary::ingestion_identity`),
  stored under the project's unsynced attachment directory, never in the
  synced channel folder and never in the human roster. Ferryman opens the
  deposit once, under that identity, using the same X25519-ECDH /
  HKDF-SHA256 / XChaCha20-Poly1305 construction `secrets::set_secret`
  already uses to seal to a named recipient (`boundary::open_deposit`,
  built on a new `secrets::open_slot` primitive factored out of that
  existing code — not a second construction), and re-seals per recipient
  only at grant time via the existing `secrets::set_secret`. Both sides'
  code now exists: `ferryman-channel/src/boundary.rs` (open) and
  `custodly-core/src/seal.rs` (seal) — mirrored by reading, not by a shared
  crate or a cross-repo test yet, so treat the pairing as unverified until
  an integration test seals on one side and opens on the other.
  *(Corrected 2026-09-21 — the original text here said "PBKDF2-SHA256
  600k", which nothing in Ferryman's code does; see `START-HERE.md`.)*
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

## What's implemented vs. still open (as of 2026-09-21)

Implemented, in each repo's own crate, with unit tests but no cross-repo
integration test yet:
- Ferryman: `ferryman-channel::boundary` — the ingestion identity, opening a
  deposit, and the receipt type. Not wired into any HTTP route (or any
  other transport) yet.
- Custodly: `custodly-core::seal` and `custodly-core::contract` — sealing a
  value to a given recipient public key, and the wire types
  (`DepositMetadata`, `SealedSecret`, `DepositReceipt`, `PolicyResponse`).

Still genuinely open, not just unimplemented:
- **How Custodly learns the ingestion identity's public key for a given
  project.** `deposit()` cannot be called end to end until this is
  answered — it is a discovery question, not a crypto one.
- **`policy()`'s transport.** Custodly runs no listener of any kind yet —
  no HTTP server, no CLI subcommand wired up, nothing n8n could call
  either. The payload shape (`PolicyResponse`) is fixed; how Ferryman
  reaches it is not decided.
- **`deposit()`'s transport on the Ferryman side.** `ferryman-server`
  exposes `/v1/...` routes over axum for everything else; a `boundary/v1`
  route has not been added there. Given this crosses a real trust
  boundary, that wiring should get read carefully (ideally build-tested)
  before it lands, not added blind.

## When the boundary hurts

If something here is awkward to build against, the fix is a Ferryman
defect report, not a workaround inside Custodly. Custodly is the first
real consumer of Ferryman's secrets-layer roadmap; friction found here now
is friction a stranger won't hit later.
