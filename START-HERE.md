# Custodly - the Ferryman boundary

Read `docs/design-brief.md` and `docs/mvp-scope.md` first. They stand. The
problem statement, the two acquisition tracks, the scoring model for risk
tiers, trust-once-transact-many, the GitHub App pilot, the two-.kdbx split -
all decided, do not relitigate any of it.

This file covers the thing those documents do not: where Custodly stops and
Ferryman starts. Get that line wrong and you either rebuild Ferryman badly
inside Custodly, or you ship a vault that cannot leave one machine.

## The line

Ferryman (github.com/estejosh/ferryman) already owns, and already ships:

- identity - seed-derived ed25519 keys, one global Ferryman ID per person,
  operator keys derived per machine
- authorization - per-project grants, where an agent is capped at its owner's
  permissions automatically, and revoking a person revokes every agent acting
  for them
- transport - a Syncthing-carried channel that moves files between machines
  with no server in the middle and nothing that phones home
- sealing at rest - a secret sealed to one recipient's X25519 public key:
  X25519 ECDH, HKDF-SHA256 (salted with both public keys, per RFC 7748 -
  never the raw ECDH output directly), XChaCha20-Poly1305
  (`ferryman-channel/src/secrets.rs`). Corrected 2026-09-21: earlier
  drafts of this file said "PBKDF2-SHA256 at 600,000 iterations" - there is
  no PBKDF2 anywhere in Ferryman's code; that claim was never checked
  against the actual crate. There is also no "project-scoped ingestion
  key" primitive pre-existing to seal to - that had to be added
  (`boundary::ingestion_identity`, a project-scoped
  `secrets::EncryptionIdentity`) rather than reused as-is. See
  `docs/BOUNDARY.md`.
- the human interface - a dashboard, because end users never touch a CLI

Custodly owns: provider adapters, the recipes, the scoring model, the
request-to-key flow, scope and expiry verification, rotation schedules, and
the record of what was acquired and why.

If you find yourself writing a permission model, a user model, or a sync
mechanism, stop - that work is done, consume it.

## Order of work

1. DONE - `docs/BOUNDARY.md` - the line, plus the versioned interface.
2. DONE - the working-store password question, in `docs/THREAT-MODEL.md`:
   `working.kdbx` re-keyed to an OS-keystore-backed password 21 Sep 2026.
3. PARTLY DONE - the vault: KeePassXC installed, `working.kdbx` created.
   `master.kdbx` still does not exist - that, and the GitHub App creation
   below, are the same sitting: Josh creates the App, downloads its
   private key, creates `master.kdbx`, seals the key into it. No agent
   ever sees either password.
4. DONE - `git init`, first commit, public remote
   (github.com/estejosh/Custodly). Note: the `crates/` Rust workspace sat
   uncommitted on disk for two days after it was written - re-check
   `git status` for untracked work before assuming "committed" means
   "current."
5. DONE, proven against a live App - `custodly mint-github`: mint an
   installation token, verify it's no broader than requested, deposit it.
   `custodly-pilot` (App ID 5061156, installed on `estejosh/Custodly`
   only, `contents: read`) minted and verified for real 24 Sep 2026 -
   the run caught and fixed a false-positive scope-creep quarantine
   trip: GitHub always adds `metadata: read` to every installation
   token regardless of what's requested, which the checker didn't yet
   know to treat as baseline rather than creep. Tier 0/1 still deposits
   straight into `working.kdbx` locally; tier 2, or anything explicitly
   `--for-recipient`, now goes through a sealed `deposit()` call to
   Ferryman's `boundary/v1` instead (`custodly-core::client` +
   `custodly-core::seal::deposit_aad`), matching Ferryman's own
   `ferryman-channel/src/boundary.rs` side, which was already built and
   tested there. No n8n yet - still a CLI a human or an n8n node runs.

## House rules

- End users never touch a command line. A flow that ends in "run this
  command" is not finished.
- No secret travels over Telegram, in any form, ever.
- Nothing phones home. Provider calls the user asked for are not telemetry;
  anything else is, and Ferryman's whole pitch dies if Custodly breaks this.
- A secret must never appear in a log, a transcript, or an error message.
  That is a severity-one bug, not a papercut.
- A key that comes back broader than requested is quarantined and reported,
  never stored.
- No "Co-Authored-By" trailers in commits.
- Ship a beta and label it beta. Do not hold a release for more testing.
