# Threat model

## The working-store password

`working.kdbx`'s password is never a file, obfuscated or otherwise, next
to the database — that's not protection, it's a second standing root
credential with a worse name. It's resolved at process start through the
OS keystore via the `keyring` crate (Windows Credential Manager, Apple
Keychain, Secret Service/KWallet on Linux) — the same mechanism Ferryman
already uses, not a third one invented here. The password lives nowhere
on disk; it's only ever held in the OS's own credential store, scoped to
Josh's local account.

`master.kdbx`'s password is never machine-held at all. Josh types it. No
agent, script, or keystore entry ever holds it.

## What an attacker gets, by access level

**Read access to `X:\Custodly`** (Syncthing misconfig, backup leak, a
second account with filesystem read):
- Gets: `working.kdbx` and `master.kdbx` as KeePassXC-format ciphertext;
  recipe and workflow source (logic only — no secret ever appears in a
  log, transcript, or file, so there's nothing to read there); the design
  docs.
- Does not get: either password. Filesystem read is a different privilege
  level than OS-keystore access or Josh's typed input — this attacker has
  two opaque encrypted files and nothing else.

**Code execution as Josh's OS user** (compromised dependency, a
malicious tool run under his account):
- Gets: full plaintext read/write of `working.kdbx` — any process running
  as that user can call the same keystore API the client does. This is
  the actual limit of "local cache convenience": it's exactly as strong
  as OS-user isolation and no stronger. It is the reason Tier 2 and any
  secret meant for someone else never sit in `working.kdbx` even
  transiently past the single acquisition that produced them — see
  `BOUNDARY.md`.
- Does not automatically get: `master.kdbx` (password never machine-held)
  or anything already deposited into Ferryman for another identity (needs
  that identity's own key, which this process doesn't have).

**A compromised agent** (prompt-injected, buggy, or malicious logic —
abusing the legitimate interfaces rather than holding OS code execution):
- Gets: whatever the request-to-key flow legitimately hands it — a
  Tier 0/1 key, scoped as asked. A key that comes back broader than
  requested is quarantined and reported, never stored, so it can't be
  harvested by asking innocuously and hoping for scope creep.
- Cannot get past `policy()`'s tier check by asking nicely: Tier 2 is
  gated in Custodly's own code path, not something a caller can talk its
  way around, so a compromised agent still hits the human gate on a
  billing-scope request exactly as an honest one would.
- Cannot read `master.kdbx` (no standing access, ever, for any agent) or
  another person's deposited secret (Ferryman's grant model caps it at
  that person's own permissions — the reason cross-person material is
  Ferryman's problem and not a second, weaker access-control system
  built inside Custodly).

## Standing invariants

- A secret never appears in a log, transcript, or error message. Severity
  one — any exception path touching a secret value gets redacted before
  it's ever formatted, not after.
- Revoking a person in Ferryman revokes every agent acting for them,
  immediately — Custodly has no separate revocation path to keep in sync.
- An unrecognized scope fails closed (treated as Tier 2) rather than being
  silently trusted, and stays rare by design — see `design-brief.md`.
