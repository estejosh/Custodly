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
- sealing at rest - PBKDF2-SHA256 at 600,000 iterations, XChaCha20-Poly1305
- the human interface - a dashboard, because end users never touch a CLI

Custodly owns: provider adapters, the recipes, the scoring model, the
request-to-key flow, scope and expiry verification, rotation schedules, and
the record of what was acquired and why.

If you find yourself writing a permission model, a user model, or a sync
mechanism, stop - that work is done, consume it.

## Order of work

1. `docs/BOUNDARY.md` - the line, plus the versioned interface.
2. Answer the working-store password question, in `docs/THREAT-MODEL.md`.
3. Unblock the vault: KeePassXC installed, `working.kdbx` and `master.kdbx`
   created. Josh types both passwords. No agent ever sees either.
4. `git init`, first commit, public remote.
5. Then the GitHub App walking skeleton: request to sealed deposit, end to
   end, one provider, no n8n yet. Prove the contract before building the
   pipeline around it.

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
