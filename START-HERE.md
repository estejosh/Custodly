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

## The conflict this creates - resolve it before building

`design-brief.md` says the working store is where "agents read/write freely".
Ferryman's model says an agent's access is capped at its owner's permissions,
per project. Both cannot be true.

A single `working.kdbx` that every agent can open is one permission level for
everyone: David's sales agent can read Redaktly's production keys the moment
it can read the file. That is fine for a single-operator MVP on beastly and
it is wrong the first time a second person is involved - which is now, David
is already onboarded.

Resolve it deliberately. The likely shape: `working.kdbx` stays the local
cache for one operator on one machine, and anything crossing a machine or a
person boundary goes through Ferryman sealed to that recipient's key, with
Ferryman's grants deciding who can open it. Custodly hands Ferryman a sealed
secret and a scope label; Ferryman decides who sees it.

Write the answer in `docs/BOUNDARY.md` along with the interface. Two calls is
the target:

  deposit(sealed_secret, metadata) -> receipt
  policy(provider, requested_scope) -> tier, and what that tier requires

Custodly never learns who David is. Ferryman never learns how to talk to
Stripe. Version the contract from the first commit so the two repos can move
at different speeds.

## The unanswered question in the MVP

`mvp-scope.md` says the client reads and writes `working.kdbx` "once its own
password is configured". Configured where, held how?

If that password sits in a file next to the database, the working store is
not protected, it is obfuscated, and Custodly has invented a new standing
root credential while trying to eliminate one. This is the single most
important detail in the MVP and it is currently a phrase rather than a
design.

Ferryman already solved this for its own keys: it depends on the `keyring`
crate with `windows-native`, `apple-native` and `sync-secret-service`, so the
OS keystore holds the secret and the process asks for it. Do the same rather
than inventing a third mechanism. Whatever you choose, state explicitly what
an attacker with read access to `X:\Custodly` gets, and what one with code
execution as Josh's user gets - those are different answers and both belong
in the threat model.

## Corrections to the current docs

**The device shell is not down.** `mvp-scope.md` lists `device_bash` being
broken as the blocker for `git init`, `keepassxc-cli`, and creating the
`.kdbx` files. `device_bash` is indeed broken on beastly - a Windows update
in September - but Desktop Commander's `start_process` runs commands on that
machine fine and has all session. The blocker is not shell access.

**The real blocker is that KeePassXC is not installed.** `keepassxc-cli`
ships inside the KeePassXC install; there is no vault to write to until it
exists. An install attempt on 15 Sep failed with MSI 1603 because the UAC
prompt went unanswered. Nothing downstream works until that is done, so it is
the first thing to clear.

**It is KeePassXC, not KeePassXS.** The typo is consistent across README.md,
design-brief.md and mvp-scope.md. Fix it before it reaches anything public -
a secrets product that misspells its own vault does not read as careful.

**Sanity-check the GitHub App plan against current docs before building.**
`mvp-scope.md` already flags this. Worth doing properly: installation access
token scoping and expiry behaviour is the load-bearing assumption of the
whole pilot.

## Order of work

1. `docs/BOUNDARY.md` - the line above, plus the versioned interface. Short.
   If it takes ten pages, the line is in the wrong place.
2. Answer the working-store password question, in `docs/THREAT-MODEL.md`,
   with the two attacker cases named above plus the compromised-agent case.
3. Unblock the vault: KeePassXC installed, `working.kdbx` and `master.kdbx`
   created. Josh types both passwords. No agent ever sees either.
4. `git init`, first commit, private remote.
5. Then the GitHub App walking skeleton: request to sealed deposit, end to
   end, one provider, no n8n yet. Prove the contract before building the
   pipeline around it.

The n8n side comes after the contract holds. Building the automation first
means rewriting it when the contract moves.

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
- Scratch files go in `X:\ferrytmp`, never under `C:\Users\oshha`.
- No "Co-Authored-By" trailers in commits.
- Ship a beta and label it beta. Do not hold a release for more testing.

## Why this matters to Ferryman

Ferryman's roadmap has a sovereign vault built on its secrets layer. That
layer has no real consumer yet, so nobody knows where it is weak. Custodly is
the first one. Every awkward thing you hit at the boundary is a Ferryman
defect found before a stranger finds it.

So when the interface is painful, do not work around it inside Custodly.
Write the defect down and fix it in Ferryman. That discipline is worth more
to the portfolio than any feature in this repo.

Josh's standard for both projects: if the software is not solid, nobody will
want to use it. Solid here means you can demonstrate each of these:

- a secret never appears in a log, a transcript, or an error message
- revoking a person revokes every agent acting for them, immediately
- a Tier 2 request is gated every time, no matter how trusted the provider is
- an unrecognized scope fails closed, and that stays rare enough not to be a
  tax on routine work
- a key returned with more scope than requested is quarantined, not stored
- the routine path, end to end, involves no human interruption at all

Start with `docs/BOUNDARY.md`. Decide what you can; ask Josh only what you
genuinely cannot.
