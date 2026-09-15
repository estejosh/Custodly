# Custodly — MVP scope (decided 15 Sep 2026)

Three implementation questions were left open in the design brief. Deciding
them here rather than leaving them as questions, per direction to make the
call rather than keep asking:

## Track 1 pilot: GitHub, via a GitHub App

Not a plain PAT (GitHub has no API to mint those) — a **GitHub App**.
The App's private key is the one master secret (sealed, master store);
Custodly signs a JWT with it and calls GitHub's API to mint a short-lived,
narrowly-scoped **installation access token** (repo-limited, permission-
limited, ~1hr expiry) on demand. That token is Tier 0/1 and goes straight
in the working store. This is the cleanest possible match for the
trust-once-transact-many model already decided: one onboarding step
(create the App, install it on the target repos, seal the private key),
then fully automatic minting after that with no standing broad credential
ever leaving the master store. Worth sanity-checking against GitHub's
current App docs before building — verify nothing's changed there.

Chosen because GitHub is already the heaviest-used provider across the
portfolio, so it's real usage from day one rather than a synthetic test
case.

## Vault mechanism: keepassxc-cli, two .kdbx files

`keepassxc-cli` (scriptable, no daemon, works headless on Windows) wrapped
by the local client, rather than the KeePassXC-Browser protocol (built for
browser extensions, not automation). The working/master store split from
the design brief becomes two separate `.kdbx` files with independent
passwords — `working.kdbx` (client reads/writes freely once its own
password is configured) and `master.kdbx` (password known only to Josh,
entered to unlock for onboarding/recovery, never stored by the client).

## Login-allow gate, MVP version: manual one-time trust step

Full automated approval-ping flow (Telegram-style, matching Ferryman's
approval-gate pattern) is deferred — it needs a notification channel
decision that's a distraction from proving the core loop works. MVP
version: onboarding a new provider is a manual, deliberate step Josh runs
once (create the GitHub App, install it, seal the private key into
master.kdbx). Everything after that — minting, rotation, monitoring — is
automatic with zero prompts, which is the actual promise. The
approval-ping mechanic gets built once there's a second provider that
needs it and the pattern is proven.

## Real blocker (not a design question)

Device shell access to beastly (`device_bash`) is down as of 15 Sep 2026 —
a known Windows-update issue, not project-specific. Files can still be
written into `X:\Custodly` via the file-transfer tools, but `git init`,
running `keepassxc-cli`, and creating the `.kdbx` files all need an actual
shell and are blocked until that's restored (or done locally by Josh).
