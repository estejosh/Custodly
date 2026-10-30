# AGENTS.md — Custodly

This file tells any agent (Claude, Codex, Gemini, whatever runs here next)
how to get a secret on this machine. Read this before ever opening `.env`,
`.git-credentials`, or grepping for a key by hand.

## How to get a secret

Never read a raw credential out of a dotfile, `.env`, or shell history.
Custodly's vault is a scoped, single-key lookup, not a browsable store:

- `custodly-vault::Vault::get(SecretQuery { project, label })` (Rust) or
  the equivalent CLI call resolves to exactly one entry — you ask for
  "the GitHub key for `<project>`" and get that value, nothing else. There
  is no `list`/`search` on the vault by design.
- If the secret you need doesn't exist yet, don't invent one or ask a
  human to paste one into a file. Request it: `custodly mint-github ...`
  (or the relevant Track 1/Track 2 acquisition) mints a fresh, correctly
  scoped credential and deposits it into the vault or, for Tier 2 /
  cross-machine delivery, into Ferryman via `boundary/v1`
  (`custodly-boundary.md`).
- Tier 2 requests (irreversible, shared-resource, or financial-exposure
  scopes) are always human-gated — see `custodly-design.md` §Risk tiering.
  Don't try to route around that by asking for a broader Tier 0/1 scope
  that happens to cover what you need.

## Do not use `gh auth login`

`gh auth login` (and any flow that leaves a long-lived token in
`.git-credentials` or the OS credential manager under a generic identity)
creates a standing, ambient credential with no project provenance and no
expiry tracking — exactly what Custodly exists to replace. If git
operations are failing with a 403 or auth error, that's a signal to mint
or refresh a properly scoped, tracked token through Custodly, not to run
`gh auth login` or hand-edit `.git-credentials`.

## `.env` in this repo

`.env` is never committed. Its only legitimate content going forward is
pointers (vault path, project/label names to query) — not raw secret
values. If you find a raw token sitting in `.env`, treat that as
technical debt to migrate into the vault with proper `DepositMetadata`
(`provider`, `project`, `source_description`, `acquired_via`,
`acquired_at`, `expires_at`, `tier`), not as a credential to keep using
as-is.

## Remote approval (planned, not yet built)

Josh wants a way to approve a Tier 2 request or authorize minting a new
PAT from his phone (Telegram) rather than only from a keyboard in front
of the machine. See `custodly-design.md` for status — until that exists,
Tier 2 gates still require Josh at the machine.

## Where this project lives
- Code on beastly: `X:\ferry\repos\custodly`
- Code on grouchly: not cloned there
- Work in those copies and nowhere else. Any other checkout of this repo (for example X:\<name> directly on the drive) is retired and must not be edited.
- Channel on beastly: `X:\ferry\comms\custodly-ferryman`
- Channel on grouchly: none on grouchly
- Find it from any machine with `ferry root show`. Scratch space is `X:\ferry\tmp` (beastly).

<!-- ferry:git begin -->
## Git: Forgejo first

- `origin` is Forgejo (`forgejo:estejosh/Custodly.git`, Josh's git server on grouchly). Fetch from it, branch from it, push to it. Pull requests and merges happen on Forgejo.
- GitHub is a copy. A relay on grouchly copies every branch and tag from Forgejo to GitHub within a minute or two. Never push to GitHub, never open or merge a pull request there, never change anything on GitHub.
- GitHub CI still runs on that copy. When it fails, a Ferryman order (or a Forgejo issue, where the repo has no channel) is opened with the error. Fix it here and push to Forgejo.
- If `origin` on your machine still points at GitHub: `git remote rename origin github && git remote add origin forgejo:estejosh/Custodly.git && git fetch origin`. The `forgejo` ssh alias exists on beastly and grouchly; anywhere else, ask in the ferryman channel.
<!-- ferry:git end -->
