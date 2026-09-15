# Custodly

Automated secrets acquisition + custody. Gets API keys/credentials from
providers — via their management API where one exists, via a maintained
browser recipe where it doesn't — and drops them straight into KeePassXS,
scoped and expiring, without a human or an agent handling the raw secret
in transit.

Full design: `docs/design-brief.md`
MVP scope + first build decisions: `docs/mvp-scope.md`

## Layout

- `client/` — local client: talks to the vault (KeePassXS via
  `keepassxc-cli`), exposes the request contract to n8n.
- `workflows/` — n8n workflow exports. One per provider/track.
- `recipes/` — Track 2 (dashboard-only provider) scripted acquisition
  flows, agent-authored, machine-executed.
- `docs/` — design brief, MVP scope, and anything else durable.

Status: scaffolding only, no code yet. `git init` and the KeePassXS
`.kdbx` files still need to be created on-machine (blocked on device shell
access as of 15 Sep 2026 — see mvp-scope.md).
