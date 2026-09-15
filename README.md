# Custodly

Automated secrets acquisition + custody. Gets API keys/credentials from
providers — via their management API where one exists, via a maintained
browser recipe where it doesn't — and drops them straight into KeePassXC,
scoped and expiring, without a human or an agent handling the raw secret
in transit.

Full design: `docs/design-brief.md`
MVP scope + first build decisions: `docs/mvp-scope.md`
Where Custodly stops and Ferryman starts: `docs/BOUNDARY.md`
Threat model: `docs/THREAT-MODEL.md`

## Layout

- `client/` — local client: talks to the vault (KeePassXC via
  `keepassxc-cli`), exposes the request contract to n8n.
- `workflows/` — n8n workflow exports. One per provider/track.
- `recipes/` — Track 2 (dashboard-only provider) scripted acquisition
  flows, agent-authored, machine-executed.
- `docs/` — design brief, MVP scope, boundary contract, threat model.

Status: scaffolding + docs only, no application code yet. KeePassXC
install and vault creation are the current blocker — see mvp-scope.md.

## License

[The Usufruct License (UFL) v1.0](https://github.com/estejosh/UFL-Usufruct-License) —
source-available, not OSI open source: free to use at any scale, license
required only to redistribute a modified version or fold the source into
another distributed product. Full terms in `LICENSE.md`.
