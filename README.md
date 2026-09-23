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

- `crates/` — the Rust workspace. `custodly-core` (tiering model, the
  `boundary/v1` contract with Ferryman, sealing), `custodly-vault`
  (KeePassXC-backed vault client), `custodly-github` (Track 1 pilot: GitHub
  App JWT signing + installation-token minting), `custodly-cli` (glues
  them together; not an end-user surface, see `START-HERE.md`).
- `client/vault/` — the actual `working.kdbx` database `custodly-vault`
  reads and writes.
- `workflows/` — n8n workflow exports. One per provider/track. Not built
  yet — the CLI proves the pipeline first.
- `recipes/` — Track 2 (dashboard-only provider) scripted acquisition
  flows, agent-authored, machine-executed. Empty until Track 1 is live.
- `docs/` — design brief, MVP scope, boundary contract, threat model.

Status: the storage/policy/tiering layer and the Track 1 GitHub App
minting pipeline are built and tested (`cargo test --workspace`), wired
together end to end behind `custodly mint-github`. Not yet runnable for
real — no GitHub App exists to mint against — and nothing here is called
from n8n yet.

## License

[![License: UFL-2.1](https://img.shields.io/badge/license-UFL--2.1-blue)](https://github.com/estejosh/UFL-Usufruct-License)

[The Usufruct License (UFL) v2.1](https://github.com/estejosh/UFL-Usufruct-License) —
Operational Scope: Unconditional. Source-available, not OSI open source: free
to use at any scale, license
required only to redistribute a modified version or fold the source into
another distributed product. Full terms in `LICENSE.md`.
