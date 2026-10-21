# Feature: native custody of generated and hand-made secrets

Status: requested by Josh, 5 Oct 2026. Not built.

## The gap (real incident, 5 Oct 2026)

Setting up Quantly's MEGA S4 backup needed two secrets: an S4 secret access key
(created in the MEGA dashboard) and a restic repository password (made up).
What actually happened:

- Josh pasted the S4 secret into a plain-text `.env` as `secret=`.
- An agent generated the restic password and appended it to the same `.env`.
  The file had no trailing newline, so it landed on the end of the `secret=`
  line, and the corrupted value was sealed and sent before anyone noticed.
- The agent then sealed both values to grouchly via `ferry channel secret set`,
  signed as its own machine because signing as Josh needs his password.
- Nothing reached KeePassXC. The only copies were a plain-text file and a
  Ferryman envelope, with Josh told to "copy it somewhere offline".

Custodly exists so that none of those steps involve a human or an agent
handling the raw secret. It should have done all of this natively.

## What Custodly should do

1. **Generate.** `custodly generate <name> --kind password|token|key` creates a
   strong secret inside Custodly and writes it straight to `working.kdbx`.
   No agent ever sees the value.
2. **Capture.** `custodly capture <name>` takes a value a human got from a
   dashboard (paste once into a Custodly prompt or form, never into a file or a
   chat) and writes it to `working.kdbx` with provider, scope and expiry.
3. **Import and scrub.** `custodly import-env <file>` moves secret-shaped lines
   from a `.env` into the vault, replaces them with a reference, and reports
   what it moved. This is how existing `.env` files migrate.
4. **Deliver.** Delivery to another machine always goes through Ferryman
   `boundary/v1 deposit`, sealed to the recipient, so the vault stays the
   source of truth and the sealed copy is derived from it. Re-sealing after a
   rotation is one command.
5. **Recovery copy.** Anything whose loss is unrecoverable (restic passwords,
   signing-key passphrases) is flagged `recovery_critical` and Custodly prompts
   the operator to confirm a second copy exists, instead of a chat reminder.
6. **Provider recipes.** MEGA S4 belongs in Track 2: a recipe that creates the
   user, the access key and the bucket policy, and captures the secret without
   a human copying it off the screen. (MEGA S4 has no custom IAM policies:
   isolation is a zero-policy user plus a bucket policy naming that user.)

## Rules

- No secret value ever in a file outside the vault, in argv, in chat, or in a
  Ferryman message body.
- Agents ask Custodly for a deposit to a named recipient; they never hold the
  value themselves.
- Dashboard or form for humans; CLI is for machines (same rule as Ferryman).

## First migration to run once it exists

`X:\Quantly\.env` currently holds `user`, `secret` (MEGA S4 for the
`grouchly-backup` user) and `QUANTLY_RESTIC_PASSWORD` in plain text. Import
them, mark the restic password `recovery_critical`, and re-deposit both to
grouchly through `boundary/v1`.
