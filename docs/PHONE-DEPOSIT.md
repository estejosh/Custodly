# Phone deposit: custodly-deposit/v1

How a key typed into the Custodly phone app reaches the vault and the right
Ferryman project, with no Tailscale, no open port and nothing secret in
Telegram. Everything travels as files in one Syncthing folder; a file in that
folder is either public or ciphertext.

## Roles

- **Intake** (`custodly-intake`, on beastly): holds the intake X25519 key
  (Windows Credential Manager, never a file), reads `inbox/`, writes `outbox/`.
- **Phone app**: holds an Ed25519 device key (app-private storage) and the
  pinned intake public key. It can send deposits; it cannot read anything back.
- **Portal** (beastly): where the owner enrolls a phone, once.

## Folder layout (sync dir)

    pairing.json                 intake -> phone, public
    outbox/projects.json         intake -> phone, the projects a key may go to
    outbox/device-<id>.json      intake -> phone, enrollment result
    outbox/receipt-<id>.json     intake -> phone, what happened to a deposit
    inbox/enroll-<id>.json       phone -> intake, public
    inbox/dep-<id>.json          phone -> intake, ciphertext + signature

## Trust bootstrap

`pairing.json` carries the intake public key and its fingerprint
(`ab12-cd34-ef56`, the first 6 bytes of SHA-256 of the key). The phone shows
the fingerprint and the owner confirms it matches the one beastly shows before
the key is pinned. The phone then writes `enroll-<id>.json` with its device
public key. Beastly shows a 6-digit code derived from that key; the owner
compares it to the one on the phone and clicks Enroll in the portal. Until
then every deposit from that device is rejected.

`device_id` = first 8 bytes of SHA-256(device public key), hex.
Device code = first 4 bytes of the same hash, as a big-endian integer mod
1,000,000, zero padded to 6 digits.

## Deposit file

    {"v":"custodly-deposit/v1","id":<32 hex>,"device_id":<16 hex>,
     "created":<RFC 3339 UTC>,"intake_fp":<12 hex>,
     "eph_pub":<64 hex>,"nonce":<24 hex>,"ct":<hex>,"sig":<128 hex>}

Crypto (all hex on the wire):

1. `shared = X25519(eph_secret, intake_pub)`, fresh ephemeral key per deposit.
2. `key = HKDF-SHA256(ikm=shared, salt=eph_pub || intake_pub, info="custodly-deposit/v1")`, 32 bytes.
3. `aad = "custodly-deposit/v1\n" + id + "\n" + device_id + "\n" + created + "\n" + intake_fp` (UTF-8).
4. `ct = ChaCha20-Poly1305(key, nonce(12 bytes), aad, plaintext)`; the 16-byte tag is appended.
5. `sig = Ed25519(device_secret, aad + "\n" + eph_pub + "\n" + nonce + "\n" + ct)` over the UTF-8 bytes of those hex strings.

Plaintext is JSON: `{"project","name","value","label"?,"note"?}`, value at
most 16 KiB. Intake verifies the signature first, then opens, and accepts a
given `id` once. `created` must be within 14 days in the past and 1 day in the
future (a phone can be offline, a clock can be wrong).

## What intake does with a good deposit

1. Stores it in `working.kdbx` at `<project>/<label>` with source `phone-deposit:<device_id>`.
2. If a Ferryman base URL and token are configured for that project, deposits
   it through `boundary/v1`, sealed to the project's ingestion key, so the
   project's agents receive it.
3. Writes `outbox/receipt-<id>.json` with status `delivered`, `stored` (kept in
   the vault, not yet delivered, with the reason) or `rejected`.

No receipt ever contains the value.

## Failure rules

Anything that does not verify is rejected and recorded, never partly applied:
unknown device, bad signature, wrong intake key, replayed id, unknown project,
bad name, oversize value, decryption failure, stale or future `created`.
A file that is not yet valid JSON is retried, since sync can show a partial file.