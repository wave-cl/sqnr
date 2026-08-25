# sqnr — the sQUIC signer

sqnr signs admin **transactions** against an HTTP/3 server. Authority is an
**Ed25519 signature on the transaction** — never the connection's transport key —
and the signing key lives in one of two interchangeable backends: a **YubiKey**
(OpenPGP Authentication key) or a **software identity** in `~/.sqnr` (encrypted
for humans, or plaintext for unattended automation).

sqnr is **generic**: it signs an ordered batch of *opaque* operations it never
parses, each carrying the human context the operator approves. It does not know
any server's command set, so a new command never touches the signer. A service
(e.g. [sqex](https://github.com/wave-cl/sqex)) defines its own command
vocabulary and its own CLI on top of sqnr's library; sqnr itself ships a small
CLI for **identity management**.

## Why

A sQUIC connection proves a caller's key during the handshake, but some
authority cannot ride on the connection at all: a **YubiKey** signs with an
Ed25519 key and never releases the seed, and sQUIC's transport identity needs
that seed to derive its X25519 key. So a YubiKey administrator can never be
recognised by the transport `peer_key`.

The answer, across the ecosystem, is to make authority an **application-layer
Ed25519 signature on the command**, verified against a list of admin keys — the
model sqex already uses. sqnr is that signing half, pulled out of the desktop
GUI into a small reusable tool so the signing story has one home and the CLI can
move fast. A software key (for scripts and CI) and a YubiKey (for humans) are
the same signature to the server; only the key custody differs.

## The two backends

- **Software identity** — `~/.sqnr/identity`. `sqnr keygen` seals it with a
  passphrase (argon2id + ChaCha20-Poly1305); `sqnr keygen --plaintext` writes it
  unencrypted (mode 0600) so an automated caller can sign with **no prompt** —
  the deliberate trade-off for unattended signing. Either way the public key is
  stored in the clear, so `sqnr pubkey` never needs the passphrase and the
  signing path only prompts when the key is actually encrypted.
- **YubiKey** (`--yubikey`) — the OpenPGP Authentication subkey via INTERNAL
  AUTHENTICATE, a raw RFC 8032 Ed25519 signature. One PIN prompt per invocation,
  then a physical touch to sign.

The passphrase, PIN, and touch are always supplied by the operator at the
terminal; sqnr never stores them.

## How a signed transaction works

A transaction is an ordered batch of operations, replay-protected and bound to
one server. One signature authorizes the whole batch; the server applies it
atomically.

1. `GET /admin/challenge` → a single-use 32-byte nonce.
2. Build `Transaction { server, nonce, ops: [ { summary, detail, payload } … ] }`,
   where each `payload` is opaque to sqnr and each `summary` is the human context.
3. Sign `TX_CONTEXT(b"sqnr-tx-v1") || sha256(encode(transaction))` — a fixed-size
   hash, so a YubiKey signs one tap no matter how large the batch, and the
   summaries (being hashed in) are bound to the signature.
4. `POST /admin/command` with `{ transaction, admin_pubkey, signature }`.

The generic transaction protocol and the `PubKey` type live in `sqnr-core`; a
server depends on that crate alone to verify. The *meaning* of each payload lives
in the service, which re-renders the summary from the payload and checks it
matches — so the context the operator approved provably corresponds to what runs.

## Usage

sqnr's own CLI manages identities:

```
sqnr keygen                # create ~/.sqnr/identity, encrypted (prompts for a passphrase)
sqnr keygen --plaintext    # unencrypted key for automation (no prompt)
sqnr pubkey                # print the public key to add to a server's admin list
sqnr --yubikey pubkey      # the YubiKey's Authentication-key public key
```

Signing actual commands is done by the service's own tool built on the sqnr
library — for sqex, that is [`sqex`](https://github.com/wave-cl/sqex) (e.g.
`sqex --server … whitelist enable`). Common connection defaults can be set once
in `~/.sqnr/config`:

```toml
server = "127.0.0.1:5400"
server_key = "<base58 server pubkey>"
```

## Layout

- `sqnr-core` — keys and the generic signed-transaction protocol (no networking, no I/O).
- `sqnr` — the signing backends (file + YubiKey), the HTTP/3 client, the
  `sign_and_submit` flow, and the identity-management CLI.

Built on [squic](https://github.com/wave-cl/squic-rust); signs for
[sqex](https://github.com/wave-cl/sqex). Design proposals live in
[sips](https://github.com/wave-cl/sips).
