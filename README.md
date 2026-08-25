# sqnr — the sQUIC signer

sqnr signs admin transactions against a sqex-style HTTP/3 server. Authority is
an **Ed25519 signature on the command itself** — never the connection's
transport key — and the signing key lives in one of two interchangeable
backends: a **YubiKey** (OpenPGP Authentication key) or a **software identity**
in `~/.sqnr` (encrypted for humans, or plaintext for unattended automation). It
ships as a CLI.

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

## How a signed command works

Each command is replay-protected by challenge-response and bound to one server:

1. `GET /admin/challenge` → a single-use 32-byte nonce.
2. Sign the canonical bytes of `{ action, nonce, server_pubkey }` with the admin
   Ed25519 key (domain-separated by `sqex-admin-v1`).
3. `POST /admin/command` with `{ command, admin_pubkey, signature }`.

The signed-command protocol and the `PubKey` type live in `sqnr-core`; a server
depends on that crate alone to verify.

## Usage

```
sqnr keygen                                  # create ~/.sqnr/identity (prompts)
sqnr keygen --plaintext                      # unencrypted key for automation (no prompt)
sqnr pubkey                                  # print the admin key to authorize
sqnr --server 127.0.0.1:5400 --server-key <b58> status
sqnr whitelist enable                        # signs (passphrase prompt)
sqnr whitelist add <peer-b58>
sqnr whitelist list
sqnr audit -n 50
sqnr --yubikey whitelist enable              # sign with a YubiKey (PIN + touch)
```

`--server` / `--server-key` (and the default identity path) can be set once in
`~/.sqnr/config`:

```toml
server = "127.0.0.1:5400"
server_key = "<base58 server pubkey>"
```

## Layout

- `sqnr-core` — keys and the signed admin-command protocol (no networking, no I/O).
- `sqnr` — the signing backends, the HTTP/3 client, the transaction flow, and the CLI.

Built on [squic](https://github.com/wave-cl/squic-rust); signs for
[sqex](https://github.com/wave-cl/sqex). Design proposals live in
[sips](https://github.com/wave-cl/sips).
