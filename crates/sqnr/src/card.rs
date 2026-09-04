//! YubiKey access on a dedicated thread that owns the card.
//!
//! The card is opened once and a single OpenPGP session is held for the app's
//! lifetime, so PW1 (the user PIN) is verified once and later signatures need
//! only a touch. PC/SC and openpgp-card are blocking and not `Send`-friendly,
//! so all card work stays on this one thread; the async worker talks to it over
//! channels.

use std::sync::mpsc::{Receiver, Sender, channel};

use card_backend_pcsc::PcscBackend;
use openpgp_card::Error as CardError;
use openpgp_card::ocard::algorithm::{AlgorithmAttributes, Curve, EccAttributes};
use openpgp_card::ocard::crypto::{EccType, PublicKeyMaterial};
use openpgp_card::ocard::data::{Fingerprint, KeyGenerationTime};
use openpgp_card::ocard::{KeyType, OpenPGP, Transaction};
use secrecy::SecretBox;
use sha1::{Digest, Sha1};
use tokio::sync::oneshot;

enum Req {
    Pubkey(oneshot::Sender<Result<[u8; 32], String>>),
    Unlock(String, oneshot::Sender<Result<(), String>>),
    Sign(Vec<u8>, oneshot::Sender<Result<[u8; 64], String>>),
    /// The admin PIN (PW3), and the generated public key on success.
    Provision(String, oneshot::Sender<Result<[u8; 32], String>>),
}

/// A handle to the card thread. Cheap to clone; all clones drive the one card.
#[derive(Clone)]
pub struct Card {
    tx: Sender<Req>,
}

impl Card {
    pub fn spawn() -> Card {
        let (tx, rx) = channel();
        std::thread::spawn(move || card_loop(rx));
        Card { tx }
    }

    /// Read the Authentication slot's Ed25519 public key (no PIN).
    pub async fn pubkey(&self) -> Result<[u8; 32], String> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(Req::Pubkey(reply))
            .map_err(|_| "card thread stopped".to_string())?;
        rx.await
            .map_err(|_| "card thread dropped the request".to_string())?
    }

    /// Verify the user PIN once for the session.
    pub async fn unlock(&self, pin: String) -> Result<(), String> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(Req::Unlock(pin, reply))
            .map_err(|_| "card thread stopped".to_string())?;
        rx.await
            .map_err(|_| "card thread dropped the request".to_string())?
    }

    /// Generate an Ed25519 key in the Authentication slot and return its
    /// public key. Requires the **admin** PIN (PW3), not the user PIN.
    ///
    /// **This overwrites whatever is in the Authentication slot, permanently.**
    /// A card whose key backs an admin identity somewhere loses that identity
    /// the moment this succeeds, and no part of this crate can undo it. The
    /// caller is responsible for saying so before asking for the PIN.
    ///
    /// The PIN arrives as a parameter rather than being prompted here: this
    /// module runs on the card thread and has no terminal, and the operator
    /// entering their own PIN is a property `sqnr` states about itself.
    pub async fn provision(&self, admin_pin: String) -> Result<[u8; 32], String> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(Req::Provision(admin_pin, reply))
            .map_err(|_| "card thread stopped".to_string())?;
        rx.await
            .map_err(|_| "card thread dropped the request".to_string())?
    }

    /// Sign `msg` with the Authentication key. Requires an earlier `unlock`;
    /// with touch enabled the card blocks here until tapped.
    pub async fn sign(&self, msg: Vec<u8>) -> Result<[u8; 64], String> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(Req::Sign(msg, reply))
            .map_err(|_| "card thread stopped".to_string())?;
        rx.await
            .map_err(|_| "card thread dropped the request".to_string())?
    }
}

fn open() -> Result<OpenPGP, String> {
    let backend = PcscBackend::cards(None)
        .map_err(|e| e.to_string())?
        .next()
        .ok_or_else(|| "no OpenPGP card found (is the YubiKey inserted?)".to_string())?
        .map_err(|e| e.to_string())?;
    OpenPGP::new(backend).map_err(|e| e.to_string())
}

/// Own the card across requests. The PC/SC connection is held open in *shared*
/// mode (so other tools and other instances can still reach the card), and each
/// request runs in its own brief transaction. PW1 persists across those
/// transactions because the backend only re-SELECTs the applet after a card
/// reset — so the PIN is verified once, yet the card is never locked
/// exclusively for the app's lifetime. A comm failure drops the connection and
/// the next request reopens it, re-locking.
fn card_loop(rx: Receiver<Req>) {
    loop {
        // Block until there is work, so we don't open the card speculatively.
        let Ok(first) = rx.recv() else { return };

        let mut card = match open() {
            Ok(c) => c,
            Err(e) => {
                reply_err(first, &e);
                continue;
            }
        };

        if !handle_req(&mut card, first) {
            continue; // card went away mid-request; reopen on the next one
        }
        loop {
            let Ok(req) = rx.recv() else { return };
            if !handle_req(&mut card, req) {
                break;
            }
        }
    }
}

/// Run one request in a short-lived transaction on the held connection.
fn handle_req(card: &mut OpenPGP, req: Req) -> bool {
    let mut tx = match card.transaction() {
        Ok(t) => t,
        Err(e) => {
            reply_err(req, &e.to_string());
            return false; // reopen the connection on the next request
        }
    };
    handle(&mut tx, req)
}

/// Handle one request. Returns false if the session should be reopened.
fn handle(tx: &mut Transaction<'_>, req: Req) -> bool {
    match req {
        Req::Pubkey(reply) => {
            let r = read_pubkey(tx);
            let keep = !is_comm_failure(&r);
            let _ = reply.send(r);
            keep
        }
        Req::Unlock(pin, reply) => {
            let r = tx
                .verify_pw1_user(SecretBox::new(pin.into_bytes().into_boxed_slice()))
                .map_err(|e| format!("PIN rejected: {e}"));
            let keep = !is_comm_failure(&r);
            let _ = reply.send(r);
            keep
        }
        Req::Provision(pin, reply) => {
            let r = provision_auth(tx, pin);
            let keep = !is_comm_failure(&r);
            let _ = reply.send(r);
            keep
        }
        Req::Sign(msg, reply) => {
            let r = tx
                .internal_authenticate(msg)
                .map_err(|e| format!("sign failed: {e}"))
                .and_then(|s| {
                    <[u8; 64]>::try_from(s.as_slice())
                        .map_err(|_| "card returned a non-64-byte signature".to_string())
                });
            let keep = !is_comm_failure(&r);
            let _ = reply.send(r);
            keep
        }
    }
}

fn read_pubkey(tx: &mut Transaction<'_>) -> Result<[u8; 32], String> {
    match tx.public_key(KeyType::Authentication) {
        Ok(PublicKeyMaterial::E(ecc)) => <[u8; 32]>::try_from(ecc.data())
            .map_err(|_| "auth key is not a 32-byte Ed25519 point".to_string()),
        Ok(PublicKeyMaterial::R(_)) => Err("auth key is RSA, not Ed25519".to_string()),
        Err(e) => Err(format!(
            "no Ed25519 auth key ({e}); generate one with `sqnr --yubikey provision`"
        )),
    }
}

/// Set the Authentication slot to Ed25519 and generate a key on-card.
///
/// Ported from `sqex-admin`'s `yubikey_spike`, which proved this path and was
/// retired with the crate around it. The card generates the key itself, so the
/// private half never exists off the card and cannot be backed up — which is
/// the point, and also why this is irreversible.
fn provision_auth(tx: &mut Transaction<'_>, pin: String) -> Result<[u8; 32], String> {
    // PW3 is at least 8 characters. Checking here rather than letting the card
    // refuse turns the commonest mistake — entering the 6-digit *user* PIN —
    // into a sentence that says which PIN was wanted, and spends no retry
    // counter doing it.
    if pin.len() < 8 {
        return Err(format!(
            "admin PIN is {} characters; PW3 needs at least 8. That is the ADMIN \
             PIN (default 12345678), not the 6-digit user PIN.",
            pin.len()
        ));
    }
    tx.verify_pw3(SecretBox::new(pin.into_bytes().into_boxed_slice()))
        .map_err(|e| format!("admin PIN rejected: {e}"))?;

    let attrs = AlgorithmAttributes::Ecc(EccAttributes::new(EccType::EdDSA, Curve::Ed25519, None));
    tx.set_algorithm_attributes(KeyType::Authentication, &attrs)
        .map_err(|e| format!("could not set the slot to Ed25519: {e}"))?;

    let (pk, _ts) = tx
        .generate_key(ed25519_fingerprint, KeyType::Authentication)
        .map_err(|e| format!("key generation failed: {e}"))?;
    match pk {
        PublicKeyMaterial::E(ecc) => <[u8; 32]>::try_from(ecc.data())
            .map_err(|_| "generated key is not a 32-byte Ed25519 point".to_string()),
        _ => Err("card generated a non-ECC key".to_string()),
    }
}

/// The OpenPGP v4 fingerprint of an Ed25519 public key.
///
/// The card stores it as metadata. `INTERNAL AUTHENTICATE` — the operation
/// every signature here uses — does not depend on it, but a correct value keeps
/// the card legible to `gpg` and `ykman`, which is worth the twenty lines.
///
/// SHA-1 is not a choice: RFC 4880 defines the v4 fingerprint that way, and a
/// different hash would produce metadata no other tool could read. Nothing is
/// authenticated by it here.
///
/// Must be a plain `fn`: the API takes a function pointer, not a closure.
fn ed25519_fingerprint(
    pk: &PublicKeyMaterial,
    ts: KeyGenerationTime,
    _kt: KeyType,
) -> Result<Fingerprint, CardError> {
    let point = match pk {
        PublicKeyMaterial::E(ecc) => ecc.data(),
        _ => {
            return Err(CardError::InternalError(
                "expected an ECC public key".into(),
            ));
        }
    };

    // v4 public-key packet body for EdDSA (RFC 4880bis).
    let mut body = Vec::new();
    body.push(0x04); // version
    body.extend_from_slice(&ts.get().to_be_bytes()); // creation time
    body.push(0x16); // algorithm 22 = EdDSA
    let oid: [u8; 9] = [0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01]; // Ed25519
    body.push(oid.len() as u8);
    body.extend_from_slice(&oid);
    // Public point as an MPI: 0x40 prefix + 32 bytes = 263 bits.
    body.extend_from_slice(&263u16.to_be_bytes());
    body.push(0x40);
    body.extend_from_slice(point);

    let mut hasher = Sha1::new();
    hasher.update([0x99]);
    hasher.update((body.len() as u16).to_be_bytes());
    hasher.update(&body);
    let digest: [u8; 20] = hasher.finalize().into();
    Ok(Fingerprint::from(digest))
}

/// Whether an error looks like the card is gone (removed/reset/transport lost),
/// as opposed to a logical rejection like a bad PIN. Only the former should
/// tear down and reopen the session.
fn is_comm_failure<T>(r: &Result<T, String>) -> bool {
    match r {
        Ok(_) => false,
        Err(e) => {
            let e = e.to_ascii_lowercase();
            [
                "removed",
                "reset",
                "transmit",
                "no smart card",
                "not transacted",
                "disconnected",
            ]
            .iter()
            .any(|needle| e.contains(needle))
        }
    }
}

fn reply_err(req: Req, err: &str) {
    match req {
        Req::Pubkey(reply) => {
            let _ = reply.send(Err(err.to_string()));
        }
        Req::Unlock(_, reply) => {
            let _ = reply.send(Err(err.to_string()));
        }
        Req::Sign(_, reply) => {
            let _ = reply.send(Err(err.to_string()));
        }
        Req::Provision(_, reply) => {
            let _ = reply.send(Err(err.to_string()));
        }
    }
}
