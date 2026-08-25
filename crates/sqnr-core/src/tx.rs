//! The generic signed-transaction protocol.
//!
//! sqnr signs **transactions**, not commands: an ordered batch of opaque
//! [`Operation`]s, each carrying the bytes a server will act on plus the human
//! context the operator approves. sqnr never parses a payload — the meaning
//! lives entirely in the server and in whatever client built the batch — so a
//! new server command never touches the signer.
//!
//! What gets signed is a domain-separated **hash** of the canonical transaction
//! ([`Transaction::signing_bytes`]): the card sees a small fixed message no
//! matter how large the batch, and because the summaries are part of the hashed
//! bytes, the context the operator saw is bound to the signature. The
//! transaction also binds a single-use server nonce (replay) and the server's
//! own key (misdirection), exactly as the old command protocol did.

use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::key::PubKey;

/// Domain separator hashed into every transaction signature. Generic and
/// service-agnostic: the meaning of the payloads is the server's concern.
pub const TX_CONTEXT: &[u8] = b"sqnr-tx-v1";

// Decode bounds — a signed transaction arrives from the network, so cap it.
const MAX_OPS: u32 = 64;
const MAX_DETAIL: u32 = 32;
const MAX_STR: usize = 4096;
const MAX_PAYLOAD: usize = 64 * 1024;

/// One operation in a transaction: opaque payload plus its human context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Operation {
    /// One-line description of what this operation does, shown to the operator.
    pub summary: String,
    /// Optional extra context lines (e.g. the key being added).
    pub detail: Vec<String>,
    /// The bytes the server will act on. Opaque to sqnr.
    pub payload: Vec<u8>,
}

/// An ordered batch of operations, bound to a server and a single-use nonce.
/// Signing the batch authorizes all of it at once; the server applies it
/// atomically.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    pub server: PubKey,
    pub nonce: [u8; 32],
    pub ops: Vec<Operation>,
}

impl Transaction {
    /// Canonical encoding: server, nonce, then length-prefixed ops. The same
    /// bytes are hashed for the signature and sent on the wire, so there is
    /// exactly one representation.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(self.server.as_bytes());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&(self.ops.len() as u32).to_be_bytes());
        for op in &self.ops {
            put_bytes(&mut out, op.summary.as_bytes());
            out.extend_from_slice(&(op.detail.len() as u32).to_be_bytes());
            for line in &op.detail {
                put_bytes(&mut out, line.as_bytes());
            }
            put_bytes(&mut out, &op.payload);
        }
        out
    }

    fn decode_from(r: &mut Reader) -> Result<Transaction> {
        let server = PubKey::new(r.array::<32>()?);
        let nonce = r.array::<32>()?;
        let n = r.u32()?;
        if n > MAX_OPS {
            return Err(Error::Malformed(format!("too many ops: {n}")));
        }
        let mut ops = Vec::with_capacity(n as usize);
        for _ in 0..n {
            let summary = r.string(MAX_STR)?;
            let d = r.u32()?;
            if d > MAX_DETAIL {
                return Err(Error::Malformed(format!("too many detail lines: {d}")));
            }
            let mut detail = Vec::with_capacity(d as usize);
            for _ in 0..d {
                detail.push(r.string(MAX_STR)?);
            }
            let payload = r.bytes(MAX_PAYLOAD)?.to_vec();
            ops.push(Operation {
                summary,
                detail,
                payload,
            });
        }
        Ok(Transaction { server, nonce, ops })
    }

    /// The bytes actually signed: the domain tag followed by a SHA-256 of the
    /// canonical encoding. A fixed-size message, so a hardware signer is never
    /// asked to sign a large batch directly.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let digest = Sha256::digest(self.encode());
        let mut msg = Vec::with_capacity(TX_CONTEXT.len() + digest.len());
        msg.extend_from_slice(TX_CONTEXT);
        msg.extend_from_slice(&digest);
        msg
    }
}

/// Anything that can produce an Ed25519 signature for an admin. Implemented by a
/// software key and by a YubiKey; the protocol is identical either way.
pub trait Signer {
    /// The admin's Ed25519 public key.
    fn public(&self) -> [u8; 32];
    /// A raw RFC 8032 Ed25519 signature over `msg`.
    fn sign(&self, msg: &[u8]) -> [u8; 64];
}

/// A signer backed by an in-memory Ed25519 key. Used by tests and the CLI's
/// software-identity path; the YubiKey backend lives in the `sqnr` crate.
pub struct SoftwareSigner {
    key: SigningKey,
}

impl SoftwareSigner {
    pub fn new(key: SigningKey) -> Self {
        Self { key }
    }

    /// The 32-byte Ed25519 seed — the **secret**.
    ///
    /// Exposed for one reason: deriving the sQUIC transport key, so a caller can
    /// connect *as* this identity and be named by the server (SIP-3). Signing
    /// never needs it. A hardware identity has no seed to give, which is why
    /// only a software identity can hold a transport identity at all
    /// (see SIP-11).
    pub fn seed(&self) -> [u8; 32] {
        self.key.to_bytes()
    }
}

impl Signer for SoftwareSigner {
    fn public(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.key.sign(msg).to_bytes()
    }
}

/// A transaction plus the administrator's key and signature over it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedTransaction {
    pub transaction: Transaction,
    pub admin: PubKey,
    pub signature: [u8; 64],
}

impl SignedTransaction {
    /// Sign `transaction` with `signer`.
    pub fn create(transaction: Transaction, signer: &dyn Signer) -> Self {
        let signature = signer.sign(&transaction.signing_bytes());
        SignedTransaction {
            transaction,
            admin: PubKey::new(signer.public()),
            signature,
        }
    }

    /// Verify the signature and the server binding. The caller still must
    /// confirm the nonce is one it issued and unused, and that `admin` is
    /// authorized — both are stateful and live in the server.
    pub fn verify(&self, expected_server: &PubKey) -> Result<()> {
        if self.transaction.server != *expected_server {
            return Err(Error::WrongServer);
        }
        let vk = self.admin.verifying_key()?;
        let sig = Signature::from_bytes(&self.signature);
        vk.verify(&self.transaction.signing_bytes(), &sig)
            .map_err(|_| Error::BadSignature)
    }

    /// Wire form: the canonical transaction, then the admin key, then the
    /// signature. This is the HTTP/3 request body.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.transaction.encode();
        out.extend_from_slice(self.admin.as_bytes());
        out.extend_from_slice(&self.signature);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<SignedTransaction> {
        let mut r = Reader::new(bytes);
        let transaction = Transaction::decode_from(&mut r)?;
        let admin = PubKey::new(r.array::<32>()?);
        let signature = r.array::<64>()?;
        r.finish()?;
        Ok(SignedTransaction {
            transaction,
            admin,
            signature,
        })
    }
}

fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_be_bytes());
    out.extend_from_slice(b);
}

/// A minimal big-endian byte cursor for decoding, bounds-checked throughout.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| Error::Malformed("length overflow".into()))?;
        if end > self.buf.len() {
            return Err(Error::Malformed("unexpected end of message".into()));
        }
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.array::<4>()?))
    }

    fn bytes(&mut self, max: usize) -> Result<&'a [u8]> {
        let len = self.u32()? as usize;
        if len > max {
            return Err(Error::Malformed(format!("field of {len} bytes exceeds {max}")));
        }
        self.take(len)
    }

    fn string(&mut self, max: usize) -> Result<String> {
        let raw = self.bytes(max)?;
        String::from_utf8(raw.to_vec()).map_err(|_| Error::Malformed("invalid utf-8".into()))
    }

    fn finish(self) -> Result<()> {
        if self.pos != self.buf.len() {
            return Err(Error::Malformed(format!(
                "{} trailing bytes",
                self.buf.len() - self.pos
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn signer() -> SoftwareSigner {
        SoftwareSigner::new(SigningKey::from_bytes(&[9u8; 32]))
    }

    fn tx(server: PubKey) -> Transaction {
        Transaction {
            server,
            nonce: [3u8; 32],
            ops: vec![
                Operation {
                    summary: "Enable the whitelist".into(),
                    detail: vec![],
                    payload: vec![0x01],
                },
                Operation {
                    summary: "Add a peer".into(),
                    detail: vec!["peer: abc".into()],
                    payload: vec![0x03, 5, 5, 5],
                },
            ],
        }
    }

    #[test]
    fn round_trip_multi_op() {
        let server = PubKey::new([1u8; 32]);
        let signed = SignedTransaction::create(tx(server), &signer());
        let bytes = signed.encode();
        let back = SignedTransaction::decode(&bytes).unwrap();
        assert_eq!(signed, back);
        assert_eq!(back.transaction.ops.len(), 2);
    }

    #[test]
    fn valid_signature_verifies() {
        let server = PubKey::new([1u8; 32]);
        let signed = SignedTransaction::create(tx(server), &signer());
        assert!(signed.verify(&server).is_ok());
    }

    #[test]
    fn rejects_wrong_server() {
        let server = PubKey::new([1u8; 32]);
        let other = PubKey::new([2u8; 32]);
        let signed = SignedTransaction::create(tx(server), &signer());
        assert!(matches!(signed.verify(&other), Err(Error::WrongServer)));
    }

    #[test]
    fn rejects_tampered_payload() {
        let server = PubKey::new([1u8; 32]);
        let mut signed = SignedTransaction::create(tx(server), &signer());
        signed.transaction.ops[0].payload = vec![0x02]; // tamper after signing
        assert!(matches!(signed.verify(&server), Err(Error::BadSignature)));
    }

    #[test]
    fn rejects_tampered_summary() {
        let server = PubKey::new([1u8; 32]);
        let mut signed = SignedTransaction::create(tx(server), &signer());
        signed.transaction.ops[0].summary = "Disable the whitelist".into();
        assert!(matches!(signed.verify(&server), Err(Error::BadSignature)));
    }

    #[test]
    fn rejects_signature_from_other_key() {
        let server = PubKey::new([1u8; 32]);
        let mut signed = SignedTransaction::create(tx(server), &signer());
        signed.admin = PubKey::new(
            SigningKey::from_bytes(&[11u8; 32])
                .verifying_key()
                .to_bytes(),
        );
        assert!(matches!(signed.verify(&server), Err(Error::BadSignature)));
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let server = PubKey::new([1u8; 32]);
        let mut bytes = SignedTransaction::create(tx(server), &signer()).encode();
        bytes.push(0);
        assert!(SignedTransaction::decode(&bytes).is_err());
    }

    #[test]
    fn empty_batch_round_trips() {
        let server = PubKey::new([7u8; 32]);
        let t = Transaction {
            server,
            nonce: [0u8; 32],
            ops: vec![],
        };
        let signed = SignedTransaction::create(t, &signer());
        let back = SignedTransaction::decode(&signed.encode()).unwrap();
        assert_eq!(signed, back);
    }
}
