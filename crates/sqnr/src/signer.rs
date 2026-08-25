//! The signing seam over both backends: an encrypted software identity and a
//! YubiKey. Both produce a raw Ed25519 signature over the same command bytes;
//! the software path never blocks, the YubiKey path may prompt for a PIN and
//! block on a physical touch.

use sqnr_core::{PubKey, Signer, SoftwareSigner};

use crate::card::Card;

/// A resolved admin signer. Its public key is fixed at construction so callers
/// can name the admin identity without an async round-trip to the card.
pub struct Backend {
    public: PubKey,
    inner: Inner,
}

enum Inner {
    // Boxed: a `SigningKey` is far larger than the `Card` handle (a channel
    // sender), and clippy flags the size skew otherwise.
    Software(Box<SoftwareSigner>),
    Yubi(Card),
}

impl Backend {
    /// A software identity that has already been decrypted into a signer.
    pub fn software(signer: SoftwareSigner) -> Self {
        let public = PubKey::new(signer.public());
        Self {
            public,
            inner: Inner::Software(Box::new(signer)),
        }
    }

    /// A YubiKey whose Authentication-slot public key has already been read.
    pub fn yubikey(card: Card, public: PubKey) -> Self {
        Self {
            public,
            inner: Inner::Yubi(card),
        }
    }

    /// The admin's Ed25519 public key.
    pub fn public(&self) -> PubKey {
        self.public
    }

    /// Whether signing this backend requires a physical touch (a YubiKey).
    pub fn is_yubikey(&self) -> bool {
        matches!(self.inner, Inner::Yubi(_))
    }

    /// Produce a raw RFC 8032 Ed25519 signature over `msg`.
    pub async fn sign(&self, msg: &[u8]) -> Result<[u8; 64], String> {
        match &self.inner {
            Inner::Software(s) => Ok(s.sign(msg)),
            Inner::Yubi(card) => card.sign(msg.to_vec()).await,
        }
    }
}
