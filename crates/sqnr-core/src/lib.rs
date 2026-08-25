//! Shared types for sqnr: keys, and the signed admin-command protocol.
//!
//! This crate has no networking and no I/O. It defines what an administrator
//! signs and how a server checks it, so that any server (sqexd) and any signer
//! (a software key, a YubiKey) agree on the exact bytes. The full sqnr crate
//! layers the signing backends, the HTTP/3 client, and the CLI on top; a server
//! depends only on this crate to verify commands.

pub mod error;
pub mod key;
pub mod protocol;

pub use error::{Error, Result};
pub use key::PubKey;
pub use protocol::{Action, Command, Nonce, SIG_CONTEXT, SignedCommand, Signer, SoftwareSigner};

/// Crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
