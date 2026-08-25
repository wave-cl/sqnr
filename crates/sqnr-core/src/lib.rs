//! Shared types for sqnr: keys, and the generic signed-transaction protocol.
//!
//! This crate has no networking and no I/O. It defines what an administrator
//! signs — an opaque, batched [`Transaction`] with human context — and how a
//! server checks it, so that any server (sqexd) and any signer (a software key,
//! a YubiKey) agree on the exact bytes. The signer never parses a payload, so a
//! new server command never touches this crate. The full sqnr crate layers the
//! signing backends, the HTTP/3 client, and the CLI on top.

pub mod error;
pub mod key;
pub mod tx;

pub use error::{Error, Result};
pub use key::PubKey;
pub use tx::{Operation, SignedTransaction, Signer, SoftwareSigner, TX_CONTEXT, Transaction};

/// Crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
