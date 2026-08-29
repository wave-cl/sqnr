//! sqnr — the sQUIC signer.
//!
//! Signs admin transactions against a sqex-style HTTP/3 server, with authority
//! proven by an Ed25519 signature on the command itself (never the connection's
//! transport key). Two interchangeable backends produce that signature: an
//! [`identity`] file encrypted at rest, and a [`card`] (YubiKey). The
//! [`flow::run_once`] transaction is shared by the CLI and the desktop GUI.
//!
//! The signed-command protocol and key types live in [`sqnr_core`].

pub mod card;
pub mod client;
pub mod config;
pub mod flow;
pub mod identity;
pub mod signer;

pub use card::Card;
pub use client::{Client, Stream};
pub use signer::Backend;

/// Crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
