//! The one admin transaction: fetch a challenge, sign a batch, POST it.
//!
//! This is the whole authority protocol in one function, shared by any client
//! (the sqex CLI, the GUI). The caller supplies opaque [`Operation`]s already
//! carrying their human context; sqnr binds them to a live server nonce, shows
//! the context, signs the batch once, and submits it. The card only ever signs a
//! transaction bound to a fresh nonce, so retrying after a dropped connection
//! simply re-runs this with a new challenge — a captured signature cannot be
//! double-applied.

use sqnr_core::{Operation, PubKey, SignedTransaction, Transaction};

use crate::client::Client;
use crate::signer::Backend;

/// Sign and submit a batch of operations against `server`, returning the
/// server's JSON response.
///
/// `on_review` is called with the assembled transaction before signing, so a UI
/// can show exactly what is about to be authorized. `on_touch` is called
/// immediately before a YubiKey signature (a tap); it is not called for a
/// software identity.
pub async fn sign_and_submit(
    client: &mut Client,
    backend: &Backend,
    server: PubKey,
    ops: Vec<Operation>,
    on_review: &dyn Fn(&Transaction),
    on_touch: &dyn Fn(),
) -> Result<serde_json::Value, String> {
    if ops.is_empty() {
        return Err("nothing to sign (empty transaction)".into());
    }
    let (cs, nonce_bytes) = client.get("/admin/challenge").await?;
    if cs != 200 || nonce_bytes.len() != 32 {
        return Err(format!("challenge failed (status {cs})"));
    }
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&nonce_bytes);
    let transaction = Transaction { server, nonce, ops };

    on_review(&transaction);
    if backend.is_yubikey() {
        on_touch();
    }
    let signature = backend.sign(&transaction.signing_bytes()).await?;

    let signed = SignedTransaction {
        transaction,
        admin: backend.public(),
        signature,
    };
    let (status, body) = client.post("/admin/command", signed.encode()).await?;
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
    if status != 200 {
        let detail = value["detail"].as_str().unwrap_or("");
        let kind = value["error"].as_str().unwrap_or("error");
        return Err(format!("{kind} ({status}) {detail}").trim().to_string());
    }
    Ok(value)
}
