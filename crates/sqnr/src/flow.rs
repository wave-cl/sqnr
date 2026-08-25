//! The one admin transaction: fetch a challenge, sign the command, POST it.
//!
//! This is the whole authority protocol in one function, shared by the CLI and
//! the GUI. The card only ever signs a command bound to a *live* server nonce,
//! so a caller that retries after a dropped connection simply re-runs this with
//! a fresh challenge — there is no way to double-apply a captured signature.

use sqnr_core::{Action, Command, PubKey, SignedCommand};

use crate::client::Client;
use crate::signer::Backend;

/// Run one signed admin action against `server`, returning the server's JSON.
///
/// `on_touch` is invoked immediately before a YubiKey signature so a UI can
/// prompt for the tap; it is not called for a software identity.
pub async fn run_once(
    client: &mut Client,
    backend: &Backend,
    server: PubKey,
    action: Action,
    on_touch: &dyn Fn(),
) -> Result<serde_json::Value, String> {
    let (cs, nonce_bytes) = client.get("/admin/challenge").await?;
    if cs != 200 || nonce_bytes.len() != 32 {
        return Err(format!("challenge failed (status {cs})"));
    }
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&nonce_bytes);
    let command = Command {
        action,
        nonce,
        server,
    };

    if backend.is_yubikey() {
        on_touch();
    }
    let signature = backend.sign(&command.signing_bytes()).await?;

    let signed = SignedCommand {
        command,
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
