//! Optional defaults from `~/.sqnr/config` (TOML), so the common `--server` and
//! `--server-key` flags can be omitted. Command-line flags always win.

use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Server address, e.g. `127.0.0.1:5400`.
    pub server: Option<String>,
    /// Server's pinned Ed25519 public key, base58.
    pub server_key: Option<String>,
    /// Software identity path (default `~/.sqnr/identity`).
    pub identity: Option<PathBuf>,
    /// SIP-29 envelope version this client emits. `None` leaves squic's own
    /// default in place.
    ///
    /// A deployment-wide transport setting, not a per-connection one, which is
    /// why `Client` reads it from a process default rather than taking it as an
    /// argument — there are ~90 `connect`/`connect_as` call sites and none of
    /// them wants an opinion about the envelope.
    ///
    /// Set it to 3 to reach an exchange that has retired versions 1 and 2
    /// (SIP-37); such a server drops an older envelope in silence, so the
    /// symptom of getting this wrong is a handshake timeout with no diagnostic.
    pub envelope_version: Option<u8>,
}

impl Config {
    /// Load `~/.sqnr/config`, or an empty config if it does not exist.
    pub fn load() -> Config {
        let config = match dirs::home_dir().map(|h| h.join(".sqnr").join("config")) {
            Some(path) if path.exists() => Config::from_file(&path).unwrap_or_default(),
            _ => Config::default(),
        };
        config.apply_transport();
        config
    }

    pub fn from_file(path: &Path) -> Result<Config, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        toml::from_str(&text).map_err(|e| format!("parse {}: {e}", path.display()))
    }

    /// Push the transport settings this config carries into the process
    /// defaults every `Client` reads.
    ///
    /// Separate from parsing, and called by `load`, because the envelope
    /// version is process-wide rather than per-connection: a caller that builds
    /// a `Config` by hand can apply it deliberately, and one that only wants to
    /// read a file is not surprised by a side effect. `SQEX_ENVELOPE_VERSION`
    /// still applies when this leaves it unset.
    pub fn apply_transport(&self) {
        if let Some(v) = self.envelope_version {
            crate::client::set_envelope_version(v);
        }
    }
}
