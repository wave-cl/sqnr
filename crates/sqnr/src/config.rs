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
    /// **There is nothing to choose today.** squic implements version 4 and
    /// only version 4; versions 1 to 3 were removed rather than deprecated, so
    /// leave it unset. A value squic cannot emit is refused at dial, naming
    /// the version it does emit — which matters because a server that cannot
    /// parse an envelope drops it without a word, so without that guard a
    /// misconfiguration and an unreachable host look identical. The setting
    /// survives for the next transition.
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
        let text =
            std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
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
