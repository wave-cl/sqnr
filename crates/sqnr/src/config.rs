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
}

impl Config {
    /// Load `~/.sqnr/config`, or an empty config if it does not exist.
    pub fn load() -> Config {
        match dirs::home_dir().map(|h| h.join(".sqnr").join("config")) {
            Some(path) if path.exists() => Config::from_file(&path).unwrap_or_default(),
            _ => Config::default(),
        }
    }

    pub fn from_file(path: &Path) -> Result<Config, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        toml::from_str(&text).map_err(|e| format!("parse {}: {e}", path.display()))
    }
}
