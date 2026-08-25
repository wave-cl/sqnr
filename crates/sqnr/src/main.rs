//! sqnr — the sQUIC signer CLI.
//!
//! Signs admin transactions against a sqex-style HTTP/3 server. Authority is the
//! Ed25519 signature on each command, produced by one of two backends: an
//! encrypted software identity in `~/.sqnr/identity`, or a YubiKey (`--yubikey`).
//! The passphrase / PIN / touch are always entered by the operator — the CLI
//! reads them at the terminal and never stores them.

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use sqnr::{Backend, Card, Client, config::Config, flow, identity};
use sqnr_core::{Action, PubKey};

#[derive(Parser)]
#[command(
    name = "sqnr",
    version,
    about = "The sQUIC signer — sign admin transactions with a YubiKey or an encrypted local identity"
)]
struct Cli {
    /// Server address, host:port (overrides ~/.sqnr/config).
    #[arg(long, global = true)]
    server: Option<String>,

    /// Server's pinned Ed25519 public key, base58 (overrides ~/.sqnr/config).
    #[arg(long = "server-key", global = true)]
    server_key: Option<String>,

    /// Sign with a YubiKey (OpenPGP Authentication key) instead of a file identity.
    #[arg(long, global = true)]
    yubikey: bool,

    /// Software identity file (default ~/.sqnr/identity).
    #[arg(short = 'i', long, global = true)]
    identity: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a new software identity (encrypted by default; prompts for a passphrase).
    Keygen {
        /// Where to write the identity (default ~/.sqnr/identity).
        #[arg(short = 'f', long)]
        file: Option<PathBuf>,
        /// Store the key unencrypted, with no passphrase, so it can sign
        /// unattended (e.g. from automation). The seed sits in the file (0600).
        #[arg(long)]
        plaintext: bool,
    },
    /// Print the admin Ed25519 public key (base58) for the selected backend.
    Pubkey,
    /// Show server status (public; no signing).
    Status,
    /// Manage the server's connection whitelist.
    Whitelist {
        #[command(subcommand)]
        action: WhitelistCmd,
    },
    /// Read recent audit entries.
    Audit {
        /// Number of entries to show.
        #[arg(short = 'n', long, default_value_t = 50)]
        count: u32,
    },
    /// Re-read the server's admin list from its config file.
    ReloadAdmins,
}

#[derive(Subcommand)]
enum WhitelistCmd {
    /// List the whitelist (enabled flag + keys).
    List,
    /// Enforce the whitelist on protected endpoints.
    Enable,
    /// Stop enforcing the whitelist.
    Disable,
    /// Add a peer's base58 key.
    Add { key: String },
    /// Remove a peer's base58 key.
    Remove { key: String },
}

#[tokio::main]
async fn main() {
    if let Err(e) = run(Cli::parse()).await {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<(), String> {
    let cfg = Config::load();
    match &cli.cmd {
        Cmd::Keygen { file, plaintext } => keygen(&cli, &cfg, file.clone(), *plaintext),
        Cmd::Pubkey => pubkey(&cli, &cfg).await,
        Cmd::Status => status(&cli, &cfg).await,
        Cmd::Whitelist { action } => whitelist(&cli, &cfg, action).await,
        Cmd::Audit { count } => audit(&cli, &cfg, *count).await,
        Cmd::ReloadAdmins => {
            let v = signed(&cli, &cfg, Action::ReloadAdmins).await?;
            println!("admins reloaded: {v}");
            Ok(())
        }
    }
}

// ---- key management (no networking) ------------------------------------------

fn keygen(cli: &Cli, cfg: &Config, file: Option<PathBuf>, plaintext: bool) -> Result<(), String> {
    let path = match file {
        Some(p) => p,
        None => identity_path(cli, cfg)?,
    };
    let public = if plaintext {
        identity::generate(&path, None)?
    } else {
        let pass = rpassword::prompt_password("New passphrase: ").map_err(|e| e.to_string())?;
        if pass.len() < 8 {
            return Err("passphrase must be at least 8 characters".into());
        }
        let confirm =
            rpassword::prompt_password("Confirm passphrase: ").map_err(|e| e.to_string())?;
        if pass != confirm {
            return Err("passphrases do not match".into());
        }
        identity::generate(&path, Some(&pass))?
    };
    println!("created {}", path.display());
    if plaintext {
        println!("WARNING: this key is UNENCRYPTED (no passphrase); protect the file.");
    }
    println!("public key: {public}");
    println!("\nAdd this key to the server's `admins` list to authorize it.");
    Ok(())
}

async fn pubkey(cli: &Cli, cfg: &Config) -> Result<(), String> {
    let public = if cli.yubikey {
        let card = Card::spawn();
        PubKey::new(card.pubkey().await?)
    } else {
        identity::read_public(&identity_path(cli, cfg)?)?
    };
    println!("{public}");
    Ok(())
}

// ---- server commands ---------------------------------------------------------

async fn status(cli: &Cli, cfg: &Config) -> Result<(), String> {
    let (mut client, _server) = connect(cli, cfg).await?;
    let (code, body) = client.get("/status").await?;
    if code != 200 {
        return Err(format!("status failed ({code})"));
    }
    let v: serde_json::Value = serde_json::from_slice(&body).map_err(|e| e.to_string())?;
    println!(
        "server {} · up {}s · whitelist {} ({} keys)",
        v["version"].as_str().unwrap_or("?"),
        v["uptime_secs"].as_u64().unwrap_or(0),
        if v["whitelist_enabled"].as_bool().unwrap_or(false) {
            "on"
        } else {
            "off"
        },
        v["whitelist_count"].as_u64().unwrap_or(0),
    );
    Ok(())
}

async fn whitelist(cli: &Cli, cfg: &Config, action: &WhitelistCmd) -> Result<(), String> {
    let act = match action {
        WhitelistCmd::List => Action::WhitelistList,
        WhitelistCmd::Enable => Action::WhitelistEnable,
        WhitelistCmd::Disable => Action::WhitelistDisable,
        WhitelistCmd::Add { key } => Action::WhitelistAdd(parse_key(key)?),
        WhitelistCmd::Remove { key } => Action::WhitelistRemove(parse_key(key)?),
    };
    let v = signed(cli, cfg, act).await?;
    match action {
        WhitelistCmd::List => {
            let enabled = v["enabled"].as_bool().unwrap_or(false);
            let keys = v["keys"].as_array().cloned().unwrap_or_default();
            println!(
                "whitelist {} ({} keys)",
                if enabled { "enabled" } else { "disabled" },
                keys.len()
            );
            for k in keys {
                if let Some(s) = k.as_str() {
                    println!("  {s}");
                }
            }
        }
        _ => println!("ok: {v}"),
    }
    Ok(())
}

async fn audit(cli: &Cli, cfg: &Config, count: u32) -> Result<(), String> {
    let v = signed(cli, cfg, Action::AuditTail(count)).await?;
    let entries = v["entries"].as_array().cloned().unwrap_or_default();
    if entries.is_empty() {
        println!("(no audit entries)");
    }
    for e in entries {
        let time = e["time"].as_u64().unwrap_or(0);
        let admin = e["admin"].as_str().unwrap_or("?");
        let action = e["action"].as_str().unwrap_or("?");
        let target = e["target"].as_str().map(|t| format!(" {t}")).unwrap_or_default();
        let short: String = admin.chars().take(8).collect();
        println!("[{time}] {short}… {action}{target}");
    }
    Ok(())
}

/// Run one signed admin action end to end: connect, resolve the signer, and
/// execute the challenge→sign→POST transaction.
async fn signed(cli: &Cli, cfg: &Config, action: Action) -> Result<serde_json::Value, String> {
    let (mut client, server) = connect(cli, cfg).await?;
    let backend = signing_backend(cli, cfg).await?;
    let on_touch = || eprintln!("👆  Touch your YubiKey to sign…");
    flow::run_once(&mut client, &backend, server, action, &on_touch).await
}

// ---- resolution helpers ------------------------------------------------------

async fn connect(cli: &Cli, cfg: &Config) -> Result<(Client, PubKey), String> {
    let addr = cli
        .server
        .clone()
        .or_else(|| cfg.server.clone())
        .ok_or_else(|| "no server address (pass --server or set it in ~/.sqnr/config)".to_string())?;
    let key = cli
        .server_key
        .clone()
        .or_else(|| cfg.server_key.clone())
        .ok_or_else(|| "no server key (pass --server-key or set it in ~/.sqnr/config)".to_string())?;
    let socket: SocketAddr = addr
        .parse()
        .map_err(|_| format!("bad server address {addr:?} (use host:port)"))?;
    let server: PubKey = key.trim().parse().map_err(|e| format!("bad server key: {e}"))?;
    let client = Client::connect(socket, server.as_bytes()).await?;
    Ok((client, server))
}

/// Build a signing backend, prompting the operator for the passphrase (software)
/// or PIN (YubiKey). One prompt per invocation.
async fn signing_backend(cli: &Cli, cfg: &Config) -> Result<Backend, String> {
    if cli.yubikey {
        let card = Card::spawn();
        let public = PubKey::new(card.pubkey().await?);
        let pin = rpassword::prompt_password("YubiKey user PIN: ").map_err(|e| e.to_string())?;
        card.unlock(pin).await?;
        Ok(Backend::yubikey(card, public))
    } else {
        let path = identity_path(cli, cfg)?;
        if !path.exists() {
            return Err(format!(
                "no identity at {} — run `sqnr keygen` first",
                path.display()
            ));
        }
        // A plaintext identity signs with no prompt — the unattended path.
        if identity::is_encrypted(&path)? {
            let pass = rpassword::prompt_password(format!("Passphrase for {}: ", path.display()))
                .map_err(|e| e.to_string())?;
            Ok(Backend::software(identity::load(&path, Some(&pass))?))
        } else {
            Ok(Backend::software(identity::load(&path, None)?))
        }
    }
}

fn identity_path(cli: &Cli, cfg: &Config) -> Result<PathBuf, String> {
    if let Some(p) = &cli.identity {
        return Ok(p.clone());
    }
    if let Some(p) = &cfg.identity {
        return Ok(p.clone());
    }
    identity::default_identity_path()
}

fn parse_key(s: &str) -> Result<PubKey, String> {
    s.trim().parse().map_err(|e| format!("bad key {s:?}: {e}"))
}
