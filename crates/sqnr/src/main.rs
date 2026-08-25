//! sqnr — the sQUIC signer CLI.
//!
//! This binary manages signing identities: it generates the encrypted (or
//! plaintext) software identity in `~/.sqnr` and reports public keys. It knows
//! no server commands — signing a transaction against a service is done by that
//! service's own tool (e.g. `sqex-cli`) via the `sqnr` library. The passphrase
//! and PIN are always entered by the operator; the CLI never stores them.

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use sqnr::{Card, config::Config, identity};
use sqnr_core::PubKey;

#[derive(Parser)]
#[command(
    name = "sqnr",
    version,
    about = "The sQUIC signer — manage the identities that sign admin transactions"
)]
struct Cli {
    /// Use the YubiKey (OpenPGP Authentication key) instead of a file identity.
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
    }
}

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

fn identity_path(cli: &Cli, cfg: &Config) -> Result<PathBuf, String> {
    if let Some(p) = &cli.identity {
        return Ok(p.clone());
    }
    if let Some(p) = &cfg.identity {
        return Ok(p.clone());
    }
    identity::default_identity_path()
}
