//! The software identity: an Ed25519 admin key kept in `~/.sqnr/identity`,
//! always encrypted at rest with a passphrase (argon2id + ChaCha20-Poly1305).
//!
//! The file has three lines — a header, the base58 encrypted seed blob, and the
//! base58 public key. Storing the public key in the clear lets `sqnr pubkey`
//! report the admin identity without the passphrase; only signing needs to
//! decrypt. The encrypt/decrypt construction mirrors sqssh's key format.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use argon2::Argon2;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use ed25519_dalek::SigningKey;
use sqnr_core::{PubKey, SoftwareSigner};
use zeroize::Zeroizing;

const HEADER: &str = "SQNR-ED25519-ENCRYPTED-KEY";

/// argon2id parameters (memory KiB, iterations, parallelism). Recorded in the
/// blob so a future bump can still decrypt older files.
const ARGON_M_COST: u32 = 65536;
const ARGON_T_COST: u32 = 3;
const ARGON_P_COST: u32 = 4;

/// The `~/.sqnr` directory, created with mode 0700 if missing.
pub fn sqnr_dir() -> Result<PathBuf, String> {
    let dir = dirs::home_dir()
        .ok_or_else(|| "cannot locate home directory".to_string())?
        .join(".sqnr");
    if !dir.exists() {
        fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("chmod {}: {e}", dir.display()))?;
    }
    Ok(dir)
}

/// The default identity path, `~/.sqnr/identity`.
pub fn default_identity_path() -> Result<PathBuf, String> {
    Ok(sqnr_dir()?.join("identity"))
}

/// Generate a fresh Ed25519 identity, encrypt it under `passphrase`, and write
/// it to `path` (mode 0600). Returns the new public key.
pub fn generate(path: &Path, passphrase: &str) -> Result<PubKey, String> {
    if path.exists() {
        return Err(format!(
            "{} already exists; refusing to overwrite",
            path.display()
        ));
    }
    let key = SigningKey::generate(&mut rand_core::OsRng);
    let public = PubKey::new(key.verifying_key().to_bytes());
    write_encrypted(path, &key, &public, passphrase)?;
    Ok(public)
}

/// Read the public key from an identity file without the passphrase.
pub fn read_public(path: &Path) -> Result<PubKey, String> {
    let (_blob, public) = read_lines(path)?;
    PubKey::from_base58(&public).map_err(|e| format!("bad public key line: {e}"))
}

/// Decrypt the identity under `passphrase` and return a signer over it. The
/// stored public key is checked against the decrypted key as a tamper guard.
pub fn load(path: &Path, passphrase: &str) -> Result<SoftwareSigner, String> {
    let (blob_b58, public_b58) = read_lines(path)?;
    let key = decrypt_seed(&blob_b58, passphrase)?;
    let derived = PubKey::new(key.verifying_key().to_bytes());
    let stored = PubKey::from_base58(&public_b58).map_err(|e| format!("bad public key line: {e}"))?;
    if derived != stored {
        return Err("identity file is inconsistent (public key does not match seed)".into());
    }
    Ok(SoftwareSigner::new(key))
}

fn write_encrypted(
    path: &Path,
    key: &SigningKey,
    public: &PubKey,
    passphrase: &str,
) -> Result<(), String> {
    let blob = encrypt_seed(&key.to_bytes(), passphrase)?;
    let content = Zeroizing::new(format!("{HEADER}\n{blob}\n{}\n", public.to_base58()));
    fs::write(path, content.as_bytes()).map_err(|e| format!("write {}: {e}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("chmod {}: {e}", path.display()))?;
    Ok(())
}

fn read_lines(path: &Path) -> Result<(String, String), String> {
    let content =
        Zeroizing::new(fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?);
    let mut lines = content.lines();
    let header = lines.next().unwrap_or("").trim();
    if header != HEADER {
        return Err(format!("{}: not an sqnr identity file", path.display()));
    }
    let blob = lines
        .next()
        .ok_or_else(|| "identity file missing key data".to_string())?
        .trim()
        .to_string();
    let public = lines
        .next()
        .ok_or_else(|| "identity file missing public key".to_string())?
        .trim()
        .to_string();
    Ok((blob, public))
}

/// Encrypted-seed blob: [4 m_cost][4 t_cost][4 p_cost][16 salt][12 nonce][ct].
fn encrypt_seed(seed: &[u8; 32], passphrase: &str) -> Result<String, String> {
    use rand_core::RngCore;

    let mut salt = [0u8; 16];
    let mut nonce_bytes = [0u8; 12];
    rand_core::OsRng.fill_bytes(&mut salt);
    rand_core::OsRng.fill_bytes(&mut nonce_bytes);

    let mut derived = Zeroizing::new([0u8; 32]);
    argon2(ARGON_M_COST, ARGON_T_COST, ARGON_P_COST, passphrase, &salt, derived.as_mut())?;

    let cipher = ChaCha20Poly1305::new_from_slice(derived.as_ref())
        .map_err(|e| format!("cipher init: {e}"))?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), seed.as_ref())
        .map_err(|e| format!("encrypt: {e}"))?;

    let mut out = Vec::with_capacity(12 + 16 + 12 + ciphertext.len());
    out.extend_from_slice(&ARGON_M_COST.to_be_bytes());
    out.extend_from_slice(&ARGON_T_COST.to_be_bytes());
    out.extend_from_slice(&ARGON_P_COST.to_be_bytes());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(bs58::encode(out).into_string())
}

fn decrypt_seed(blob_b58: &str, passphrase: &str) -> Result<SigningKey, String> {
    let data = bs58::decode(blob_b58)
        .into_vec()
        .map_err(|e| format!("bad base58 in identity: {e}"))?;
    if data.len() < 40 {
        return Err("encrypted key blob too short".into());
    }
    let m_cost = u32::from_be_bytes(data[0..4].try_into().unwrap());
    let t_cost = u32::from_be_bytes(data[4..8].try_into().unwrap());
    let p_cost = u32::from_be_bytes(data[8..12].try_into().unwrap());
    let salt = &data[12..28];
    let nonce = &data[28..40];
    let ciphertext = &data[40..];

    let mut derived = Zeroizing::new([0u8; 32]);
    argon2(m_cost, t_cost, p_cost, passphrase, salt, derived.as_mut())?;

    let cipher = ChaCha20Poly1305::new_from_slice(derived.as_ref())
        .map_err(|e| format!("cipher init: {e}"))?;
    let seed = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| "decryption failed (wrong passphrase?)".to_string())?;
    if seed.len() != 32 {
        return Err("decrypted seed is not 32 bytes".into());
    }
    let mut arr = Zeroizing::new([0u8; 32]);
    arr.copy_from_slice(&seed);
    Ok(SigningKey::from_bytes(&arr))
}

fn argon2(
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    passphrase: &str,
    salt: &[u8],
    out: &mut [u8],
) -> Result<(), String> {
    let params = argon2::Params::new(m_cost, t_cost, p_cost, Some(out.len()))
        .map_err(|e| format!("argon2 params: {e}"))?;
    Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
        .hash_password_into(passphrase.as_bytes(), salt, out)
        .map_err(|e| format!("argon2 hash: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqnr_core::Signer;

    #[test]
    fn round_trip_and_public_without_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity");
        let public = generate(&path, "correct horse").unwrap();

        // Public key readable without the passphrase.
        assert_eq!(read_public(&path).unwrap(), public);

        // Load with the right passphrase, and the signer matches.
        let signer = load(&path, "correct horse").unwrap();
        assert_eq!(PubKey::new(signer.public()), public);
    }

    #[test]
    fn wrong_passphrase_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity");
        generate(&path, "right").unwrap();
        assert!(load(&path, "wrong").is_err());
    }

    #[test]
    fn file_is_0600() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity");
        generate(&path, "pw").unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn refuses_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity");
        generate(&path, "pw").unwrap();
        assert!(generate(&path, "pw").is_err());
    }
}
