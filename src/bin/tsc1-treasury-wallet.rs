//! Separate encrypted TSC-1 treasury wallet prototype. Not audited.
//! Never use this research software with real funds.

use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

use argon2::Argon2;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"TSC1WLT1";
const WALLET_LEN: usize = 96;

fn wallet_path() -> Result<PathBuf, &'static str> {
    let app_data = env::var_os("APPDATA").ok_or("Windows APPDATA path unavailable")?;
    Ok(PathBuf::from(app_data).join("TSC1").join("treasury.tsc1"))
}

fn address_path() -> Result<PathBuf, &'static str> {
    let app_data = env::var_os("APPDATA").ok_or("Windows APPDATA path unavailable")?;
    Ok(PathBuf::from(app_data)
        .join("TSC1")
        .join("treasury-address.txt"))
}

fn public_scalar(seed: &[u8; 32], role: &'static [u8]) -> Scalar {
    let mut hash = Sha512::new();
    hash.update(b"TSC-1:wallet-key:v1");
    hash.update(role);
    hash.update(seed);
    Scalar::from_hash(hash)
}

fn address_from_seed(seed: &[u8; 32]) -> String {
    let mut public = [0u8; 64];
    public[..32].copy_from_slice(
        &(public_scalar(seed, b"view") * RISTRETTO_BASEPOINT_POINT)
            .compress()
            .to_bytes(),
    );
    public[32..].copy_from_slice(
        &(public_scalar(seed, b"spend") * RISTRETTO_BASEPOINT_POINT)
            .compress()
            .to_bytes(),
    );
    let checksum = Sha256::digest([b"TSC1-address-v1".as_slice(), &public].concat());
    format!(
        "tsc1_{}{}",
        hex::encode(public),
        hex::encode(&checksum[..4])
    )
}

fn derive_key(password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, &'static str> {
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut *key)
        .map_err(|_| "password derivation failed")?;
    Ok(key)
}

fn encrypt_seed(
    seed: &[u8; 32],
    password: &str,
    salt: &[u8; 16],
    nonce: &[u8; 24],
) -> Result<Vec<u8>, &'static str> {
    let key = derive_key(password, salt)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key[..]));
    let encrypted = cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: seed,
                aad: MAGIC,
            },
        )
        .map_err(|_| "wallet encryption failed")?;
    let mut file = Vec::with_capacity(WALLET_LEN);
    file.extend_from_slice(MAGIC);
    file.extend_from_slice(salt);
    file.extend_from_slice(nonce);
    file.extend_from_slice(&encrypted);
    Ok(file)
}

fn decrypt_seed(bytes: &[u8], password: &str) -> Result<Zeroizing<[u8; 32]>, &'static str> {
    if bytes.len() != WALLET_LEN || &bytes[..8] != MAGIC {
        return Err("invalid treasury wallet file");
    }
    let key = derive_key(password, &bytes[8..24])?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key[..]));
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&bytes[24..48]),
            Payload {
                msg: &bytes[48..],
                aad: MAGIC,
            },
        )
        .map_err(|_| "wrong password or damaged treasury wallet")?;
    let plaintext = Zeroizing::new(plaintext);
    if plaintext.len() != 32 {
        return Err("invalid treasury wallet file");
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(&plaintext);
    Ok(seed)
}

fn create() -> Result<(), Box<dyn std::error::Error>> {
    let path = wallet_path()?;
    let public_path = address_path()?;
    if path.exists() || public_path.exists() {
        return Err("treasury wallet or address already exists; refusing to overwrite".into());
    }
    let password = Zeroizing::new(rpassword::prompt_password(
        "Choose a NEW treasury password (12+ characters): ",
    )?);
    if password.chars().count() < 12 {
        return Err("password must contain at least 12 characters".into());
    }
    let repeat = Zeroizing::new(rpassword::prompt_password("Repeat treasury password: ")?);
    if *password != *repeat {
        return Err("passwords do not match".into());
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(&mut *seed)?;
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 24];
    getrandom::getrandom(&mut salt)?;
    getrandom::getrandom(&mut nonce)?;
    let encrypted = encrypt_seed(&seed, &password, &salt, &nonce)?;
    let public_address = address_from_seed(&seed);
    fs::create_dir_all(path.parent().ok_or("invalid treasury wallet path")?)?;
    let mut wallet_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?;
    wallet_file.write_all(&encrypted)?;
    wallet_file.sync_all()?;
    let mut address_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&public_path)?;
    address_file.write_all(public_address.as_bytes())?;
    address_file.write_all(b"\n")?;
    address_file.sync_all()?;
    println!("Treasury wallet created at {}", path.display());
    println!("Public treasury address: {public_address}");
    println!("Public address saved at {}", public_path.display());
    println!("Back up the encrypted wallet and password separately.");
    println!("Research software only; no real TNB can be received yet.");
    Ok(())
}

fn show_address() -> Result<(), Box<dyn std::error::Error>> {
    let path = wallet_path()?;
    if fs::metadata(&path)?.len() != WALLET_LEN as u64 {
        return Err("invalid treasury wallet file".into());
    }
    let encrypted = fs::read(path)?;
    let password = Zeroizing::new(rpassword::prompt_password("Treasury password: ")?);
    let seed = decrypt_seed(&encrypted, &password)?;
    println!("Public treasury address: {}", address_from_seed(&seed));
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    match env::args().nth(1).as_deref() {
        Some("create") => create(),
        Some("address") => show_address(),
        _ => {
            println!("TENEBRA treasury wallet prototype. Commands: create, address");
            println!("No wallet is created without the explicit 'create' command.");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn treasury_file_round_trip_and_wrong_password() {
        let seed = [7u8; 32];
        let file = encrypt_seed(&seed, "synthetic-test-password", &[1; 16], &[2; 24]).unwrap();
        assert_eq!(file.len(), WALLET_LEN);
        let restored = decrypt_seed(&file, "synthetic-test-password").unwrap();
        assert_eq!(address_from_seed(&seed), address_from_seed(&restored));
        assert!(decrypt_seed(&file, "wrong-password").is_err());
    }

    #[test]
    fn treasury_file_tampering_is_rejected() {
        let mut file =
            encrypt_seed(&[7u8; 32], "synthetic-test-password", &[1; 16], &[2; 24]).unwrap();
        file[WALLET_LEN - 1] ^= 1;
        assert!(decrypt_seed(&file, "synthetic-test-password").is_err());
    }
}
