//! Offline TSC-1 wallet prototype. Not audited; never use with real funds.

use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

use argon2::Argon2;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
#[cfg(test)]
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha256, Sha512};
use tenebra::Address;
#[cfg(test)]
use tenebra::OneTimeOutput;
use tenebra::WalletSecrets;
use tenebra::network::pinned_genesis;
use tenebra::tsc1_chain_v3::load_blocks;
use tenebra::tsc1_wallet_tx_v3::create_signed_transfer;
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"TSC1WLT1";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const CIPHERTEXT_LEN: usize = 48; // 32-byte seed + 16-byte authentication tag
const FILE_LEN: usize = MAGIC.len() + SALT_LEN + NONCE_LEN + CIPHERTEXT_LEN;

struct WalletSeed(Zeroizing<[u8; 32]>);

impl WalletSeed {
    fn from_seed_bytes(seed: &[u8; 32]) -> Self {
        Self(Zeroizing::new(*seed))
    }

    fn from_hex(text: &str) -> Result<Self, String> {
        let trimmed = text.trim();
        let cleaned = trimmed.strip_prefix("0x").unwrap_or(trimmed);
        let bytes = hex::decode(cleaned)
            .map_err(|error| format!("invalid seed hex: {error}"))?;
        if bytes.len() != 32 {
            return Err("seed must decode to exactly 32 bytes".into());
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes);
        Ok(Self::from_seed_bytes(&seed))
    }

    fn generate() -> Result<Self, String> {
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(&mut *seed).map_err(|error| error.to_string())?;
        Ok(Self(seed))
    }

    fn scalar(&self, role: &'static [u8]) -> Scalar {
        let mut hash = Sha512::new();
        hash.update(b"TSC-1:wallet-key:v1");
        hash.update(role);
        hash.update(&self.0[..]);
        Scalar::from_hash(hash)
    }

    fn address(&self) -> Address {
        Address {
            view: (self.scalar(b"view") * RISTRETTO_BASEPOINT_POINT)
                .compress()
                .to_bytes(),
            spend: (self.scalar(b"spend") * RISTRETTO_BASEPOINT_POINT)
                .compress()
                .to_bytes(),
        }
    }

    #[cfg(test)]
    fn owns_output(&self, output: &OneTimeOutput, index: u64) -> bool {
        let Some(ephemeral) = CompressedRistretto(output.ephemeral).decompress() else {
            return false;
        };
        let mut hash = Sha512::new();
        hash.update(b"TENEBRA:one-time-output:v1");
        hash.update((self.scalar(b"view") * ephemeral).compress().to_bytes());
        hash.update(index.to_le_bytes());
        let tweak = Scalar::from_hash(hash);
        let expected = ((self.scalar(b"spend") + tweak) * RISTRETTO_BASEPOINT_POINT)
            .compress()
            .to_bytes();
        expected == output.destination
    }
}

fn address_text(address: Address) -> String {
    let mut public = [0u8; 64];
    public[..32].copy_from_slice(&address.view);
    public[32..].copy_from_slice(&address.spend);
    let checksum = Sha256::digest([b"TSC1-address-v1".as_slice(), &public].concat());
    format!(
        "tsc1_{}{}",
        hex::encode(public),
        hex::encode(&checksum[..4])
    )
}

#[cfg(test)]
fn parse_address(text: &str) -> Result<Address, &'static str> {
    let encoded = text.strip_prefix("tsc1_").ok_or("wrong address prefix")?;
    if encoded.len() != 136 {
        return Err("wrong address length");
    }
    let bytes = hex::decode(encoded).map_err(|_| "invalid address characters")?;
    let public = &bytes[..64];
    let checksum = Sha256::digest([b"TSC1-address-v1".as_slice(), public].concat());
    if bytes[64..] != checksum[..4] {
        return Err("invalid address checksum");
    }
    let mut view = [0u8; 32];
    let mut spend = [0u8; 32];
    view.copy_from_slice(&public[..32]);
    spend.copy_from_slice(&public[32..]);
    if CompressedRistretto(view).decompress().is_none()
        || CompressedRistretto(spend).decompress().is_none()
    {
        return Err("invalid public key");
    }
    Ok(Address { view, spend })
}

fn derive_encryption_key(
    password: &str,
    salt: &[u8; SALT_LEN],
) -> Result<Zeroizing<[u8; 32]>, String> {
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut *key)
        .map_err(|error| format!("password derivation failed: {error}"))?;
    Ok(key)
}

fn encrypt_seed(
    seed: &WalletSeed,
    password: &str,
    salt: &[u8; SALT_LEN],
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>, String> {
    let key = derive_encryption_key(password, salt)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key[..]));
    let encrypted = cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: &seed.0[..],
                aad: MAGIC,
            },
        )
        .map_err(|_| "wallet encryption failed")?;
    let mut file = Vec::with_capacity(FILE_LEN);
    file.extend_from_slice(MAGIC);
    file.extend_from_slice(salt);
    file.extend_from_slice(nonce);
    file.extend_from_slice(&encrypted);
    Ok(file)
}

fn decrypt_seed(bytes: &[u8], password: &str) -> Result<WalletSeed, String> {
    if bytes.len() != FILE_LEN || &bytes[..MAGIC.len()] != MAGIC {
        return Err("invalid wallet file".into());
    }
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&bytes[8..24]);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&bytes[24..48]);
    let key = derive_encryption_key(password, &salt)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key[..]));
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &bytes[48..],
                aad: MAGIC,
            },
        )
        .map_err(|_| "wrong password or damaged wallet file")?;
    if plaintext.len() != 32 {
        return Err("invalid decrypted seed".into());
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(&plaintext);
    Ok(WalletSeed(seed))
}

fn wallet_filename(account: &str) -> Result<&'static str, String> {
    match account {
        "founder" => Ok("wallet.tsc1"),
        "treasury" => Ok("treasury.tsc1"),
        _ => Err("TSC1_WALLET_ACCOUNT must be founder or treasury".into()),
    }
}

fn wallet_path() -> Result<PathBuf, String> {
    let app_data = env::var_os("APPDATA").ok_or("Windows APPDATA path unavailable")?;
    let account = match env::var("TSC1_WALLET_ACCOUNT") {
        Ok(value) => value,
        Err(env::VarError::NotPresent) => "founder".to_owned(),
        Err(_) => return Err("invalid wallet account encoding".into()),
    };
    Ok(PathBuf::from(app_data)
        .join("TSC1")
        .join(wallet_filename(&account)?))
}

fn parse_seed_hex(text: &str) -> Result<WalletSeed, String> {
    WalletSeed::from_hex(text)
}

fn restore_wallet_from_seed(seed_hex: &str, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    let seed = parse_seed_hex(seed_hex)?;
    let path = wallet_path()?;
    if path.exists() {
        return Err("wallet already exists; refusing to overwrite it".into());
    }
    let password = Zeroizing::new(password.to_owned());
    if password.chars().count() < 12 {
        return Err("password must have at least 12 characters".into());
    }
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut salt)?;
    getrandom::getrandom(&mut nonce)?;
    let encrypted = encrypt_seed(&seed, &password, &salt, &nonce)?;
    fs::create_dir_all(path.parent().ok_or("invalid wallet path")?)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?;
    file.write_all(&encrypted)?;
    file.sync_all()?;
    println!("Wallet restored at {}", path.display());
    println!("Public address: {}", address_text(seed.address()));
    println!("Restore complete. Keep the wallet file and password private.");
    Ok(())
}

fn create_wallet() -> Result<(), Box<dyn std::error::Error>> {
    let path = wallet_path()?;
    if path.exists() {
        return Err("wallet already exists; refusing to overwrite it".into());
    }
    let password = Zeroizing::new(rpassword::prompt_password(
        "Choose a wallet password (12+ characters): ",
    )?);
    if password.chars().count() < 12 {
        return Err("password must have at least 12 characters".into());
    }
    let repeat = Zeroizing::new(rpassword::prompt_password("Repeat password: ")?);
    if *password != *repeat {
        return Err("passwords do not match".into());
    }
    let seed = WalletSeed::generate()?;
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut salt)?;
    getrandom::getrandom(&mut nonce)?;
    let encrypted = encrypt_seed(&seed, &password, &salt, &nonce)?;
    fs::create_dir_all(path.parent().ok_or("invalid wallet path")?)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?;
    file.write_all(&encrypted)?;
    file.sync_all()?;
    println!("Wallet created at {}", path.display());
    println!("Public address: {}", address_text(seed.address()));
    println!("Back up the encrypted wallet file and remember the password separately.");
    println!("Research software only: do not use with real funds yet.");
    Ok(())
}

fn show_address() -> Result<(), Box<dyn std::error::Error>> {
    let path = wallet_path()?;
    if fs::metadata(&path)?.len() != FILE_LEN as u64 {
        return Err("invalid wallet file length".into());
    }
    let encrypted = fs::read(&path)?;
    let password = Zeroizing::new(rpassword::prompt_password("Wallet password: ")?);
    let seed = decrypt_seed(&encrypted, &password)?;
    println!("Public address: {}", address_text(seed.address()));
    Ok(())
}

fn sign_v3(
    recipient_text: &str,
    amount_text: &str,
    fee_text: &str,
    output_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let recipient = Address::parse(recipient_text)?;
    let amount_nox: u64 = amount_text.parse()?;
    let fee_nox: u64 = fee_text.parse()?;
    let wallet_file = wallet_path()?;
    println!(
        "network={} wallet={} recipient={} amount_nox={amount_nox} fee_nox={fee_nox}",
        tenebra::network::NAME,
        wallet_file.display(),
        recipient_text
    );
    if fs::metadata(&wallet_file)?.len() != FILE_LEN as u64 {
        return Err("invalid wallet file length".into());
    }
    let encrypted = fs::read(&wallet_file)?;
    let password = Zeroizing::new(rpassword::prompt_password("Wallet password: ")?);
    let seed = decrypt_seed(&encrypted, &password)?;
    let wallet = WalletSecrets::from_seed(&seed.0);
    let blocks_dir = tenebra::network::blocks_dir();
    let chain = load_blocks(&blocks_dir, pinned_genesis()?)?;
    let transaction = create_signed_transfer(&chain, &wallet, &recipient, amount_nox, fee_nox)?;
    let encoded = transaction.encode()?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output_path)?;
    file.write_all(&encoded)?;
    file.sync_all()?;
    println!("signed_txid={}", hex::encode(transaction.txid()?));
    println!("transaction_file={output_path}");
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = env::args().skip(1).collect();
    match args.as_slice() {
        [command] if command == "create" => create_wallet(),
        [command] if command == "address" => show_address(),
        [command, seed_hex] if command == "restore-seed" || command == "import-seed" => {
            let password = Zeroizing::new(rpassword::prompt_password("Choose a wallet password (12+ characters): ")?);
            if password.chars().count() < 12 {
                return Err("password must have at least 12 characters".into());
            }
            let repeat = Zeroizing::new(rpassword::prompt_password("Repeat password: ")?);
            if *password != *repeat {
                return Err("passwords do not match".into());
            }
            restore_wallet_from_seed(seed_hex, &password)
        }
        [command, seed_hex, password] if command == "restore-seed" || command == "import-seed" => {
            restore_wallet_from_seed(seed_hex, password)
        }
        [command, recipient, amount, fee, path] if command == "sign-v3" => {
            sign_v3(recipient, amount, fee, path)
        }
        _ => {
            println!(
                "TSC-1 wallet prototype. Commands: create, address, restore-seed <seed_hex> [password], import-seed <seed_hex> [password], sign-v3 <recipient_address> <amount_nox> <fee_nox> <output.bin>"
            );
            println!("No wallet is created without the explicit 'create' or 'restore-seed' command.");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenebra::create_output;

    fn sample_seed() -> WalletSeed {
        WalletSeed(Zeroizing::new([7u8; 32]))
    }

    #[test]
    fn encrypted_wallet_restores_same_address() {
        let seed = sample_seed();
        let encrypted =
            encrypt_seed(&seed, "correct horse battery staple", &[1; 16], &[2; 24]).unwrap();
        let restored = decrypt_seed(&encrypted, "correct horse battery staple").unwrap();
        assert_eq!(seed.address(), restored.address());
        assert!(decrypt_seed(&encrypted, "wrong password").is_err());
    }

    #[test]
    fn tampered_wallet_is_rejected() {
        let mut encrypted = encrypt_seed(
            &sample_seed(),
            "correct horse battery staple",
            &[1; 16],
            &[2; 24],
        )
        .unwrap();
        encrypted[FILE_LEN - 1] ^= 1;
        assert!(decrypt_seed(&encrypted, "correct horse battery staple").is_err());
    }

    #[test]
    fn address_round_trip_and_bad_checksum() {
        let address = sample_seed().address();
        let text = address_text(address);
        assert_eq!(parse_address(&text), Ok(address));
        let mut broken = text.into_bytes();
        let last = broken.last_mut().unwrap();
        *last = if *last == b'0' { b'1' } else { b'0' };
        assert!(parse_address(&String::from_utf8(broken).unwrap()).is_err());
    }

    #[test]
    fn restored_wallet_recognizes_its_one_time_output() {
        let seed = sample_seed();
        let output = create_output(&seed.address(), 0).unwrap();
        assert!(seed.owns_output(&output, 0));
        assert!(!seed.owns_output(&output, 1));
    }

    #[test]
    fn kdf_vector_is_deterministic_and_calibrated() {
        let salt = [1u8; SALT_LEN];
        let password = "vector-password";
        let first = derive_encryption_key(password, &salt).unwrap();
        let second = derive_encryption_key(password, &salt).unwrap();
        assert_eq!(*first, *second);
        assert_ne!(*first, [0u8; 32]);

        let start = std::time::Instant::now();
        for _ in 0..3 {
            let _ = derive_encryption_key(password, &salt).unwrap();
        }
        assert!(
            start.elapsed().as_secs() < 10,
            "KDF calibration exceeded test budget"
        );
    }

    #[test]
    fn seed_hex_round_trip_restores_same_address() {
        let expected = [7u8; 32];
        let seed = parse_seed_hex(&hex::encode(expected)).unwrap();
        assert_eq!(seed.0[..], expected);
        assert_eq!(seed.address(), WalletSeed::from_seed_bytes(&expected).address());
        assert!(parse_seed_hex("zz").is_err());
    }
}

#[cfg(test)]
mod account_selection_tests {
    #[test]
    fn treasury_and_founder_use_distinct_existing_wallet_names() {
        assert_eq!(super::wallet_filename("founder").unwrap(), "wallet.tsc1");
        assert_eq!(super::wallet_filename("treasury").unwrap(), "treasury.tsc1");
        assert!(super::wallet_filename("").is_err());
        assert!(super::wallet_filename("../treasury").is_err());
    }
}
