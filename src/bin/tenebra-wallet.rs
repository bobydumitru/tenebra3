//! Experimental TENEBRA Wallet UI with separate personal and treasury accounts.
//! Not audited; never use this research software with real funds.

use std::{env, fs, path::PathBuf};

use argon2::Argon2;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, scalar::Scalar};
use eframe::egui;
use sha2::{Digest, Sha256, Sha512};
#[cfg(test)]
use tenebra::Address;
use tenebra::WalletSecrets;
use tenebra::network::pinned_genesis;
use tenebra::tsc1_chain_v3::load_blocks;
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 8] = b"TSC1WLT1";
const WALLET_LEN: usize = 96;

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum Account {
    #[default]
    Personal,
    Treasury,
}

impl Account {
    fn label(self) -> &'static str {
        match self {
            Self::Personal => "Personal",
            Self::Treasury => "Treasury",
        }
    }

    fn file_name(self) -> &'static str {
        match self {
            Self::Personal => "wallet.tsc1",
            Self::Treasury => "treasury.tsc1",
        }
    }
}

fn wallet_path(account: Account) -> Result<PathBuf, &'static str> {
    let app_data = env::var_os("APPDATA").ok_or("Wallet location is unavailable")?;
    Ok(PathBuf::from(app_data)
        .join("TSC1")
        .join(account.file_name()))
}

fn v3_blocks_dir() -> PathBuf {
    tenebra::network::blocks_dir()
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

#[allow(dead_code)]
fn unlock_address(bytes: &[u8], password: &str) -> Result<String, &'static str> {
    unlock_wallet(bytes, password).map(|(address, _)| address)
}

fn unlock_wallet(bytes: &[u8], password: &str) -> Result<(String, WalletSecrets), &'static str> {
    if bytes.len() != WALLET_LEN || &bytes[..MAGIC.len()] != MAGIC {
        return Err("Invalid wallet file");
    }
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::default()
        .hash_password_into(password.as_bytes(), &bytes[8..24], &mut *key)
        .map_err(|_| "Password derivation failed")?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key[..]));
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&bytes[24..48]),
            Payload {
                msg: &bytes[48..],
                aad: MAGIC,
            },
        )
        .map_err(|_| "Wrong password or damaged wallet file")?;
    let plaintext = Zeroizing::new(plaintext);
    if plaintext.len() != 32 {
        return Err("Invalid wallet file");
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(&plaintext);
    Ok((address_from_seed(&seed), WalletSecrets::from_seed(&seed)))
}

fn read_wallet_state(
    account: Account,
    password: &str,
) -> Result<(String, WalletSecrets, u64, u64), &'static str> {
    let path = wallet_path(account)?;
    let length = fs::metadata(&path)
        .map_err(|_| "Selected wallet file not found")?
        .len();
    if length != WALLET_LEN as u64 {
        return Err("Invalid wallet file");
    }
    let bytes = fs::read(path).map_err(|_| "Wallet file could not be read")?;
    let (address, wallet) = unlock_wallet(&bytes, password)?;
    let genesis = pinned_genesis().map_err(|_| "V3 genesis could not be loaded")?;
    let chain = load_blocks(&v3_blocks_dir(), genesis).map_err(|_| "V3 chain validation failed")?;
    let balance = chain
        .wallet_balance_nox(&wallet)
        .map_err(|_| "V3 balance calculation failed")?;
    Ok((address, wallet, balance, chain.height()))
}

#[derive(Default)]
struct TenebraWallet {
    account: Account,
    password: String,
    address: Option<String>,
    wallet: Option<WalletSecrets>,
    balance_nox: Option<u64>,
    chain_height: Option<u64>,
    message: Option<String>,
}

impl TenebraWallet {
    fn select_account(&mut self, selected: Account) {
        if self.account != selected {
            self.password.zeroize();
            self.password.clear();
            self.address = None;
            self.wallet = None;
            self.balance_nox = None;
            self.chain_height = None;
            self.message = None;
            self.account = selected;
        }
    }
}

impl Drop for TenebraWallet {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

impl eframe::App for TenebraWallet {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(egui::Color32::from_rgb(12, 12, 15)))
            .show(ui, |ui| {
                ui.vertical_centered(|ui| {
                    ui.add_space(12.0);
                    ui.label(
                        egui::RichText::new("TSC-1 NETWORK  Ãƒâ€šÃ‚Â·  EXPERIMENTAL")
                            .color(egui::Color32::from_rgb(210, 177, 104)),
                    );
                    ui.add_space(7.0);
                    ui.add(
                        egui::Image::new(egui::include_image!("../../assets/tnb-emblem-v2.png"))
                            .fit_to_exact_size(egui::vec2(180.0, 180.0)),
                    );
                    ui.heading("TENEBRA Wallet");
                    ui.label("TNB  Ãƒâ€šÃ‚Â·  Private by design");
                    ui.add_space(10.0);
                    let mut selected = self.account;
                    egui::ComboBox::from_label("Wallet")
                        .selected_text(selected.label())
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut selected, Account::Personal, "Personal");
                            ui.selectable_value(&mut selected, Account::Treasury, "Treasury");
                        });
                    self.select_account(selected);
                    ui.add_space(10.0);
                    egui::Frame::group(ui.style()).show(ui, |ui| {
                        ui.set_min_width(390.0);
                        ui.label(format!(
                            "{} LOCAL BALANCE",
                            tenebra::network::NAME.to_uppercase()
                        ));
                        if let Some(balance) = self.balance_nox {
                            ui.heading(format!(
                                "{}.{:09} TNB",
                                balance / 1_000_000_000,
                                balance % 1_000_000_000
                            ));
                            ui.small(format!(
                                "Verified through V3 block {}. Transfers are disabled.",
                                self.chain_height.unwrap_or(0)
                            ));
                        } else {
                            ui.heading("Unavailable");
                            ui.small("Unlock to scan the validated local chain.");
                        }
                    });
                    ui.add_space(10.0);
                    egui::Frame::group(ui.style()).show(ui, |ui| {
                        ui.set_min_width(390.0);
                        ui.label(format!(
                            "{} WALLET ADDRESS",
                            self.account.label().to_uppercase()
                        ));
                        if let Some(address) = &self.address {
                            for chunk in address.as_bytes().chunks(45) {
                                ui.monospace(std::str::from_utf8(chunk).expect("ASCII address"));
                            }
                            if ui.button("Copy address").clicked() {
                                ui.ctx().copy_text(address.clone());
                                self.message = Some("Public address copied".into());
                            }
                        } else {
                            ui.label("Unlock the selected wallet to view its public address.");
                        }
                    });
                    if self.address.is_none() {
                        ui.add_space(12.0);
                        ui.label(format!("{} wallet password", self.account.label()));
                        ui.add(
                            egui::TextEdit::singleline(&mut self.password)
                                .password(true)
                                .desired_width(300.0),
                        );
                        if ui.button("Unlock address").clicked() {
                            let password = Zeroizing::new(std::mem::take(&mut self.password));
                            match read_wallet_state(self.account, &password) {
                                Ok((address, wallet, balance, height)) => {
                                    self.address = Some(address);
                                    self.wallet = Some(wallet);
                                    self.balance_nox = Some(balance);
                                    self.chain_height = Some(height);
                                    self.message = Some("Local devnet rewards scanned".into());
                                }
                                Err(error) => self.message = Some(error.into()),
                            }
                        }
                    }
                    if let Some(message) = &self.message {
                        ui.label(message);
                    }
                    ui.add_space(12.0);
                    ui.horizontal(|ui| {
                        ui.add_enabled(false, egui::Button::new("Send TNB"));
                        ui.add_enabled(false, egui::Button::new("Mine devnet block"));
                    });
                    ui.add_space(10.0);
                    ui.small("Experimental software. Do not use with real funds.");
                });
            });
    }
}

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([520.0, 690.0]),
        ..Default::default()
    };
    eframe::run_native(
        "TENEBRA Wallet",
        options,
        Box::new(|cc| {
            egui_extras::install_image_loaders(&cc.egui_ctx);
            Ok(Box::new(TenebraWallet::default()))
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accounts_use_different_encrypted_files_and_switch_clears_state() {
        assert_ne!(Account::Personal.file_name(), Account::Treasury.file_name());
        let mut app = TenebraWallet::default();
        app.password = "private-test-password".into();
        app.address = Some("tsc1_test".into());
        app.message = Some("old message".into());
        app.select_account(Account::Treasury);
        assert!(app.password.is_empty());
        assert!(app.address.is_none());
        assert!(app.message.is_none());
    }

    #[test]
    fn synthetic_wallet_unlocks_and_rejects_wrong_password() {
        let seed = [7u8; 32];
        let salt = [1u8; 16];
        let nonce = [2u8; 24];
        let mut key = [0u8; 32];
        Argon2::default()
            .hash_password_into(b"synthetic-password", &salt, &mut key)
            .unwrap();
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
        let encrypted = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &seed,
                    aad: MAGIC,
                },
            )
            .unwrap();
        key.zeroize();
        let mut file = Vec::new();
        file.extend_from_slice(MAGIC);
        file.extend_from_slice(&salt);
        file.extend_from_slice(&nonce);
        file.extend_from_slice(&encrypted);
        assert_eq!(
            unlock_address(&file, "synthetic-password"),
            Ok(address_from_seed(&seed))
        );
        let (_, wallet) = unlock_wallet(&file, "synthetic-password").unwrap();
        assert_eq!(
            wallet.address(),
            Address::parse(&address_from_seed(&seed)).unwrap()
        );
        assert!(unlock_address(&file, "wrong-password").is_err());
    }
}
