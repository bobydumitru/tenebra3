//! Experimental TENEBRA Wallet desktop app. Not audited; never use with real funds.

use std::{env, fs, path::PathBuf};

use argon2::Argon2;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, scalar::Scalar};
use eframe::egui;
use sha2::{Digest, Sha256, Sha512};
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 8] = b"TSC1WLT1";
const WALLET_LEN: usize = 96;

fn wallet_path() -> Result<PathBuf, &'static str> {
    let app_data = env::var_os("APPDATA").ok_or("Wallet location is unavailable")?;
    Ok(PathBuf::from(app_data).join("TSC1").join("wallet.tsc1"))
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

fn unlock_address(bytes: &[u8], password: &str) -> Result<String, &'static str> {
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
    Ok(address_from_seed(&seed))
}

fn read_public_address(password: &str) -> Result<String, &'static str> {
    let path = wallet_path()?;
    let length = fs::metadata(&path)
        .map_err(|_| "Wallet file not found")?
        .len();
    if length != WALLET_LEN as u64 {
        return Err("Invalid wallet file");
    }
    let bytes = fs::read(path).map_err(|_| "Wallet file could not be read")?;
    unlock_address(&bytes, password)
}

#[derive(Default)]
struct TenebraWallet {
    password: String,
    address: Option<String>,
    message: Option<String>,
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
                    ui.add_space(15.0);
                    ui.label(
                        egui::RichText::new("TSC-1 NETWORK  ·  EXPERIMENTAL")
                            .color(egui::Color32::from_rgb(210, 177, 104)),
                    );
                    ui.add_space(8.0);
                    ui.add(
                        egui::Image::new(egui::include_image!("../../assets/tnb-emblem-v2.png"))
                            .fit_to_exact_size(egui::vec2(190.0, 190.0)),
                    );
                    ui.heading("TENEBRA Wallet");
                    ui.label("TNB  ·  Private by design");
                    ui.add_space(20.0);
                    egui::Frame::group(ui.style()).show(ui, |ui| {
                        ui.set_min_width(390.0);
                        ui.label("TNB BALANCE");
                        ui.heading("Unavailable");
                        ui.small("No active blockchain connection yet.");
                    });
                    ui.add_space(10.0);
                    egui::Frame::group(ui.style()).show(ui, |ui| {
                        ui.set_min_width(390.0);
                        ui.label("WALLET ADDRESS");
                        if let Some(address) = &self.address {
                            ui.label(egui::RichText::new(address).monospace().size(11.0));
                            if ui.button("Copy address").clicked() {
                                ui.ctx().copy_text(address.clone());
                                self.message = Some("Public address copied".into());
                            }
                        } else {
                            ui.label("Unlock the local wallet to view your public address.");
                        }
                    });
                    if self.address.is_none() {
                        ui.add_space(12.0);
                        ui.label("Wallet password");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.password)
                                .password(true)
                                .desired_width(300.0),
                        );
                        if ui.button("Unlock address").clicked() {
                            let password = Zeroizing::new(std::mem::take(&mut self.password));
                            match read_public_address(&password) {
                                Ok(address) => {
                                    self.address = Some(address);
                                    self.message = Some("Wallet address unlocked locally".into());
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
                        ui.add_enabled(false, egui::Button::new("Mine TNB"));
                    });
                    ui.add_space(12.0);
                    ui.small("Experimental software. Do not use with real funds.");
                });
            });
    }
}

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([520.0, 680.0]),
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
    fn synthetic_wallet_unlocks_only_with_correct_password() {
        let seed = [7u8; 32];
        let salt = [1u8; 16];
        let nonce = [2u8; 24];
        let mut key = [0u8; 32];
        Argon2::default()
            .hash_password_into(b"test-password", &salt, &mut key)
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
            unlock_address(&file, "test-password"),
            Ok(address_from_seed(&seed))
        );
        assert!(unlock_address(&file, "wrong-password").is_err());
        file[WALLET_LEN - 1] ^= 1;
        assert!(unlock_address(&file, "test-password").is_err());
    }
}
