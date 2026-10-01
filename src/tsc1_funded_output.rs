//! Candidate confidential output for TSC-1 v2. Not connected to consensus.

use crate::tsc1_private_amounts::{
    ProvenAmount, TNB_ASSET_ID, prove_amount, random_blinding, verify_amount,
};
use crate::{Address, OneTimeOutput, WalletSecrets, output_tweak, random_scalar};
use bulletproofs::PedersenGens;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha256};
use std::io::{Cursor, Read};

const MAX_AMOUNT_PROOF_BYTES: usize = 2_048;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FundedOutput {
    pub destination: OneTimeOutput,
    pub amount: ProvenAmount,
    pub note_nonce: [u8; 12],
    pub encrypted_note: Vec<u8>,
}

pub struct RecoveredOutput {
    pub amount_nox: u64,
    pub blinding: Scalar,
    pub one_time_spend: [u8; 32],
}

impl FundedOutput {
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, &'static str> {
        fn take<const N: usize>(cursor: &mut Cursor<&[u8]>) -> Result<[u8; N], &'static str> {
            let mut field = [0u8; N];
            cursor
                .read_exact(&mut field)
                .map_err(|_| "truncated output")?;
            Ok(field)
        }
        let mut cursor = Cursor::new(bytes);
        let ephemeral = take(&mut cursor)?;
        let destination = take(&mut cursor)?;
        let commitment = take(&mut cursor)?;
        let next = u32::from_le_bytes(take(&mut cursor)?);
        let (asset_id, proof_len) = if next == u32::MAX {
            let asset_id = take(&mut cursor)?;
            if asset_id == TNB_ASSET_ID {
                return Err("noncanonical native output");
            }
            (asset_id, u32::from_le_bytes(take(&mut cursor)?) as usize)
        } else if next as usize <= MAX_AMOUNT_PROOF_BYTES {
            (crate::assets::TNB_ASSET_ID, next as usize)
        } else {
            return Err("oversized amount proof");
        };
        if proof_len > MAX_AMOUNT_PROOF_BYTES {
            return Err("oversized amount proof");
        }
        let mut range_proof = vec![0u8; proof_len];
        cursor
            .read_exact(&mut range_proof)
            .map_err(|_| "truncated output")?;
        let note_nonce = take(&mut cursor)?;
        let note_len = u32::from_le_bytes(take(&mut cursor)?) as usize;
        if note_len > 56 {
            return Err("oversized encrypted note");
        }
        let mut encrypted_note = vec![0u8; note_len];
        cursor
            .read_exact(&mut encrypted_note)
            .map_err(|_| "truncated output")?;
        if cursor.position() != bytes.len() as u64 {
            return Err("trailing output bytes");
        }
        Ok(Self {
            destination: OneTimeOutput {
                ephemeral,
                destination,
            },
            amount: ProvenAmount {
                asset_id,
                commitment,
                range_proof,
            },
            note_nonce,
            encrypted_note,
        })
    }

    pub fn encode_canonical(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.destination.ephemeral);
        bytes.extend_from_slice(&self.destination.destination);
        bytes.extend_from_slice(&self.amount.commitment);
        if self.amount.asset_id != crate::assets::TNB_ASSET_ID {
            bytes.extend_from_slice(&u32::MAX.to_le_bytes());
            bytes.extend_from_slice(&self.amount.asset_id);
        }
        bytes.extend_from_slice(&(self.amount.range_proof.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.amount.range_proof);
        bytes.extend_from_slice(&self.note_nonce);
        bytes.extend_from_slice(&(self.encrypted_note.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.encrypted_note);
        bytes
    }

    /// Checks the public fields before an output can enter a candidate block.
    pub fn verify_public_structure(&self) -> bool {
        let ephemeral = CompressedRistretto(self.destination.ephemeral).decompress();
        let destination = CompressedRistretto(self.destination.destination).decompress();
        matches!(ephemeral, Some(point) if point != RistrettoPoint::default())
            && matches!(destination, Some(point) if point != RistrettoPoint::default())
            && self.amount.range_proof.len() <= MAX_AMOUNT_PROOF_BYTES
            && self.encrypted_note.len() == 56
    }

    pub fn verify_public(&self) -> bool {
        self.verify_public_structure() && verify_amount(&self.amount, &self.amount.asset_id)
    }
}

fn note_key(shared: [u8; 32]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"TSC-1:funded-output-note:v2");
    hash.update(shared);
    hash.finalize().into()
}

fn note_aad(output: &OneTimeOutput, commitment: &[u8; 32], index: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(8 + 32 * 3 + 8);
    aad.extend_from_slice(b"TSC1NOTE");
    aad.extend_from_slice(&output.ephemeral);
    aad.extend_from_slice(&output.destination);
    aad.extend_from_slice(commitment);
    aad.extend_from_slice(&index.to_le_bytes());
    aad
}

pub fn create_funded_output(
    address: &Address,
    index: u64,
    amount_nox: u64,
) -> Result<FundedOutput, &'static str> {
    let blinding = random_blinding().map_err(|_| "OS randomness unavailable")?;
    create_with_blinding(address, index, amount_nox, blinding)
}

pub fn create_funded_output_with_blinding(
    address: &Address,
    index: u64,
    amount_nox: u64,
    blinding: Scalar,
) -> Result<FundedOutput, &'static str> {
    create_with_blinding(address, index, amount_nox, blinding)
}

/// Reward amounts are public; zero blinding lets validators enforce exact issuance.
pub fn create_reward_output(
    address: &Address,
    index: u64,
    amount_nox: u64,
) -> Result<FundedOutput, &'static str> {
    create_with_blinding(address, index, amount_nox, Scalar::ZERO)
}

fn create_with_blinding(
    address: &Address,
    index: u64,
    amount_nox: u64,
    blinding: Scalar,
) -> Result<FundedOutput, &'static str> {
    let ephemeral_secret = random_scalar().map_err(|_| "OS randomness unavailable")?;
    create_with_blinding_and_secret(address, index, amount_nox, blinding, ephemeral_secret)
}

pub fn create_public_fee_output(
    address: &Address,
    amount_nox: u64,
    ephemeral_secret: Scalar,
) -> Result<FundedOutput, &'static str> {
    create_with_blinding_and_secret(address, 0, amount_nox, Scalar::ZERO, ephemeral_secret)
}

fn create_with_blinding_and_secret(
    address: &Address,
    index: u64,
    amount_nox: u64,
    blinding: Scalar,
    ephemeral_secret: Scalar,
) -> Result<FundedOutput, &'static str> {
    let view = CompressedRistretto(address.view)
        .decompress()
        .ok_or("invalid view key")?;
    let spend = CompressedRistretto(address.spend)
        .decompress()
        .ok_or("invalid spend key")?;
    let shared = (ephemeral_secret * view).compress().to_bytes();
    let destination = OneTimeOutput {
        ephemeral: (ephemeral_secret * RISTRETTO_BASEPOINT_POINT)
            .compress()
            .to_bytes(),
        destination: (spend + output_tweak(shared, index) * RISTRETTO_BASEPOINT_POINT)
            .compress()
            .to_bytes(),
    };
    let amount = prove_amount(amount_nox, &blinding, &TNB_ASSET_ID)
        .map_err(|_| "amount proof creation failed")?;
    let mut note = Vec::with_capacity(40);
    note.extend_from_slice(&amount_nox.to_le_bytes());
    note.extend_from_slice(&blinding.to_bytes());
    let mut note_nonce = [0u8; 12];
    getrandom::getrandom(&mut note_nonce).map_err(|_| "OS randomness unavailable")?;
    let encrypted_note = ChaCha20Poly1305::new(&note_key(shared).into())
        .encrypt(
            Nonce::from_slice(&note_nonce),
            Payload {
                msg: &note,
                aad: &note_aad(&destination, &amount.commitment, index),
            },
        )
        .map_err(|_| "note encryption failed")?;
    Ok(FundedOutput {
        destination,
        amount,
        note_nonce,
        encrypted_note,
    })
}

impl WalletSecrets {
    /// Recognizes, decrypts, and validates a candidate output owned by this wallet.
    pub fn scan_funded_output(&self, output: &FundedOutput, index: u64) -> Option<RecoveredOutput> {
        let one_time_spend = self.scan_output(&output.destination, index)?;
        if !output.verify_public() {
            return None;
        }
        let ephemeral = CompressedRistretto(output.destination.ephemeral).decompress()?;
        let shared = (self.view * ephemeral).compress().to_bytes();
        let plaintext = ChaCha20Poly1305::new(&note_key(shared).into())
            .decrypt(
                Nonce::from_slice(&output.note_nonce),
                Payload {
                    msg: &output.encrypted_note,
                    aad: &note_aad(&output.destination, &output.amount.commitment, index),
                },
            )
            .ok()?;
        if plaintext.len() != 40 {
            return None;
        }
        let amount_nox = u64::from_le_bytes(plaintext[..8].try_into().ok()?);
        let blinding = Option::<Scalar>::from(Scalar::from_canonical_bytes(
            plaintext[8..].try_into().ok()?,
        ))?;
        let recomputed = PedersenGens::default().commit(Scalar::from(amount_nox), blinding);
        if recomputed.compress().to_bytes() != output.amount.commitment {
            return None;
        }
        Some(RecoveredOutput {
            amount_nox,
            blinding,
            one_time_spend,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_output_roundtrip_and_asset_proof_binding() {
        let wallet = WalletSecrets::from_seed(&[19; 32]);
        let mut output = create_funded_output(&wallet.address(), 0, 42).unwrap();
        // Includes asset IDs whose prefix could otherwise look like a proof length.
        for token in [[7; 32], {
            let mut id = [0; 32];
            id[31] = 1;
            id
        }] {
            output.amount = prove_amount(42, &Scalar::ONE, &token).unwrap();
            let bytes = output.encode_canonical();
            let decoded = FundedOutput::decode_canonical(&bytes).unwrap();
            assert_eq!(decoded.encode_canonical(), bytes);
            assert_eq!(decoded.amount.asset_id, token);
            assert!(decoded.verify_public());
            let mut tampered = decoded;
            tampered.amount.asset_id = TNB_ASSET_ID;
            assert!(!tampered.verify_public());
        }
    }

    #[test]
    fn wallet_recovers_valid_output() {
        let wallet = WalletSecrets::generate().unwrap();
        let stranger = WalletSecrets::generate().unwrap();
        let output = create_funded_output(&wallet.address(), 0, 42).unwrap();
        let recovered = wallet.scan_funded_output(&output, 0).unwrap();
        assert_eq!(recovered.amount_nox, 42);
        assert!(wallet.scan_funded_output(&output, 1).is_none());
        assert!(stranger.scan_funded_output(&output, 0).is_none());
    }

    #[test]
    fn tampering_fails() {
        let wallet = WalletSecrets::generate().unwrap();
        let mut output = create_funded_output(&wallet.address(), 0, 99).unwrap();
        output.encrypted_note[0] ^= 1;
        assert!(wallet.scan_funded_output(&output, 0).is_none());
    }

    #[test]
    fn changed_nonce_and_commitment_fail() {
        let wallet = WalletSecrets::generate().unwrap();
        let mut output = create_funded_output(&wallet.address(), 0, 99).unwrap();
        output.note_nonce[0] ^= 1;
        assert!(wallet.scan_funded_output(&output, 0).is_none());

        let mut output = create_funded_output(&wallet.address(), 0, 99).unwrap();
        output.amount.commitment[0] ^= 1;
        assert!(wallet.scan_funded_output(&output, 0).is_none());
    }
}
