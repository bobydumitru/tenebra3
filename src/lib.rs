//! TENEBRA privacy-first mainnet implementation.
//!
//! The public deployment is operational, but the protocol still carries
//! documented cryptographic and network limitations.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroize;

#[cfg(all(feature = "mainnet-candidate", not(target_arch = "wasm32")))]
pub mod candidate_node;
pub mod assets;
#[cfg(not(target_arch = "wasm32"))]
pub mod bridge;
pub mod dex;
pub mod miner_auth;
pub mod network;
pub mod tsc1_chain_v2;
pub mod tsc1_chain_v3;
pub mod tsc1_devnet_v2;
pub mod tsc1_fee;
pub mod tsc1_funded_output;
pub mod tsc1_microblock_v4;
pub mod tsc1_peer_v2;
pub mod tsc1_peer_v3;
pub mod tsc1_peer_v4;
pub mod tsc1_pending_v3;
pub mod tsc1_private_amounts;
pub mod tsc1_protocol_v4;
pub mod tsc1_settlement_v4;
pub mod tsc1_spend_journal_v2;
pub mod tsc1_spend_state_v2;
pub mod tsc1_tx_v2;
pub mod tsc1_wallet_tx_v3;

pub const SYMBOL: &str = "TNB";
pub const NOX_PER_TNB: u64 = 1_000_000_000;
pub const MAX_SUPPLY_NOX: u64 = 100_000_000 * NOX_PER_TNB;
pub const FOUNDER_ALLOCATION_NOX: u64 = 10_000_000 * NOX_PER_TNB;
pub const MINING_ALLOCATION_NOX: u64 = 90_000_000 * NOX_PER_TNB;

/// Public address: view and spend points. Neither contains a real-world name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Address {
    pub view: [u8; 32],
    pub spend: [u8; 32],
}

impl Address {
    pub fn parse(text: &str) -> Result<Self, &'static str> {
        let encoded = text
            .trim()
            .strip_prefix("tsc1_")
            .ok_or("wrong address prefix")?;
        if encoded.len() != 136 {
            return Err("wrong address length");
        }
        let bytes = hex::decode(encoded).map_err(|_| "invalid address characters")?;
        let checksum = Sha256::digest([b"TSC1-address-v1".as_slice(), &bytes[..64]].concat());
        if bytes[64..] != checksum[..4] {
            return Err("invalid address checksum");
        }
        let mut view = [0u8; 32];
        let mut spend = [0u8; 32];
        view.copy_from_slice(&bytes[..32]);
        spend.copy_from_slice(&bytes[32..64]);
        let view_point = CompressedRistretto(view)
            .decompress()
            .ok_or("invalid view point")?;
        let spend_point = CompressedRistretto(spend)
            .decompress()
            .ok_or("invalid spend point")?;
        if view_point == Default::default() || spend_point == Default::default() {
            return Err("identity address point");
        }
        Ok(Self { view, spend })
    }
}

/// A fresh destination for one payment. The transaction must publish both fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OneTimeOutput {
    pub ephemeral: [u8; 32],
    pub destination: [u8; 32],
}

/// Secret keys must never be logged, checked into source control, or sent to nodes.
pub struct WalletSecrets {
    view: Scalar,
    spend: Scalar,
}

impl Drop for WalletSecrets {
    fn drop(&mut self) {
        self.view.zeroize();
        self.spend.zeroize();
    }
}

fn random_scalar() -> Result<Scalar, getrandom::Error> {
    let mut wide = [0u8; 64];
    getrandom::getrandom(&mut wide)?;
    Ok(Scalar::from_bytes_mod_order_wide(&wide))
}

fn output_tweak(shared: [u8; 32], index: u64) -> Scalar {
    let mut hash = Sha512::new();
    hash.update(b"TENEBRA:one-time-output:v1");
    hash.update(shared);
    hash.update(index.to_le_bytes());
    Scalar::from_hash(hash)
}

impl WalletSecrets {
    /// Derives the keys used by existing TSC-1 encrypted wallet files.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        fn derive(seed: &[u8; 32], role: &[u8]) -> Scalar {
            let mut hash = Sha512::new();
            hash.update(b"TSC-1:wallet-key:v1");
            hash.update(role);
            hash.update(seed);
            Scalar::from_hash(hash)
        }
        Self {
            view: derive(seed, b"view"),
            spend: derive(seed, b"spend"),
        }
    }
    /// Generates two independent secrets using the operating system RNG.
    pub fn generate() -> Result<Self, getrandom::Error> {
        Ok(Self {
            view: random_scalar()?,
            spend: random_scalar()?,
        })
    }

    pub fn address(&self) -> Address {
        Address {
            view: (self.view * RISTRETTO_BASEPOINT_POINT)
                .compress()
                .to_bytes(),
            spend: (self.spend * RISTRETTO_BASEPOINT_POINT)
                .compress()
                .to_bytes(),
        }
    }

    /// Returns a one-time private spend key only for outputs belonging to us.
    /// It is not yet wired into a transaction or wallet database.
    pub fn scan_output(&self, output: &OneTimeOutput, index: u64) -> Option<[u8; 32]> {
        let ephemeral = CompressedRistretto(output.ephemeral).decompress()?;
        let shared = (self.view * ephemeral).compress().to_bytes();
        let one_time_spend = self.spend + output_tweak(shared, index);
        let expected = (one_time_spend * RISTRETTO_BASEPOINT_POINT)
            .compress()
            .to_bytes();
        (expected == output.destination).then(|| one_time_spend.to_bytes())
    }
}

/// Creates an unlinkable destination for a public address and output index.
pub fn create_output(address: &Address, index: u64) -> Result<OneTimeOutput, &'static str> {
    let ephemeral_secret = random_scalar().map_err(|_| "OS randomness unavailable")?;
    output_from_ephemeral_secret(address, index, ephemeral_secret)
}

pub(crate) fn output_from_ephemeral_secret(
    address: &Address,
    index: u64,
    ephemeral_secret: Scalar,
) -> Result<OneTimeOutput, &'static str> {
    let view = CompressedRistretto(address.view)
        .decompress()
        .ok_or("invalid public view key")?;
    let spend = CompressedRistretto(address.spend)
        .decompress()
        .ok_or("invalid public spend key")?;
    let ephemeral = (ephemeral_secret * RISTRETTO_BASEPOINT_POINT)
        .compress()
        .to_bytes();
    let shared = (ephemeral_secret * view).compress().to_bytes();
    let destination = (spend + output_tweak(shared, index) * RISTRETTO_BASEPOINT_POINT)
        .compress()
        .to_bytes();
    Ok(OneTimeOutput {
        ephemeral,
        destination,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn allocations_fit_cap() {
        assert_eq!(
            FOUNDER_ALLOCATION_NOX + MINING_ALLOCATION_NOX,
            MAX_SUPPLY_NOX
        );
    }

    #[test]
    fn recipient_finds_output_but_stranger_does_not() {
        let recipient = WalletSecrets::generate().unwrap();
        let stranger = WalletSecrets::generate().unwrap();
        let output = create_output(&recipient.address(), 0).unwrap();
        assert!(recipient.scan_output(&output, 0).is_some());
        assert!(recipient.scan_output(&output, 1).is_none());
        assert!(stranger.scan_output(&output, 0).is_none());
    }

    #[test]
    fn two_payments_have_different_destinations() {
        let recipient = WalletSecrets::generate().unwrap();
        let first = create_output(&recipient.address(), 0).unwrap();
        let second = create_output(&recipient.address(), 0).unwrap();
        assert_ne!(first.destination, second.destination);
    }

    proptest! {
        #[test]
        fn seeded_wallet_derivation_is_deterministic(seed in prop::array::uniform32(any::<u8>())) {
            let first = WalletSecrets::from_seed(&seed).address();
            let second = WalletSecrets::from_seed(&seed).address();
            prop_assert_eq!(first, second);
        }

        #[test]
        fn one_time_output_round_trip_scans_only_at_its_index(
            seed in prop::array::uniform32(any::<u8>()),
            index in any::<u64>(),
        ) {
            let wallet = WalletSecrets::from_seed(&seed);
            let output = create_output(&wallet.address(), index).unwrap();
            prop_assert!(wallet.scan_output(&output, index).is_some());
            if index != u64::MAX {
                prop_assert!(wallet.scan_output(&output, index + 1).is_none());
            }
        }
    }
}
