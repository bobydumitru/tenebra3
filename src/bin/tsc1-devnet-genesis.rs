//! Reproducible local TSC-1 genesis prototype. Not a mainnet genesis block.

#[path = "../tsc1_chain.rs"]
mod chain;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha256, Sha512};
use tenebra::{Address, OneTimeOutput};

const FOUNDER_ADDRESS: &str = include_str!("../../config/founder-address.txt");
const DEVNET_TIMESTAMP: u64 = 1_789_776_000; // 2026-09-19 00:00:00 UTC

fn parse_address(text: &str) -> Result<Address, &'static str> {
    let encoded = text
        .trim()
        .strip_prefix("tsc1_")
        .ok_or("wrong address prefix")?;
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

/// A fixed public one-time output for a publicly disclosed founder allocation.
/// The ephemeral scalar is deliberately reproducible and not a privacy secret.
fn founder_output(address: &Address) -> Result<OneTimeOutput, &'static str> {
    let view = CompressedRistretto(address.view)
        .decompress()
        .ok_or("invalid view point")?;
    let spend = CompressedRistretto(address.spend)
        .decompress()
        .ok_or("invalid spend point")?;
    let mut source = Sha512::new();
    source.update(b"TSC-1:devnet:founder-ephemeral:v1");
    source.update(address.view);
    source.update(address.spend);
    let ephemeral_secret = Scalar::from_hash(source);
    if ephemeral_secret == Scalar::ZERO {
        return Err("invalid ephemeral scalar");
    }
    let ephemeral = (ephemeral_secret * RISTRETTO_BASEPOINT_POINT)
        .compress()
        .to_bytes();
    let shared = (ephemeral_secret * view).compress().to_bytes();
    let mut tweak_hash = Sha512::new();
    tweak_hash.update(b"TENEBRA:one-time-output:v1");
    tweak_hash.update(shared);
    tweak_hash.update(0u64.to_le_bytes());
    let tweak = Scalar::from_hash(tweak_hash);
    let destination = spend + tweak * RISTRETTO_BASEPOINT_POINT;
    if destination == RistrettoPoint::default() {
        return Err("invalid founder destination");
    }
    Ok(OneTimeOutput {
        ephemeral,
        destination: destination.compress().to_bytes(),
    })
}

fn devnet_genesis() -> Result<chain::Chain, &'static str> {
    let founder = parse_address(FOUNDER_ADDRESS)?;
    let output = founder_output(&founder)?;
    let chain = chain::Chain::new(output, DEVNET_TIMESTAMP)?;
    chain.verify()?;
    if chain.issued_nox() != chain::FOUNDER_NOX {
        return Err("wrong founder issuance");
    }
    Ok(chain)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let chain = devnet_genesis()?;
    println!(
        "TSC-1 devnet genesis hash: {}",
        hex::encode(chain.tip_hash())
    );
    println!("Founder allocation: 10,000,000 TNB");
    println!("Mining allocation: 90,000,000 TNB over approximately 50 years");
    println!("This is a local research devnet, not a public blockchain or spendable coin.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenebra::WalletSecrets;

    #[test]
    fn founder_address_is_valid() {
        assert!(parse_address(FOUNDER_ADDRESS).is_ok());
    }

    #[test]
    fn genesis_hash_is_reproducible_and_supply_is_exact() {
        let first = devnet_genesis().unwrap();
        let second = devnet_genesis().unwrap();
        assert_eq!(first.tip_hash(), second.tip_hash());
        assert_eq!(first.issued_nox(), 10_000_000 * chain::NOX_PER_TNB);
        assert_eq!(
            chain::FOUNDER_NOX + chain::MINING_POOL_NOX,
            chain::MAX_SUPPLY_NOX
        );
    }

    #[test]
    fn recipient_can_identify_deterministic_one_time_output() {
        let wallet = WalletSecrets::generate().unwrap();
        let output = founder_output(&wallet.address()).unwrap();
        assert!(wallet.scan_output(&output, 0).is_some());
        assert!(wallet.scan_output(&output, 1).is_none());
    }
}
