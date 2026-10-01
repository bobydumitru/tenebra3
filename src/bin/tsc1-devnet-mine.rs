//! Mines one valueless local TSC-1 devnet block from the fixed founder genesis.
//! Fixed 8-bit proof of work is deliberately insecure and for testing only.

#[path = "../tsc1_chain.rs"]
mod chain;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha256, Sha512};
use tenebra::{Address, OneTimeOutput, create_output};

const FOUNDER_ADDRESS: &str = include_str!("../../config/founder-address.txt");
const TREASURY_ADDRESS: &str = include_str!("../../config/treasury-address.txt");
const DEVNET_TIMESTAMP: u64 = 1_789_776_000;
const GENESIS_HASH: &str = "bbb10408fe764edeb6b886dc3d927597857d930c2c932eeb94f29b30570a95b4";

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

fn founder_output(address: &Address) -> Result<OneTimeOutput, &'static str> {
    let view = CompressedRistretto(address.view)
        .decompress()
        .ok_or("invalid founder view point")?;
    let spend = CompressedRistretto(address.spend)
        .decompress()
        .ok_or("invalid founder spend point")?;
    let mut source = Sha512::new();
    source.update(b"TSC-1:devnet:founder-ephemeral:v1");
    source.update(address.view);
    source.update(address.spend);
    let ephemeral_secret = Scalar::from_hash(source);
    if ephemeral_secret == Scalar::ZERO {
        return Err("invalid founder ephemeral scalar");
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
        return Err("invalid founder output");
    }
    Ok(OneTimeOutput {
        ephemeral,
        destination: destination.compress().to_bytes(),
    })
}

fn build_devnet() -> Result<chain::Chain, &'static str> {
    let founder = parse_address(FOUNDER_ADDRESS)?;
    let genesis_output = founder_output(&founder)?;
    let chain = chain::Chain::new(genesis_output, DEVNET_TIMESTAMP)?;
    if hex::encode(chain.tip_hash()) != GENESIS_HASH {
        return Err("devnet genesis hash changed");
    }
    chain.verify()?;
    Ok(chain)
}

fn mine_one_block() -> Result<chain::Chain, &'static str> {
    let mut chain = build_devnet()?;
    let miner = parse_address(TREASURY_ADDRESS)?;
    let reward_output = create_output(&miner, 0)?;
    let mut block = chain.next_block(reward_output, DEVNET_TIMESTAMP + 30);
    block.mine()?;
    chain.append(block)?;
    chain.verify()?;
    Ok(chain)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let chain = mine_one_block()?;
    println!("TSC-1 local devnet height: {}", chain.height());
    println!("Genesis hash: {GENESIS_HASH}");
    println!("First mining reward: {} nox", chain::reward_at_height(1));
    println!("Total issued: {} nox", chain.issued_nox());
    println!("Demo miner receiving address: {}", TREASURY_ADDRESS.trim());
    println!("In-memory demo only. No real or persistent TNB was created.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_is_anchored_to_expected_hash() {
        let chain = build_devnet().unwrap();
        assert_eq!(chain.height(), 0);
        assert_eq!(hex::encode(chain.tip_hash()), GENESIS_HASH);
        assert_eq!(chain.issued_nox(), chain::FOUNDER_NOX);
    }

    #[test]
    fn one_mined_block_only_issues_the_scheduled_reward() {
        let chain = mine_one_block().unwrap();
        assert_eq!(chain.height(), 1);
        assert_eq!(
            chain.issued_nox(),
            chain::FOUNDER_NOX + chain::reward_at_height(1)
        );
        assert!(chain.issued_nox() <= chain::MAX_SUPPLY_NOX);
        assert!(chain.verify().is_ok());
    }

    #[test]
    fn founder_and_miner_receiving_addresses_are_distinct() {
        assert_ne!(
            parse_address(FOUNDER_ADDRESS),
            parse_address(TREASURY_ADDRESS)
        );
    }
}
