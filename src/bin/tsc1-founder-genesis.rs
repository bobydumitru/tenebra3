//! Local-only founder allocation check. Does not launch a network or mint real coins.

#[path = "../tsc1_chain.rs"]
mod chain;

use curve25519_dalek::ristretto::CompressedRistretto;
use sha2::{Digest, Sha256};
use tenebra::{Address, create_output};

const FOUNDER_ADDRESS: &str = include_str!("../../config/founder-address.txt");

fn parse_address(text: &str) -> Result<Address, &'static str> {
    let encoded = text.trim().strip_prefix("tsc1_").ok_or("wrong prefix")?;
    if encoded.len() != 136 {
        return Err("wrong length");
    }
    let bytes = hex::decode(encoded).map_err(|_| "invalid hexadecimal address")?;
    let public = &bytes[..64];
    let checksum = Sha256::digest([b"TSC1-address-v1".as_slice(), public].concat());
    if bytes[64..] != checksum[..4] {
        return Err("invalid checksum");
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let founder = parse_address(FOUNDER_ADDRESS)?;
    let founder_output = create_output(&founder, 0)?;
    let chain = chain::Chain::new(founder_output, 1)?;
    chain.verify()?;
    if chain.issued_nox() != chain::FOUNDER_NOX {
        return Err("wrong founder allocation".into());
    }
    println!("Founder allocation configuration verified: 10,000,000 TNB.");
    println!("Local prototype only; no real coins were created.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approved_founder_address_has_valid_keys_and_checksum() {
        assert!(parse_address(FOUNDER_ADDRESS).is_ok());
    }

    #[test]
    fn tampered_address_is_rejected() {
        let mut changed = FOUNDER_ADDRESS.trim().as_bytes().to_vec();
        let last = changed.last_mut().unwrap();
        *last = if *last == b'0' { b'1' } else { b'0' };
        assert!(parse_address(std::str::from_utf8(&changed).unwrap()).is_err());
    }
}
