use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, ristretto::CompressedRistretto, scalar::Scalar};
use sha2::{Digest, Sha512};

const DOMAIN: &[u8] = b"TENEBRA:miner-auth:v1";

fn challenge_scalar(public: &[u8; 32], challenge: &[u8], commitment: &[u8; 32]) -> Scalar {
    let mut hash = Sha512::new();
    hash.update(DOMAIN);
    hash.update(public);
    hash.update(challenge);
    hash.update(commitment);
    Scalar::from_hash(hash)
}

pub fn sign(spend_secret: Scalar, challenge: &[u8], nonce_wide: &[u8; 64]) -> [u8; 64] {
    let public = (spend_secret * RISTRETTO_BASEPOINT_POINT).compress().to_bytes();
    let nonce = Scalar::from_bytes_mod_order_wide(nonce_wide);
    let commitment = (nonce * RISTRETTO_BASEPOINT_POINT).compress().to_bytes();
    let response = nonce + challenge_scalar(&public, challenge, &commitment) * spend_secret;
    let mut signature = [0u8; 64];
    signature[..32].copy_from_slice(&commitment);
    signature[32..].copy_from_slice(&response.to_bytes());
    signature
}

pub fn verify(address: &str, challenge: &[u8], signature: &[u8; 64]) -> bool {
    let parsed = match crate::Address::parse(address) {
        Ok(address) => address,
        Err(_) => return false,
    };
    let commitment = CompressedRistretto::from_slice(&signature[..32])
        .ok()
        .and_then(|point| point.decompress());
    let response_bytes: [u8; 32] = match signature[32..].try_into() {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };
    let response = Scalar::from_canonical_bytes(response_bytes).into_option();
    let public = CompressedRistretto::from_slice(&parsed.spend)
        .ok()
        .and_then(|point| point.decompress());
    let (Some(commitment), Some(response), Some(public)) = (commitment, response, public) else {
        return false;
    };
    let commitment_bytes: [u8; 32] = match signature[..32].try_into() {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };
    let challenge = challenge_scalar(&parsed.spend, challenge, &commitment_bytes);
    response * RISTRETTO_BASEPOINT_POINT == commitment + challenge * public
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_signature_binds_address_and_message() {
        let secret = Scalar::from(42u64);
        let mut nonce = [0u8; 64];
        nonce[0] = 7;
        let signature = sign(secret, b"challenge", &nonce);
        let address = crate::Address {
            view: RISTRETTO_BASEPOINT_POINT.compress().to_bytes(),
            spend: (secret * RISTRETTO_BASEPOINT_POINT).compress().to_bytes(),
        };
        let checksum = sha2::Sha256::digest([b"TSC1-address-v1".as_slice(), &address.view, &address.spend].concat());
        let text = format!("tsc1_{}{}", hex::encode([address.view, address.spend].concat()), hex::encode(&checksum[..4]));
        assert!(verify(&text, b"challenge", &signature));
        assert!(!verify(&text, b"other", &signature));
    }
}
