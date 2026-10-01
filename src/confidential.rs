//! Experimental amount commitments. NOT a complete confidential transaction.
//! Range proofs and spend authorization are mandatory before network use.

#![allow(dead_code)]

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Commitment(pub [u8; 32]);

fn value_generator() -> RistrettoPoint {
    let uniform: [u8; 64] = Sha512::digest(b"TENEBRA:amount-generator:v1").into();
    RistrettoPoint::from_uniform_bytes(&uniform)
}

pub fn random_blinding() -> Result<Scalar, getrandom::Error> {
    let mut bytes = [0u8; 64];
    getrandom::getrandom(&mut bytes)?;
    Ok(Scalar::from_bytes_mod_order_wide(&bytes))
}

/// Hides `amount` using a secret blinding scalar: C = amount*H + blind*G.
pub fn commit(amount: u64, blind: Scalar) -> Commitment {
    let point = Scalar::from(amount) * value_generator() + blind * RISTRETTO_BASEPOINT_POINT;
    Commitment(point.compress().to_bytes())
}

/// Checks the commitment balance, including the public fee.
/// This is NOT sufficient without a range proof for every output.
pub fn balances(inputs: &[Commitment], outputs: &[Commitment], fee: u64) -> bool {
    let decode = |commitment: &Commitment| CompressedRistretto(commitment.0).decompress();
    let mut left = RistrettoPoint::default();
    for input in inputs {
        let Some(point) = decode(input) else {
            return false;
        };
        left += point;
    }
    let mut right = Scalar::from(fee) * value_generator();
    for output in outputs {
        let Some(point) = decode(output) else {
            return false;
        };
        right += point;
    }
    left == right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commitment_hides_value_with_fresh_blinding() {
        let a = commit(100, random_blinding().unwrap());
        let b = commit(100, random_blinding().unwrap());
        assert_ne!(a, b);
    }

    #[test]
    fn correct_amounts_and_blindings_balance() {
        let input_blind = random_blinding().unwrap();
        let first_output_blind = random_blinding().unwrap();
        let second_output_blind = input_blind - first_output_blind;
        let input = commit(100, input_blind);
        let first = commit(60, first_output_blind);
        let second = commit(39, second_output_blind);
        assert!(balances(&[input], &[first, second], 1));
        assert!(!balances(&[input], &[first, second], 2));
    }

    #[test]
    fn invalid_commitment_is_rejected() {
        assert!(!balances(&[Commitment([0xff; 32])], &[], 0));
    }
}
