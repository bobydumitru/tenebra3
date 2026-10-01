//! Structural checks for a future anonymous-spend proof. These checks are not
//! cryptographic verification and must never authorize a transaction.

use std::collections::HashSet;

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};

const RING_SIZE: usize = 16;
const MAX_PROOF_BYTES: usize = 16 * 1024;

struct SpendEnvelope {
    key_image: [u8; 32],
    ring_members: Vec<[u8; 32]>,
    proof: Vec<u8>,
}

fn precheck(
    envelope: &SpendEnvelope,
    spent_images: &HashSet<[u8; 32]>,
) -> Result<(), &'static str> {
    if envelope.ring_members.len() != RING_SIZE {
        return Err("invalid ring size");
    }
    if envelope
        .ring_members
        .iter()
        .copied()
        .collect::<HashSet<_>>()
        .len()
        != RING_SIZE
    {
        return Err("duplicate ring member");
    }
    if envelope.proof.is_empty() || envelope.proof.len() > MAX_PROOF_BYTES {
        return Err("invalid proof size");
    }
    if spent_images.contains(&envelope.key_image) {
        return Err("key image already spent");
    }
    let image = CompressedRistretto(envelope.key_image)
        .decompress()
        .ok_or("invalid key image encoding")?;
    if image == RistrettoPoint::default() {
        return Err("identity key image");
    }
    Ok(())
}

/// Structural acceptance is never enough to authorize a private spend.
fn verify_for_consensus(
    envelope: &SpendEnvelope,
    spent_images: &HashSet<[u8; 32]>,
) -> Result<(), &'static str> {
    precheck(envelope, spent_images)?;
    Err("reviewed anonymous-spend proof verifier is not implemented")
}

fn main() {
    println!("TSC-1 anonymous-spend boundary: consensus authorization disabled");
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;

    fn sample() -> SpendEnvelope {
        SpendEnvelope {
            key_image: RISTRETTO_BASEPOINT_POINT.compress().to_bytes(),
            ring_members: (0..RING_SIZE).map(|i| [i as u8; 32]).collect(),
            proof: vec![1],
        }
    }

    #[test]
    fn structurally_valid_envelope_still_cannot_spend() {
        let envelope = sample();
        let spent = HashSet::new();
        assert_eq!(precheck(&envelope, &spent), Ok(()));
        assert_eq!(
            verify_for_consensus(&envelope, &spent),
            Err("reviewed anonymous-spend proof verifier is not implemented")
        );
    }

    #[test]
    fn rejects_duplicate_ring_members_and_wrong_size() {
        let mut envelope = sample();
        envelope.ring_members[1] = envelope.ring_members[0];
        assert_eq!(
            precheck(&envelope, &HashSet::new()),
            Err("duplicate ring member")
        );
        envelope.ring_members.pop();
        assert_eq!(
            precheck(&envelope, &HashSet::new()),
            Err("invalid ring size")
        );
    }

    #[test]
    fn rejects_replayed_or_invalid_key_images() {
        let mut envelope = sample();
        let mut spent = HashSet::new();
        spent.insert(envelope.key_image);
        assert_eq!(precheck(&envelope, &spent), Err("key image already spent"));
        envelope.key_image = [0; 32];
        assert_eq!(
            precheck(&envelope, &HashSet::new()),
            Err("identity key image")
        );
    }

    #[test]
    fn rejects_empty_or_excessive_proofs() {
        let mut envelope = sample();
        envelope.proof.clear();
        assert_eq!(
            precheck(&envelope, &HashSet::new()),
            Err("invalid proof size")
        );
        envelope.proof.resize(MAX_PROOF_BYTES + 1, 0);
        assert_eq!(
            precheck(&envelope, &HashSet::new()),
            Err("invalid proof size")
        );
    }
}
