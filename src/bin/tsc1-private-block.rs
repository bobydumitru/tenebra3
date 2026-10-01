//! Atomic block-state prototype for private spends. Cryptographic authorization
//! is deliberately disabled in production until a reviewed verifier exists.

use std::collections::HashSet;

use sha2::{Digest, Sha256};

const MAX_TRANSACTIONS: usize = 1024;
const MAX_OUTPUTS_PER_TX: usize = 16;

#[derive(Clone)]
struct PrivateTx {
    key_images: Vec<[u8; 32]>,
    output_destinations: Vec<[u8; 32]>,
    fee_nox: u64,
    authorization: Vec<u8>,
}

#[derive(Clone, Default)]
struct BlockState {
    spent_images: HashSet<[u8; 32]>,
    destinations: HashSet<[u8; 32]>,
    height: u64,
}

struct FeePayout {
    miner_nox: u64,
    treasury_nox: u64,
}

trait PrivateProofVerifier {
    fn verify(&self, tx: &PrivateTx) -> Result<(), &'static str>;
}

struct ProductionVerifier;

impl PrivateProofVerifier for ProductionVerifier {
    fn verify(&self, _tx: &PrivateTx) -> Result<(), &'static str> {
        Err("anonymous spend proof verifier is not implemented")
    }
}

impl BlockState {
    /// Validates a complete block against a temporary copy, committing only
    /// after every transaction and fee calculation succeeds.
    fn apply_block<V: PrivateProofVerifier>(
        &mut self,
        transactions: &[PrivateTx],
        verifier: &V,
    ) -> Result<FeePayout, &'static str> {
        if transactions.len() > MAX_TRANSACTIONS {
            return Err("too many transactions");
        }
        let mut pending = self.clone();
        let mut fees: u64 = 0;
        for tx in transactions {
            if tx.key_images.is_empty()
                || tx.output_destinations.is_empty()
                || tx.output_destinations.len() > MAX_OUTPUTS_PER_TX
                || tx.fee_nox == 0
                || tx.authorization.is_empty()
            {
                return Err("invalid transaction shape");
            }
            let mut local_images = HashSet::new();
            for image in &tx.key_images {
                if !local_images.insert(*image) || !pending.spent_images.insert(*image) {
                    return Err("duplicate or spent key image");
                }
            }
            for destination in &tx.output_destinations {
                if !pending.destinations.insert(*destination) {
                    return Err("duplicate output destination");
                }
            }
            verifier.verify(tx)?;
            fees = fees.checked_add(tx.fee_nox).ok_or("fee overflow")?;
        }
        pending.height = pending.height.checked_add(1).ok_or("height overflow")?;
        let treasury_nox = fees / 10;
        let payout = FeePayout {
            miner_nox: fees - treasury_nox,
            treasury_nox,
        };
        *self = pending;
        Ok(payout)
    }

    fn fingerprint(&self) -> [u8; 32] {
        let mut images: Vec<_> = self.spent_images.iter().collect();
        images.sort();
        let mut hasher = Sha256::new();
        hasher.update(b"TSC-1:private-block-state:v1");
        hasher.update(self.height.to_le_bytes());
        for image in images {
            hasher.update(image);
        }
        hasher.finalize().into()
    }
}

fn main() {
    let mut state = BlockState::default();
    let result = state.apply_block(&[sample_tx(1, 11, 10)], &ProductionVerifier);
    assert!(result.is_err());
    println!("TSC-1 private block state: real spends remain disabled");
}

fn sample_tx(image: u8, destination: u8, fee_nox: u64) -> PrivateTx {
    PrivateTx {
        key_images: vec![[image; 32]],
        output_destinations: vec![[destination; 32]],
        fee_nox,
        authorization: vec![1],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // This fake verifier exercises state transitions only. It is never used in main.
    struct TestVerifier;
    impl PrivateProofVerifier for TestVerifier {
        fn verify(&self, _: &PrivateTx) -> Result<(), &'static str> {
            Ok(())
        }
    }

    #[test]
    fn production_rejects_and_keeps_state_unchanged() {
        let mut state = BlockState::default();
        let before = state.fingerprint();
        assert_eq!(
            state
                .apply_block(&[sample_tx(1, 11, 10)], &ProductionVerifier)
                .err(),
            Some("anonymous spend proof verifier is not implemented")
        );
        assert_eq!(state.fingerprint(), before);
    }

    #[test]
    fn test_verifier_checks_atomicity_and_replay() {
        let mut state = BlockState::default();
        let payout = state
            .apply_block(&[sample_tx(1, 11, 11), sample_tx(2, 12, 9)], &TestVerifier)
            .unwrap();
        assert_eq!((payout.miner_nox, payout.treasury_nox), (18, 2));
        assert_eq!(state.height, 1);
        let before = state.fingerprint();
        assert_eq!(
            state
                .apply_block(&[sample_tx(3, 13, 10), sample_tx(1, 14, 10)], &TestVerifier)
                .err(),
            Some("duplicate or spent key image")
        );
        assert_eq!(state.fingerprint(), before);
    }

    #[test]
    fn same_block_duplicates_and_overflow_reject_atomically() {
        let mut state = BlockState::default();
        assert_eq!(
            state
                .apply_block(&[sample_tx(1, 11, 1), sample_tx(1, 12, 1)], &TestVerifier)
                .err(),
            Some("duplicate or spent key image")
        );
        assert_eq!(state.height, 0);
        assert_eq!(
            state
                .apply_block(
                    &[sample_tx(1, 11, u64::MAX), sample_tx(2, 12, 1)],
                    &TestVerifier
                )
                .err(),
            Some("fee overflow")
        );
        assert_eq!(state.height, 0);
    }
}
