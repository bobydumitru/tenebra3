//! TSC-1 v4 throughput protocol parameters.
//!
//! This module defines the versioned microblock/settlement envelope. It does
//! not enable v4 consensus until anonymous batch-proof verification is wired
//! into the validator.

use crate::tsc1_chain_v2::Hash;
use sha2::{Digest, Sha256};

pub const PROTOCOL_VERSION: u8 = 4;
pub const MICROBLOCK_INTERVAL_SECONDS: u64 = 1;
pub const MICROBLOCK_TRANSACTION_LIMIT: usize = 500;
pub const SETTLEMENT_INTERVAL_MICROBLOCKS: u64 = 30;
pub const FINALITY_SETTLEMENTS: u64 = 10;
pub const NETWORK_DOMAIN: &[u8] = b"TSC-1:v4-throughput-network";

pub fn network_id(genesis_hash: Hash) -> Hash {
    let mut bytes = Vec::with_capacity(NETWORK_DOMAIN.len() + genesis_hash.len());
    bytes.extend_from_slice(NETWORK_DOMAIN);
    bytes.extend_from_slice(&genesis_hash);
    Sha256::digest(bytes).into()
}

pub fn settlement_height(microblock_height: u64) -> u64 {
    microblock_height / SETTLEMENT_INTERVAL_MICROBLOCKS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_network_domain_is_distinct_and_bounded() {
        let genesis = [7; 32];
        assert_ne!(network_id(genesis), genesis);
        assert_eq!(MICROBLOCK_TRANSACTION_LIMIT, 500);
        assert_eq!(settlement_height(29), 0);
        assert_eq!(settlement_height(30), 1);
    }
}
