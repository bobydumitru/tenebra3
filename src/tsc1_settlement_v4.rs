//! V4 settlement envelope for microblock commitments.

use crate::tsc1_chain_v2::Hash;
use crate::tsc1_protocol_v4::{FINALITY_SETTLEMENTS, SETTLEMENT_INTERVAL_MICROBLOCKS};
use sha2::{Digest, Sha256};
use std::io::{Cursor, Read};

const TAG: &[u8; 10] = b"TSC1SET4A1";

#[derive(Clone)]
pub struct SettlementV4 {
    pub parent_hash: Hash,
    pub height: u64,
    pub microblock_hashes: Vec<Hash>,
    pub finalized_height: u64,
}

impl SettlementV4 {
    pub fn validate_chain(
        &self,
        expected_parent: Hash,
        expected_height: u64,
        local_finalized_height: u64,
    ) -> Result<(), &'static str> {
        if self.parent_hash != expected_parent || self.height != expected_height {
            return Err("invalid v4 settlement link");
        }
        let required_finalized = self.height.saturating_sub(FINALITY_SETTLEMENTS);
        if self.finalized_height != required_finalized
            || self.finalized_height < local_finalized_height
        {
            return Err("invalid v4 settlement finality");
        }
        if self.microblock_hashes.contains(&[0; 32]) {
            return Err("invalid v4 microblock hash");
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, &'static str> {
        if self.microblock_hashes.len() != SETTLEMENT_INTERVAL_MICROBLOCKS as usize {
            return Err("invalid v4 settlement microblock count");
        }
        if self.finalized_height > self.height {
            return Err("invalid v4 finalized height");
        }
        let mut bytes = Vec::with_capacity(10 + 32 + 8 + 8 + 32 * self.microblock_hashes.len());
        bytes.extend_from_slice(TAG);
        bytes.extend_from_slice(&self.parent_hash);
        bytes.extend_from_slice(&self.height.to_le_bytes());
        bytes.extend_from_slice(&self.finalized_height.to_le_bytes());
        for hash in &self.microblock_hashes {
            bytes.extend_from_slice(hash);
        }
        Ok(bytes)
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, &'static str> {
        let expected = 10 + 32 + 8 + 8 + 32 * SETTLEMENT_INTERVAL_MICROBLOCKS as usize;
        if encoded.len() != expected {
            return Err("invalid v4 settlement length");
        }
        let mut cursor = Cursor::new(encoded);
        let mut tag = [0; 10];
        cursor
            .read_exact(&mut tag)
            .map_err(|_| "truncated v4 settlement")?;
        if &tag != TAG {
            return Err("wrong v4 settlement format");
        }
        let mut parent_hash = [0; 32];
        cursor
            .read_exact(&mut parent_hash)
            .map_err(|_| "truncated v4 settlement")?;
        let height = u64::from_le_bytes(read_array(&mut cursor)?);
        let finalized_height = u64::from_le_bytes(read_array(&mut cursor)?);
        if finalized_height > height {
            return Err("invalid v4 finalized height");
        }
        let mut microblock_hashes = Vec::with_capacity(SETTLEMENT_INTERVAL_MICROBLOCKS as usize);
        for _ in 0..SETTLEMENT_INTERVAL_MICROBLOCKS {
            microblock_hashes.push(read_array(&mut cursor)?);
        }
        Ok(Self {
            parent_hash,
            height,
            microblock_hashes,
            finalized_height,
        })
    }

    pub fn hash(&self) -> Result<Hash, &'static str> {
        let mut hasher = Sha256::new();
        hasher.update(b"TSC-1:v4:settlement-hash");
        hasher.update(self.encode()?);
        Ok(hasher.finalize().into())
    }
}

fn read_array<const N: usize>(cursor: &mut Cursor<&[u8]>) -> Result<[u8; N], &'static str> {
    let mut value = [0; N];
    cursor
        .read_exact(&mut value)
        .map_err(|_| "truncated v4 settlement")?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settlement_requires_exact_microblock_window() {
        let settlement = SettlementV4 {
            parent_hash: [0; 32],
            height: 1,
            microblock_hashes: vec![[1; 32]; SETTLEMENT_INTERVAL_MICROBLOCKS as usize],
            finalized_height: 0,
        };
        let encoded = settlement.encode().unwrap();
        assert_eq!(SettlementV4::decode(&encoded).unwrap().height, 1);
    }
}
