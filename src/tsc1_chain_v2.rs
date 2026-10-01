//! Reward-only devnet v2 chain with funded outputs and confidential amount proofs.
//! The local devnet pins genesis and persists blocks; payments and P2P are absent.

use crate::tsc1_funded_output::FundedOutput;
use crate::tsc1_private_amounts::ProvenAmount;
use crate::{FOUNDER_ALLOCATION_NOX, MAX_SUPPLY_NOX, MINING_ALLOCATION_NOX, OneTimeOutput};
use bulletproofs::PedersenGens;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io::{Cursor, Read};

pub const TARGET_BLOCK_SECONDS: u64 = 30;
pub const EMISSION_BLOCKS: u64 = 50 * 365 * 24 * 60 * 60 / TARGET_BLOCK_SECONDS;
pub const MINING_REWARD_SPLIT_ACTIVATION_HEIGHT: u64 =
    crate::tsc1_fee::FEE_POLICY_ACTIVATION_HEIGHT;
pub type Hash = [u8; 32];

fn read_array<const N: usize>(cursor: &mut Cursor<&[u8]>) -> Result<[u8; N], &'static str> {
    let mut value = [0u8; N];
    cursor
        .read_exact(&mut value)
        .map_err(|_| "truncated block")?;
    Ok(value)
}

fn read_bounded(cursor: &mut Cursor<&[u8]>, limit: usize) -> Result<Vec<u8>, &'static str> {
    let len = u32::from_le_bytes(read_array(cursor)?) as usize;
    if len > limit {
        return Err("oversized block field");
    }
    let mut value = vec![0u8; len];
    cursor
        .read_exact(&mut value)
        .map_err(|_| "truncated block")?;
    Ok(value)
}

fn scheduled_reward_at_height(height: u64) -> u64 {
    if height == 0 || height > EMISSION_BLOCKS {
        return 0;
    }
    let current = (height as u128 * MINING_ALLOCATION_NOX as u128) / EMISSION_BLOCKS as u128;
    let previous = ((height - 1) as u128 * MINING_ALLOCATION_NOX as u128) / EMISSION_BLOCKS as u128;
    (current - previous) as u64
}

pub fn treasury_mining_reward_at_height(height: u64) -> u64 {
    if crate::network::IS_MAINNET && height >= MINING_REWARD_SPLIT_ACTIVATION_HEIGHT {
        scheduled_reward_at_height(height) / 10
    } else {
        0
    }
}

pub fn reward_at_height(height: u64) -> u64 {
    scheduled_reward_at_height(height) - treasury_mining_reward_at_height(height)
}

fn valid_reward(output: &FundedOutput, expected_nox: u64) -> bool {
    output.amount.asset_id == crate::assets::TNB_ASSET_ID && output.verify_public()
        && output.amount.commitment
            == PedersenGens::default()
                .commit(Scalar::from(expected_nox), Scalar::ZERO)
                .compress()
                .to_bytes()
}

#[derive(Clone, Debug)]
pub struct Block {
    pub height: u64,
    pub previous_hash: Hash,
    pub timestamp: u64,
    pub reward_nox: u64,
    pub reward_output: FundedOutput,
    pub nonce: u64,
}

impl Block {
    /// Fixed field order and little-endian lengths define the v2 block encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"TSC-1:local:block:v2");
        bytes.extend_from_slice(&self.height.to_le_bytes());
        bytes.extend_from_slice(&self.previous_hash);
        bytes.extend_from_slice(&self.timestamp.to_le_bytes());
        bytes.extend_from_slice(&self.reward_nox.to_le_bytes());
        bytes.extend_from_slice(&self.reward_output.encode_canonical());
        bytes.extend_from_slice(&self.nonce.to_le_bytes());
        bytes
    }

    pub fn hash(&self) -> Hash {
        Sha256::digest(self.encode()).into()
    }

    pub fn reward_output_id(&self) -> Hash {
        let mut hash = Sha256::new();
        hash.update(b"TSC-1:reward-output-id:v2");
        hash.update(self.hash());
        hash.update(0u32.to_le_bytes());
        hash.finalize().into()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        let mut cursor = Cursor::new(bytes);
        let tag: [u8; 20] = read_array(&mut cursor)?;
        if &tag != b"TSC-1:local:block:v2" {
            return Err("wrong block version");
        }
        let height = u64::from_le_bytes(read_array(&mut cursor)?);
        let previous_hash = read_array(&mut cursor)?;
        let timestamp = u64::from_le_bytes(read_array(&mut cursor)?);
        let reward_nox = u64::from_le_bytes(read_array(&mut cursor)?);
        let ephemeral = read_array(&mut cursor)?;
        let destination = read_array(&mut cursor)?;
        let commitment = read_array(&mut cursor)?;
        let range_proof = read_bounded(&mut cursor, 1024)?;
        let note_nonce = read_array(&mut cursor)?;
        let encrypted_note = read_bounded(&mut cursor, 56)?;
        let nonce = u64::from_le_bytes(read_array(&mut cursor)?);
        if cursor.position() != bytes.len() as u64 {
            return Err("trailing block data");
        }
        Ok(Self {
            height,
            previous_hash,
            timestamp,
            reward_nox,
            reward_output: FundedOutput {
                destination: OneTimeOutput {
                    ephemeral,
                    destination,
                },
                amount: ProvenAmount {
                    asset_id: crate::assets::TNB_ASSET_ID,
                    commitment,
                    range_proof,
                },
                note_nonce,
                encrypted_note,
            },
            nonce,
        })
    }

    pub fn mine(&mut self) -> Result<(), &'static str> {
        if self.mine_with_control(|| true)? {
            Ok(())
        } else {
            Err("mining cancelled")
        }
    }

    pub fn mine_with_control<F>(&mut self, mut should_continue: F) -> Result<bool, &'static str>
    where
        F: FnMut() -> bool,
    {
        if self.height == 0 {
            return Err("genesis is not mined");
        }
        let mut checks_remaining = 0;
        loop {
            if checks_remaining == 0 {
                if !should_continue() {
                    return Ok(false);
                }
                checks_remaining = 256;
            }
            checks_remaining -= 1;
            if self.hash()[0] == 0 {
                return Ok(true);
            }
            self.nonce = self.nonce.checked_add(1).ok_or("nonce exhausted")?;
        }
    }
}

#[derive(Clone, Debug)]
pub struct Chain {
    blocks: Vec<Block>,
    issued_nox: u64,
    reward_destinations: HashSet<[u8; 32]>,
    reward_ephemerals: HashSet<[u8; 32]>,
}

impl Chain {
    pub fn new(founder_output: FundedOutput, timestamp: u64) -> Result<Self, &'static str> {
        Self::from_genesis(Block {
            height: 0,
            previous_hash: [0; 32],
            timestamp,
            reward_nox: FOUNDER_ALLOCATION_NOX,
            reward_output: founder_output,
            nonce: 0,
        })
    }

    pub fn from_genesis(genesis: Block) -> Result<Self, &'static str> {
        if genesis.height != 0
            || genesis.previous_hash != [0; 32]
            || genesis.reward_nox != FOUNDER_ALLOCATION_NOX
            || genesis.nonce != 0
            || !valid_reward(&genesis.reward_output, FOUNDER_ALLOCATION_NOX)
        {
            return Err("invalid genesis");
        }
        Ok(Self {
            reward_destinations: HashSet::from([genesis.reward_output.destination.destination]),
            reward_ephemerals: HashSet::from([genesis.reward_output.destination.ephemeral]),
            blocks: vec![genesis],
            issued_nox: FOUNDER_ALLOCATION_NOX,
        })
    }

    pub fn height(&self) -> u64 {
        self.blocks.last().expect("genesis exists").height
    }

    pub fn tip_timestamp(&self) -> u64 {
        self.blocks.last().expect("genesis exists").timestamp
    }

    pub fn issued_nox(&self) -> u64 {
        self.issued_nox
    }

    pub fn tip_hash(&self) -> Hash {
        self.blocks.last().expect("genesis exists").hash()
    }

    pub fn genesis_hash(&self) -> Hash {
        self.blocks[0].hash()
    }

    pub fn genesis_block(&self) -> &Block {
        &self.blocks[0]
    }

    pub fn blocks(&self) -> &[Block] {
        &self.blocks
    }

    pub fn lookup_reward_output(&self, id: &Hash) -> Option<&FundedOutput> {
        self.blocks
            .iter()
            .find(|block| block.reward_output_id() == *id)
            .map(|block| &block.reward_output)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"TSC1CHAIN2");
        bytes.extend_from_slice(&(self.blocks.len() as u32).to_le_bytes());
        for block in &self.blocks {
            let encoded = block.encode();
            bytes.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&encoded);
        }
        bytes
    }

    pub fn decode(bytes: &[u8], expected_genesis: Hash) -> Result<Self, &'static str> {
        let mut cursor = Cursor::new(bytes);
        let tag: [u8; 10] = read_array(&mut cursor)?;
        if &tag != b"TSC1CHAIN2" {
            return Err("wrong chain version");
        }
        let count = u32::from_le_bytes(read_array(&mut cursor)?) as usize;
        if count == 0 || count > 1_000_000 {
            return Err("invalid block count");
        }
        let genesis = Block::decode(&read_bounded(&mut cursor, 2048)?)?;
        if genesis.hash() != expected_genesis {
            return Err("genesis hash mismatch");
        }
        let mut chain = Self::from_genesis(genesis)?;
        for _ in 1..count {
            let block = Block::decode(&read_bounded(&mut cursor, 2048)?)?;
            chain.append(block)?;
        }
        if cursor.position() != bytes.len() as u64 {
            return Err("trailing chain data");
        }
        Ok(chain)
    }

    pub fn next_block(&self, reward_output: FundedOutput, timestamp: u64) -> Block {
        let height = self.height() + 1;
        Block {
            height,
            previous_hash: self.tip_hash(),
            timestamp,
            reward_nox: reward_at_height(height),
            reward_output,
            nonce: 0,
        }
    }

    pub fn append(&mut self, block: Block) -> Result<(), &'static str> {
        let previous = self.blocks.last().ok_or("missing genesis")?;
        if block.height != previous.height + 1 || block.previous_hash != previous.hash() {
            return Err("invalid block link");
        }
        if block.timestamp <= previous.timestamp {
            return Err("invalid timestamp");
        }
        if block.reward_nox != reward_at_height(block.height)
            || !valid_reward(&block.reward_output, block.reward_nox)
        {
            return Err("invalid reward output");
        }
        if self.reward_destinations.contains(&block.reward_output.destination.destination)
            || self.reward_ephemerals.contains(&block.reward_output.destination.ephemeral)
        {
            return Err("reused reward output");
        }
        if block.hash()[0] != 0 {
            return Err("insufficient proof of work");
        }
        let issued = self
            .issued_nox
            .checked_add(block.reward_nox)
            .ok_or("issuance overflow")?;
        if issued > MAX_SUPPLY_NOX {
            return Err("maximum supply exceeded");
        }
        self.reward_destinations.insert(block.reward_output.destination.destination);
        self.reward_ephemerals.insert(block.reward_output.destination.ephemeral);
        self.issued_nox = issued;
        self.blocks.push(block);
        Ok(())
    }

    pub fn append_wallet_reward(&mut self, block: Block) -> Result<(), &'static str> {
        self.append_wallet_reward_with_treasury_reward(block, 0)
    }

    pub fn append_wallet_reward_with_treasury_reward(
        &mut self,
        block: Block,
        treasury_reward_nox: u64,
    ) -> Result<(), &'static str> {
        let previous = self.blocks.last().ok_or("missing genesis")?;
        if block.height != previous.height + 1 || block.previous_hash != previous.hash() {
            return Err("invalid block link");
        }
        if treasury_reward_nox != treasury_mining_reward_at_height(block.height) {
            return Err("invalid treasury mining reward");
        }
        if block.timestamp <= previous.timestamp {
            return Err("invalid timestamp");
        }
        if block.reward_nox != reward_at_height(block.height)
            || !valid_reward(&block.reward_output, block.reward_nox)
        {
            return Err("invalid reward output");
        }
        if self
            .reward_destinations
            .contains(&block.reward_output.destination.destination)
            || self
                .reward_ephemerals
                .contains(&block.reward_output.destination.ephemeral)
        {
            return Err("reused reward output");
        }
        if block.hash()[0] != 0 {
            return Err("insufficient proof of work");
        }
        let total_reward = block
            .reward_nox
            .checked_add(treasury_reward_nox)
            .ok_or("issuance overflow")?;
        let issued = self
            .issued_nox
            .checked_add(total_reward)
            .ok_or("issuance overflow")?;
        if issued > MAX_SUPPLY_NOX {
            return Err("maximum supply exceeded");
        }
        self.reward_destinations
            .insert(block.reward_output.destination.destination);
        self.reward_ephemerals
            .insert(block.reward_output.destination.ephemeral);
        self.issued_nox = issued;
        self.blocks.push(block);
        Ok(())
    }

    pub fn verify(&self) -> Result<(), &'static str> {
        let genesis = self.blocks.first().ok_or("missing genesis")?.clone();
        let mut rebuilt = Self::from_genesis(genesis)?;
        for block in self.blocks.iter().skip(1) {
            rebuilt.append(block.clone())?;
        }
        if rebuilt.issued_nox != self.issued_nox {
            return Err("issuance mismatch");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::WalletSecrets;
    use crate::tsc1_funded_output::{create_funded_output, create_reward_output};

    #[test]
    fn funded_genesis_and_mined_reward_validate() {
        let founder = WalletSecrets::generate().unwrap();
        let miner = WalletSecrets::generate().unwrap();
        let genesis = create_reward_output(&founder.address(), 0, FOUNDER_ALLOCATION_NOX).unwrap();
        let mut chain = Chain::new(genesis, 1).unwrap();
        let reward = create_reward_output(&miner.address(), 0, reward_at_height(1)).unwrap();
        let mut block = chain.next_block(reward, 2);
        block.mine().unwrap();
        chain.append(block).unwrap();
        assert_eq!(chain.height(), 1);
        assert_eq!(
            chain.issued_nox(),
            FOUNDER_ALLOCATION_NOX + reward_at_height(1)
        );
        assert!(chain.verify().is_ok());
    }

    #[test]
    fn mainnet_reward_split_activates_at_height_22000_and_preserves_issuance() {
        let before = MINING_REWARD_SPLIT_ACTIVATION_HEIGHT - 1;
        let activation = MINING_REWARD_SPLIT_ACTIVATION_HEIGHT;
        assert_eq!(treasury_mining_reward_at_height(before), 0);
        if crate::network::IS_MAINNET {
            let treasury = treasury_mining_reward_at_height(activation);
            assert_eq!(treasury, scheduled_reward_at_height(activation) / 10);
            assert_eq!(
                reward_at_height(activation) + treasury,
                scheduled_reward_at_height(activation)
            );
        } else {
            assert_eq!(treasury_mining_reward_at_height(activation), 0);
            assert_eq!(reward_at_height(activation), scheduled_reward_at_height(activation));
        }
    }

    #[test]
    fn rejects_hidden_overissuance_and_reused_reward() {
        let wallet = WalletSecrets::generate().unwrap();
        let genesis = create_reward_output(&wallet.address(), 0, FOUNDER_ALLOCATION_NOX).unwrap();
        let mut chain = Chain::new(genesis.clone(), 1).unwrap();
        let excess = create_funded_output(&wallet.address(), 1, reward_at_height(1) + 1).unwrap();
        let mut block = chain.next_block(excess, 2);
        block.mine().unwrap();
        assert_eq!(chain.append(block), Err("invalid reward output"));

        let mut reused_output =
            create_reward_output(&wallet.address(), 0, reward_at_height(1)).unwrap();
        reused_output.destination = genesis.destination;
        let mut reused = chain.next_block(reused_output, 2);
        reused.mine().unwrap();
        assert_eq!(chain.append(reused), Err("reused reward output"));
        assert_eq!(chain.height(), 0);
    }

    #[test]
    fn encoded_chain_requires_exact_genesis_and_complete_bytes() {
        let founder = WalletSecrets::generate().unwrap();
        let genesis = create_reward_output(&founder.address(), 0, FOUNDER_ALLOCATION_NOX).unwrap();
        let chain = Chain::new(genesis, 1).unwrap();
        let encoded = chain.encode();
        let decoded = Chain::decode(&encoded, chain.genesis_hash()).unwrap();
        assert_eq!(decoded.tip_hash(), chain.tip_hash());
        let output_id = chain.genesis_block().reward_output_id();
        assert_eq!(decoded.genesis_block().reward_output_id(), output_id);
        assert!(decoded.lookup_reward_output(&output_id).is_some());
        assert_eq!(decoded.issued_nox(), FOUNDER_ALLOCATION_NOX);
        assert!(Chain::decode(&encoded, [0; 32]).is_err());
        assert!(Chain::decode(&encoded[..encoded.len() - 1], chain.genesis_hash()).is_err());
        let mut extended = encoded;
        extended.push(0);
        assert!(Chain::decode(&extended, chain.genesis_hash()).is_err());
    }
}
