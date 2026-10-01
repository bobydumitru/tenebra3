//! Local TSC-1 proof-of-work chain. Payments are deliberately disabled.
//! Fixed 8-bit difficulty is for tests only; there is no P2P consensus yet.

use curve25519_dalek::ristretto::CompressedRistretto;
use sha2::{Digest, Sha256};
use tenebra::OneTimeOutput;

pub const NOX_PER_TNB: u64 = 1_000_000_000;
pub const MAX_SUPPLY_NOX: u64 = 100_000_000 * NOX_PER_TNB;
pub const FOUNDER_NOX: u64 = 10_000_000 * NOX_PER_TNB;
pub const MINING_POOL_NOX: u64 = 90_000_000 * NOX_PER_TNB;
pub const TARGET_BLOCK_SECONDS: u64 = 30;
pub const EMISSION_BLOCKS: u64 = 50 * 365 * 24 * 60 * 60 / TARGET_BLOCK_SECONDS;

pub type Hash = [u8; 32];

pub fn reward_at_height(height: u64) -> u64 {
    if height == 0 || height > EMISSION_BLOCKS {
        return 0;
    }
    let current = (height as u128 * MINING_POOL_NOX as u128) / EMISSION_BLOCKS as u128;
    let previous = ((height - 1) as u128 * MINING_POOL_NOX as u128) / EMISSION_BLOCKS as u128;
    (current - previous) as u64
}

fn valid_output(output: &OneTimeOutput) -> bool {
    let ephemeral = CompressedRistretto(output.ephemeral).decompress();
    let destination = CompressedRistretto(output.destination).decompress();
    match (ephemeral, destination) {
        (Some(ephemeral), Some(destination)) => {
            ephemeral != Default::default() && destination != Default::default()
        }
        _ => false,
    }
}

fn meets_difficulty(hash: &Hash) -> bool {
    hash[0] == 0 // Exactly 8 leading zero bits in this local prototype.
}

#[derive(Clone, Debug)]
pub struct Block {
    pub height: u64,
    pub previous_hash: Hash,
    pub timestamp: u64,
    pub reward_nox: u64,
    pub reward_output: OneTimeOutput,
    pub nonce: u64,
}

impl Block {
    pub fn hash(&self) -> Hash {
        let mut hasher = Sha256::new();
        hasher.update(b"TSC-1:local:block:v1");
        hasher.update(self.height.to_le_bytes());
        hasher.update(self.previous_hash);
        hasher.update(self.timestamp.to_le_bytes());
        hasher.update(self.reward_nox.to_le_bytes());
        hasher.update(self.reward_output.ephemeral);
        hasher.update(self.reward_output.destination);
        hasher.update(self.nonce.to_le_bytes());
        hasher.finalize().into()
    }

    pub fn mine(&mut self) -> Result<(), &'static str> {
        if self.height == 0 {
            return Err("genesis is not mined");
        }
        loop {
            if meets_difficulty(&self.hash()) {
                return Ok(());
            }
            self.nonce = self.nonce.checked_add(1).ok_or("nonce exhausted")?;
        }
    }
}

#[derive(Clone, Debug)]
pub struct Chain {
    blocks: Vec<Block>,
    issued_nox: u64,
}

impl Chain {
    pub fn new(founder_output: OneTimeOutput, timestamp: u64) -> Result<Self, &'static str> {
        let genesis = Block {
            height: 0,
            previous_hash: [0; 32],
            timestamp,
            reward_nox: FOUNDER_NOX,
            reward_output: founder_output,
            nonce: 0,
        };
        Self::from_genesis(genesis)
    }

    fn from_genesis(genesis: Block) -> Result<Self, &'static str> {
        if genesis.height != 0
            || genesis.previous_hash != [0; 32]
            || genesis.reward_nox != FOUNDER_NOX
            || genesis.nonce != 0
            || !valid_output(&genesis.reward_output)
        {
            return Err("invalid genesis");
        }
        Ok(Self {
            blocks: vec![genesis],
            issued_nox: FOUNDER_NOX,
        })
    }

    pub fn height(&self) -> u64 {
        self.blocks.last().expect("genesis exists").height
    }

    pub fn issued_nox(&self) -> u64 {
        self.issued_nox
    }

    pub fn tip_hash(&self) -> Hash {
        self.blocks.last().expect("genesis exists").hash()
    }

    pub fn next_block(&self, reward_output: OneTimeOutput, timestamp: u64) -> Block {
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
        if block.reward_nox != reward_at_height(block.height) {
            return Err("invalid mining reward");
        }
        if !valid_output(&block.reward_output)
            || self
                .blocks
                .iter()
                .any(|known| known.reward_output.destination == block.reward_output.destination)
        {
            return Err("invalid or reused reward output");
        }
        if !meets_difficulty(&block.hash()) {
            return Err("insufficient proof of work");
        }
        let issued = self
            .issued_nox
            .checked_add(block.reward_nox)
            .ok_or("issuance overflow")?;
        if issued > MAX_SUPPLY_NOX {
            return Err("maximum supply exceeded");
        }
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
    use tenebra::{WalletSecrets, create_output};

    fn output() -> OneTimeOutput {
        let wallet = WalletSecrets::generate().unwrap();
        create_output(&wallet.address(), 0).unwrap()
    }

    #[test]
    fn emission_never_exceeds_cap() {
        assert_eq!(FOUNDER_NOX + MINING_POOL_NOX, MAX_SUPPLY_NOX);
        assert_eq!(reward_at_height(0), 0);
        assert_eq!(reward_at_height(EMISSION_BLOCKS + 1), 0);
        let final_total =
            (EMISSION_BLOCKS as u128 * MINING_POOL_NOX as u128) / EMISSION_BLOCKS as u128;
        assert_eq!(final_total as u64, MINING_POOL_NOX);
    }

    #[test]
    fn mines_and_validates_two_blocks() {
        let mut chain = Chain::new(output(), 1).unwrap();
        for timestamp in [2, 3] {
            let mut block = chain.next_block(output(), timestamp);
            block.mine().unwrap();
            chain.append(block).unwrap();
        }
        assert_eq!(chain.height(), 2);
        assert_eq!(
            chain.issued_nox(),
            FOUNDER_NOX + reward_at_height(1) + reward_at_height(2)
        );
        assert!(chain.verify().is_ok());
    }

    #[test]
    fn rejects_wrong_reward_even_when_mined() {
        let mut chain = Chain::new(output(), 1).unwrap();
        let mut block = chain.next_block(output(), 2);
        block.reward_nox += 1;
        block.mine().unwrap();
        assert_eq!(chain.append(block), Err("invalid mining reward"));
    }

    #[test]
    fn rejects_broken_link_and_duplicate_output() {
        let reused = output();
        let mut chain = Chain::new(reused, 1).unwrap();
        let mut broken = chain.next_block(output(), 2);
        broken.previous_hash = [1; 32];
        broken.mine().unwrap();
        assert_eq!(chain.append(broken), Err("invalid block link"));

        let mut duplicate = chain.next_block(reused, 2);
        duplicate.mine().unwrap();
        assert_eq!(
            chain.append(duplicate),
            Err("invalid or reused reward output")
        );
    }

    #[test]
    fn rejects_tampered_chain() {
        let mut chain = Chain::new(output(), 1).unwrap();
        let mut block = chain.next_block(output(), 2);
        block.mine().unwrap();
        chain.append(block).unwrap();
        chain.blocks[0].reward_nox += 1;
        assert_eq!(chain.verify(), Err("invalid genesis"));
    }
}
