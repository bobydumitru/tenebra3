//! Pinned local devnet v2 state shared by the miner and wallet.

use crate::tsc1_chain_v2::{Block, Chain, Hash, reward_at_height};
use crate::tsc1_funded_output::create_reward_output;
use crate::{Address, WalletSecrets};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const GENESIS_HEX: &str = include_str!("../config/devnet-v2-genesis.hex");
pub const GENESIS_HASH: &str = "962ea954fe2344106531c67b6fcf391f0ff74d3e3b349b1e41fe8703ba168932";

pub fn default_blocks_dir() -> PathBuf {
    if let Some(configured) = std::env::var_os("TSC1_DEVNET_BLOCKS_DIR") {
        if !configured.is_empty() {
            return PathBuf::from(configured);
        }
    }
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("devnet-v2")
        .join("blocks")
}

pub struct MinedBlock {
    pub height: u64,
    pub reward_nox: u64,
    pub tip_hash: Hash,
}

pub fn pinned_genesis() -> Result<Chain, Box<dyn std::error::Error>> {
    let encoded = GENESIS_HEX
        .lines()
        .find(|line| !line.is_empty() && !line.starts_with('#'))
        .ok_or("missing genesis fixture")?;
    let block = Block::decode(&hex::decode(encoded)?)?;
    let chain = Chain::from_genesis(block)?;
    let expected: Hash = hex::decode(GENESIS_HASH)?
        .try_into()
        .map_err(|_| "bad genesis hash")?;
    if chain.genesis_hash() != expected {
        return Err("genesis fixture hash mismatch".into());
    }
    Ok(chain)
}

pub fn load_chain(blocks_dir: &Path) -> Result<Chain, Box<dyn std::error::Error>> {
    let mut chain = pinned_genesis()?;
    if !blocks_dir.exists() {
        return Ok(chain);
    }
    let mut files = Vec::new();
    for entry in fs::read_dir(blocks_dir)? {
        let path = entry?.path();
        if path.extension().is_some_and(|ext| ext == "bin") {
            let height: u64 = path
                .file_stem()
                .ok_or("invalid block file name")?
                .to_str()
                .ok_or("invalid block file name")?
                .parse()?;
            files.push((height, path));
        }
    }
    files.sort_by_key(|(height, _)| *height);
    for (height, path) in files {
        if height != chain.height() + 1 {
            return Err("missing or duplicate block height".into());
        }
        chain.append(Block::decode(&fs::read(path)?)?)?;
    }
    Ok(chain)
}

pub(crate) fn persist_block(
    blocks_dir: &Path,
    block: &Block,
) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(blocks_dir)?;
    let target = blocks_dir.join(format!("{:020}.bin", block.height));
    if target.exists() {
        return Err("block height already persisted".into());
    }
    let mut suffix = [0u8; 8];
    getrandom::getrandom(&mut suffix)?;
    let temporary = blocks_dir.join(format!("{:020}.{}.tmp", block.height, hex::encode(suffix)));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    file.write_all(&block.encode())?;
    file.sync_all()?;
    drop(file);
    fs::rename(temporary, target)?;
    Ok(())
}

pub fn mine_to(
    blocks_dir: &Path,
    recipient: &Address,
) -> Result<MinedBlock, Box<dyn std::error::Error>> {
    let mut chain = load_chain(blocks_dir)?;
    let height = chain.height() + 1;
    let output = create_reward_output(recipient, 0, reward_at_height(height))?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let timestamp = now.max(chain.tip_timestamp() + 1);
    let mut block = chain.next_block(output, timestamp);
    block.mine()?;
    chain.append(block.clone())?;
    persist_block(blocks_dir, &block)?;
    Ok(MinedBlock {
        height: chain.height(),
        reward_nox: block.reward_nox,
        tip_hash: chain.tip_hash(),
    })
}

pub fn wallet_reward_balance_nox(
    wallet: &WalletSecrets,
    chain: &Chain,
) -> Result<u64, &'static str> {
    let mut balance = 0u64;
    for block in chain.blocks() {
        if let Some(recovered) = wallet.scan_funded_output(&block.reward_output, 0) {
            balance = balance
                .checked_add(recovered.amount_nox)
                .ok_or("balance overflow")?;
        }
    }
    Ok(balance)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FOUNDER_ALLOCATION_NOX;
    use crate::tsc1_funded_output::create_reward_output;

    #[test]
    fn owner_scans_founder_reward_stranger_does_not() {
        let owner = WalletSecrets::from_seed(&[7; 32]);
        let stranger = WalletSecrets::from_seed(&[8; 32]);
        let output = create_reward_output(&owner.address(), 0, FOUNDER_ALLOCATION_NOX).unwrap();
        let chain = Chain::new(output, 1).unwrap();
        assert_eq!(
            wallet_reward_balance_nox(&owner, &chain),
            Ok(FOUNDER_ALLOCATION_NOX)
        );
        assert_eq!(wallet_reward_balance_nox(&stranger, &chain), Ok(0));
    }

    #[test]
    fn pinned_genesis_is_valid() {
        let chain = pinned_genesis().unwrap();
        assert_eq!(hex::encode(chain.genesis_hash()), GENESIS_HASH);
        assert_eq!(chain.issued_nox(), FOUNDER_ALLOCATION_NOX);
    }
}
