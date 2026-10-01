//! Build-time separation between the public mainnet build and the legacy devnet.
use crate::tsc1_chain_v2::Chain;
use std::path::PathBuf;

pub const IS_MAINNET: bool = cfg!(feature = "mainnet-candidate");
pub const NAME: &str = if IS_MAINNET {
    "mainnet-candidate"
} else {
    "devnet-v3f"
};
pub const TX_DOMAIN: &[u8] = if IS_MAINNET {
    b"TENEBRA:mainnet:v1:network-id"
} else {
    b"TSC-1:v3f-network-id"
};
pub const PEER_MAGIC: &[u8; 8] = if IS_MAINNET { b"TNBMN001" } else { b"TSC1P3V8" };
pub const MAINNET_GENESIS_HASH: &str =
    "58ed7d7dcf4c173a25059585f1b06489a190ee8f42e2e03d5a88b69af65d0652";

pub fn variable(suffix: &str) -> String {
    format!(
        "{}_{suffix}",
        if IS_MAINNET {
            "TENEBRA_MAINNET"
        } else {
            "TSC1_DEVNET_V3"
        }
    )
}

pub fn blocks_dir() -> PathBuf {
    std::env::var_os(variable("BLOCKS_DIR"))
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("data")
                .join(NAME)
                .join("blocks")
        })
}

pub fn pinned_genesis() -> Result<Chain, Box<dyn std::error::Error>> {
    if !IS_MAINNET {
        return crate::tsc1_devnet_v2::pinned_genesis();
    }
    let encoded = include_str!("../config/mainnet-genesis.hex")
        .lines()
        .find(|line| !line.is_empty() && !line.starts_with('#'))
        .ok_or("missing mainnet genesis")?;
    let block = crate::tsc1_chain_v2::Block::decode(&hex::decode(encoded)?)?;
    let chain = Chain::from_genesis(block)?;
    if hex::encode(chain.genesis_hash()) != MAINNET_GENESIS_HASH {
        return Err("mainnet genesis hash mismatch".into());
    }
    Ok(chain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    #[test]
    fn selected_transaction_domain_matches_genesis() {
        let chain = pinned_genesis().unwrap();
        let mut hash = Sha256::new();
        hash.update(TX_DOMAIN);
        hash.update(chain.genesis_hash());
        let expected: [u8; 32] = hash.finalize().into();
        assert_eq!(crate::tsc1_tx_v2::NETWORK_ID, expected);
        assert_eq!(chain.issued_nox(), crate::FOUNDER_ALLOCATION_NOX);
        if IS_MAINNET {
            assert_ne!(
                chain.genesis_hash(),
                crate::tsc1_devnet_v2::pinned_genesis()
                    .unwrap()
                    .genesis_hash()
            );
            assert_ne!(PEER_MAGIC, b"TSC1P3V8");
            assert_eq!(variable("BLOCKS_DIR"), "TENEBRA_MAINNET_BLOCKS_DIR");
        }
    }
}
