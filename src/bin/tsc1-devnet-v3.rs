// Shared node CLI; selected network is fixed at build time.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tenebra::Address;
use tenebra::network::pinned_genesis;
#[cfg(not(feature = "mainnet-candidate"))]
use tenebra::tsc1_chain_v2::reward_at_height;
use tenebra::tsc1_chain_v3::load_blocks;
#[cfg(not(feature = "mainnet-candidate"))]
use tenebra::tsc1_chain_v3::persist_block;
#[cfg(not(feature = "mainnet-candidate"))]
use tenebra::tsc1_funded_output::create_reward_output;
#[cfg(not(feature = "mainnet-candidate"))]
use tenebra::tsc1_peer_v3::sync;
use tenebra::tsc1_peer_v3::{relay_block, serve, submit};
#[cfg(not(feature = "mainnet-candidate"))]
use tenebra::tsc1_pending_v3::{load_pending, load_pending_assets, remove_included, remove_included_assets};
use tenebra::tsc1_tx_v2::Transaction;

const MAX_SIGNED_TX_BYTES: u64 = 512 * 1024;

fn decode_signed_transaction(bytes: &[u8]) -> Result<Transaction, Box<dyn std::error::Error>> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_SIGNED_TX_BYTES {
        return Err("invalid signed transaction size".into());
    }
    let transaction = Transaction::decode(bytes)?;
    if transaction.encode()? != bytes {
        return Err("noncanonical signed transaction".into());
    }
    Ok(transaction)
}

fn read_signed_transaction(path: &Path) -> Result<Transaction, Box<dyn std::error::Error>> {
    if fs::metadata(path)?.len() > MAX_SIGNED_TX_BYTES {
        return Err("signed transaction exceeds size limit".into());
    }
    decode_signed_transaction(&fs::read(path)?)
}

fn blocks_dir() -> PathBuf {
    tenebra::network::blocks_dir()
}

#[cfg(feature = "mainnet-candidate")]
fn mine_candidate(
    directory: &Path,
    address: &str,
    signed_tx_path: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut node = tenebra::candidate_node::NodeState::open(directory, pinned_genesis()?)?;
    let recipient = Address::parse(address)?;
    if let Some(path) = signed_tx_path {
        let tx = read_signed_transaction(Path::new(&path))?;
        node.accept_batch(&tenebra::candidate_node::encode_batch(&[tx])?)?;
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let timestamp =
        tenebra::candidate_node::mining_timestamp(now, node.chain().rewards().tip_timestamp())
            .ok_or("wait until wall clock is later than the chain tip before mining")?;
    let mut block = node.candidate(&recipient, timestamp)?;
    block.mine()?;
    node.import_block(block.clone())?;
    let (relayed, failed) = relay_block(&block).unwrap_or_else(|error| {
        eprintln!("block persisted; relay failed: {error}");
        (0, 1)
    });
    println!(
        "mined_height={} included_transactions={} relayed_blocks={relayed} relay_failed={failed}",
        node.chain().height(),
        block.transactions.len()
    );
    println!("tip_hash={}", hex::encode(node.chain().tip_hash()));
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let command = args.next();
    let parameter = args.next();
    let signed_tx_path = args.next();
    if args.next().is_some() {
        return Err("too many arguments".into());
    }
    let directory = blocks_dir();
    match (command.as_deref(), parameter, signed_tx_path) {
        (Some("status"), None, None) => {
            let chain = load_blocks(&directory, pinned_genesis()?)?;
            println!("network={}", tenebra::network::NAME);
            println!("height={}", chain.height());
            if !tenebra::network::IS_MAINNET {
                println!("devnet_v3_height={}", chain.height());
            }
            println!(
                "network_id={}",
                hex::encode(tenebra::tsc1_tx_v2::NETWORK_ID)
            );
            println!(
                "genesis_hash={}",
                hex::encode(chain.rewards().genesis_hash())
            );
            println!("tip_hash={}", hex::encode(chain.tip_hash()));
            println!("issued_nox={}", chain.rewards().issued_nox());
            Ok(())
        }
        (Some("mine"), Some(address), signed_tx_path) => {
            #[cfg(feature = "mainnet-candidate")]
            {
                mine_candidate(&directory, &address, signed_tx_path)
            }
            #[cfg(not(feature = "mainnet-candidate"))]
            {
                let mut chain = load_blocks(&directory, pinned_genesis()?)?;
                let recipient = Address::parse(&address)?;
                let height = chain.height() + 1;
                let from_pending = signed_tx_path.is_none();
                let transactions = match signed_tx_path {
                    Some(path) => vec![read_signed_transaction(Path::new(&path))?],
                    None => load_pending(&directory, &chain)?,
                };
                let asset_transactions = load_pending_assets(&directory)?;
                let mut candidate_spends = chain.spends().clone();
                candidate_spends.apply_batch(&transactions, height)?;
                let reward = create_reward_output(&recipient, 0, reward_at_height(height))?;
                let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
                let timestamp = now.max(chain.rewards().tip_timestamp() + 1);
                let mut block =
                    chain.next_block_with_fees(reward, &recipient, timestamp, transactions)?;
                block.asset_transactions = asset_transactions.clone();
                block.mine()?;
                chain.append(block.clone())?;
                persist_block(&directory, &block)?;
                if from_pending {
                    if let Err(error) = remove_included(&directory, &block.transactions) {
                        eprintln!("pending cleanup failed after block persistence: {error}");
                    }
                    if let Err(error) = remove_included_assets(&directory, &block.asset_transactions) {
                        eprintln!("pending asset cleanup failed after block persistence: {error}");
                    }
                }
                let (relayed, relay_failed) = match relay_block(&block) {
                    Ok(result) => result,
                    Err(error) => {
                        eprintln!("block persisted, but relay configuration failed: {error}");
                        (0, 1)
                    }
                };
                println!("mined_height={}", chain.height());
                println!("reward_nox={}", block.reward.reward_nox);
                println!("included_transactions={}", block.transactions.len());
                println!(
                    "total_fee_nox={}",
                    block.transactions.iter().map(|tx| tx.fee_nox).sum::<u64>()
                );
                println!("relayed_blocks={relayed}");
                println!("relay_failed={relay_failed}");
                println!("tip_hash={}", hex::encode(chain.tip_hash()));
                Ok(())
            }
        }
        (Some("serve"), Some(bind), None) => serve(&bind, &directory),
        #[cfg(feature = "mainnet-candidate")]
        (Some("submit-batch"), Some(peer), Some(path)) => {
            if fs::metadata(&path)?.len() > tenebra::candidate_node::MAX_BATCH_BYTES as u64 {
                return Err("batch file too large".into());
            }
            let ids = tenebra::candidate_node::submit_batch(&peer, &fs::read(path)?)?;
            println!("accepted_transactions={}", ids.len());
            Ok(())
        }
        #[cfg(feature = "mainnet-candidate")]
        (Some("peer-status"), Some(peer), None) => {
            let (height, tip, confirmed, pending) = tenebra::candidate_node::query_status(&peer)?;
            println!(
                "height={height} tip={} confirmed_transactions={confirmed} pending={pending}",
                hex::encode(tip)
            );
            Ok(())
        }
        (Some("submit"), Some(peer), Some(path)) => {
            let tx = read_signed_transaction(Path::new(&path))?;
            let txid = submit(&peer, &tx.encode()?)?;
            println!("submitted_txid={}", hex::encode(txid));
            Ok(())
        }
        (Some("sync"), Some(peer), None) => {
            #[cfg(feature = "mainnet-candidate")]
            let added = tenebra::candidate_node::sync_directory(&peer, &directory)?;
            #[cfg(not(feature = "mainnet-candidate"))]
            let added = sync(&peer, &directory)?;
            println!("synced_blocks={added}");
            Ok(())
        }
        _ => {
            let binary = if tenebra::network::IS_MAINNET {
                "tenebra-node"
            } else {
                "tsc1-devnet-v3"
            };
            let extra = if tenebra::network::IS_MAINNET {
                " | submit-batch <peer_address> <batch.bin> | peer-status <peer_address>"
            } else {
                ""
            };
            Err(format!("usage: {binary} status | mine <tsc1_public_address> [signed_transaction.bin] | serve <bind_address> | submit <peer_address> <signed_transaction.bin> | sync <peer_address>{extra}").into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenebra::WalletSecrets;
    use tenebra::tsc1_funded_output::create_funded_output;
    use tenebra::tsc1_tx_v2::{NETWORK_ID, RING_SIZE, RingInput};

    #[test]
    fn rejects_empty_and_oversized_signed_transaction_files() {
        assert!(decode_signed_transaction(&[]).is_err());
        assert!(decode_signed_transaction(&vec![0; MAX_SIGNED_TX_BYTES as usize + 1]).is_err());
        assert!(decode_signed_transaction(b"not a transaction").is_err());
    }

    #[test]
    fn accepts_canonical_signed_transaction_encoding() {
        let wallet = WalletSecrets::from_seed(&[77; 32]);
        let output = create_funded_output(&wallet.address(), 0, 1).unwrap();
        let transaction = Transaction {
            network_id: NETWORK_ID,
            version: 1,
            expires_at_height: 10,
            inputs: vec![RingInput {
                asset_id: tenebra::assets::TNB_ASSET_ID,
                members: [[0; 32]; RING_SIZE],
                key_image: [0; 32],
                pseudo_output: [0; 32],
                authorization: vec![1; 32],
            }],
            outputs: vec![output],
            fee_nox: 1,
        };
        let encoded = transaction.encode().unwrap();
        let decoded = decode_signed_transaction(&encoded).unwrap();
        assert_eq!(decoded.encode().unwrap(), encoded);
    }
}
