//! Persistent local candidate-spend journal; records are not confirmed blocks.

use crate::tsc1_chain_v2::{Chain, Hash};
use crate::tsc1_spend_state_v2::SpendState;
use crate::tsc1_tx_v2::Transaction;
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{Cursor, Read, Write};
use std::path::Path;

const TAG: &[u8; 12] = b"TSC1JOURNAL1";
const MAX_RECORD_BYTES: usize = 4 * 1024 * 1024;
const MAX_TX_BYTES: usize = 512 * 1024;
const MAX_TXS: usize = 16;

pub struct JournalState {
    pub spends: SpendState,
    pub record_count: u64,
    pub last_hash: Hash,
}

struct Record {
    previous_hash: Hash,
    anchor_height: u64,
    anchor_hash: Hash,
    transactions: Vec<Transaction>,
}

fn take<const N: usize>(cursor: &mut Cursor<&[u8]>) -> Result<[u8; N], &'static str> {
    let mut bytes = [0; N];
    cursor
        .read_exact(&mut bytes)
        .map_err(|_| "truncated spend record")?;
    Ok(bytes)
}

impl Record {
    fn encode(&self) -> Result<Vec<u8>, &'static str> {
        if self.transactions.is_empty() || self.transactions.len() > MAX_TXS {
            return Err("invalid spend record transaction count");
        }
        let mut bytes = Vec::new();
        bytes.extend_from_slice(TAG);
        bytes.extend_from_slice(&self.previous_hash);
        bytes.extend_from_slice(&self.anchor_height.to_le_bytes());
        bytes.extend_from_slice(&self.anchor_hash);
        bytes.extend_from_slice(&(self.transactions.len() as u16).to_le_bytes());
        for tx in &self.transactions {
            let encoded = tx.encode()?;
            if encoded.len() > MAX_TX_BYTES {
                return Err("oversized journal transaction");
            }
            bytes.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&encoded);
        }
        if bytes.len() > MAX_RECORD_BYTES {
            return Err("oversized spend record");
        }
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() > MAX_RECORD_BYTES {
            return Err("oversized spend record");
        }
        let mut cursor = Cursor::new(bytes);
        if &take::<12>(&mut cursor)? != TAG {
            return Err("wrong spend record format");
        }
        let previous_hash = take(&mut cursor)?;
        let anchor_height = u64::from_le_bytes(take(&mut cursor)?);
        let anchor_hash = take(&mut cursor)?;
        let count = u16::from_le_bytes(take(&mut cursor)?) as usize;
        if count == 0 || count > MAX_TXS {
            return Err("invalid spend record transaction count");
        }
        let mut transactions = Vec::with_capacity(count);
        for _ in 0..count {
            let len = u32::from_le_bytes(take(&mut cursor)?) as usize;
            if len == 0 || len > MAX_TX_BYTES {
                return Err("invalid journal transaction length");
            }
            let mut encoded = vec![0; len];
            cursor
                .read_exact(&mut encoded)
                .map_err(|_| "truncated spend record")?;
            transactions.push(Transaction::decode(&encoded)?);
        }
        if cursor.position() != bytes.len() as u64 {
            return Err("trailing spend record bytes");
        }
        Ok(Self {
            previous_hash,
            anchor_height,
            anchor_hash,
            transactions,
        })
    }
}

fn record_hash(bytes: &[u8]) -> Hash {
    let mut hash = Sha256::new();
    hash.update(b"TSC-1:spend-journal-record:v1");
    hash.update(bytes);
    hash.finalize().into()
}

pub fn load(chain: &Chain, directory: &Path) -> Result<JournalState, Box<dyn std::error::Error>> {
    let mut state = JournalState {
        spends: SpendState::from_reward_chain(chain),
        record_count: 0,
        last_hash: [0; 32],
    };
    if !directory.exists() {
        return Ok(state);
    }
    let mut files = Vec::new();
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.extension().is_some_and(|ext| ext == "bin") {
            let index: u64 = path
                .file_stem()
                .ok_or("invalid record filename")?
                .to_str()
                .ok_or("invalid record filename")?
                .parse()?;
            files.push((index, path));
        }
    }
    files.sort_by_key(|(index, _)| *index);
    for (index, path) in files {
        if index != state.record_count + 1 {
            return Err("missing or duplicate spend record".into());
        }
        if fs::metadata(&path)?.len() > MAX_RECORD_BYTES as u64 {
            return Err("oversized spend record".into());
        }
        let encoded = fs::read(path)?;
        let record = Record::decode(&encoded)?;
        if record.previous_hash != state.last_hash {
            return Err("broken spend journal link".into());
        }
        let anchor_index: usize = record.anchor_height.try_into()?;
        if chain.blocks().get(anchor_index).map(|block| block.hash()) != Some(record.anchor_hash) {
            return Err("spend journal chain anchor mismatch".into());
        }
        state
            .spends
            .apply_batch(&record.transactions, record.anchor_height + 1)?;
        state.record_count = index;
        state.last_hash = record_hash(&encoded);
    }
    Ok(state)
}

pub fn append(
    chain: &Chain,
    directory: &Path,
    transactions: &[Transaction],
) -> Result<JournalState, Box<dyn std::error::Error>> {
    let mut state = load(chain, directory)?;
    state.spends.apply_batch(transactions, chain.height() + 1)?;
    let record = Record {
        previous_hash: state.last_hash,
        anchor_height: chain.height(),
        anchor_hash: chain.tip_hash(),
        transactions: transactions.to_vec(),
    };
    let encoded = record.encode()?;
    fs::create_dir_all(directory)?;
    let index = state.record_count + 1;
    let target = directory.join(format!("{index:020}.bin"));
    if target.exists() {
        return Err("spend record already persisted".into());
    }
    let mut suffix = [0u8; 8];
    getrandom::getrandom(&mut suffix)?;
    let temporary = directory.join(format!("{index:020}.{}.tmp", hex::encode(suffix)));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    file.write_all(&encoded)?;
    file.sync_all()?;
    drop(file);
    fs::rename(temporary, target)?;
    state.record_count = index;
    state.last_hash = record_hash(&encoded);
    Ok(state)
}
