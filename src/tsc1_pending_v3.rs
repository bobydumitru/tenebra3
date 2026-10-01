//! Bounded on-disk transaction inbox for a single v3 devnet node.

use crate::tsc1_chain_v3::ChainV3;
use crate::assets::SignedAssetTransaction;
use crate::tsc1_tx_v2::Transaction;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

pub const MAX_PENDING: usize = 16;
pub const MAX_TX_BYTES: usize = 512 * 1024;

pub fn pending_assets_dir(blocks_dir: &Path) -> Result<PathBuf, &'static str> {
    Ok(blocks_dir
        .parent()
        .ok_or("invalid blocks directory")?
        .join("pending-assets"))
}

pub fn load_pending_assets(
    blocks_dir: &Path,
) -> Result<Vec<SignedAssetTransaction>, Box<dyn std::error::Error>> {
    let directory = pending_assets_dir(blocks_dir)?;
    if !directory.exists() {
        return Ok(Vec::new());
    }
    let mut files: Vec<_> = fs::read_dir(&directory)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "bin"))
        .collect();
    files.sort();
    if files.len() > 256 {
        return Err("too many pending asset transactions".into());
    }
    let mut pending = Vec::with_capacity(files.len());
    for path in files {
        let bytes = fs::read(path)?;
        if bytes.len() < 96 || bytes.len() > 512 * 1024 {
            return Err("invalid pending asset transaction size".into());
        }
        let signed = SignedAssetTransaction::decode(&bytes)?;
        signed.verify()?;
        pending.push(signed);
    }
    Ok(pending)
}

pub fn accept_asset(blocks_dir: &Path, signed: &SignedAssetTransaction) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    signed.verify()?;
    let transaction_id = signed.transaction.txid()?;
    let directory = pending_assets_dir(blocks_dir)?;
    fs::create_dir_all(&directory)?;
    let path = directory.join(format!("{}.bin", hex::encode(transaction_id)));
    if path.exists() {
        return Err("asset transaction already pending".into());
    }
    let bytes = signed.encode()?;
    fs::write(path, bytes)?;
    Ok(transaction_id)
}

pub fn remove_included_assets(blocks_dir: &Path, transactions: &[SignedAssetTransaction]) -> Result<(), Box<dyn std::error::Error>> {
    let directory = pending_assets_dir(blocks_dir)?;
    for transaction in transactions {
        let path = directory.join(format!("{}.bin", hex::encode(transaction.transaction.txid()?)));
        if path.exists() {
            fs::remove_file(path)?;
        }
    }
    Ok(())
}

pub fn pending_dir(blocks_dir: &Path) -> Result<PathBuf, &'static str> {
    Ok(blocks_dir
        .parent()
        .ok_or("invalid blocks directory")?
        .join("pending"))
}

pub fn decode_signed(bytes: &[u8]) -> Result<Transaction, &'static str> {
    if bytes.is_empty() || bytes.len() > MAX_TX_BYTES {
        return Err("invalid signed transaction size");
    }
    let tx = Transaction::decode(bytes)?;
    if tx.encode()? != bytes {
        return Err("noncanonical signed transaction");
    }
    Ok(tx)
}

pub fn load_pending(
    blocks_dir: &Path,
    chain: &ChainV3,
) -> Result<Vec<Transaction>, Box<dyn std::error::Error>> {
    let directory = pending_dir(blocks_dir)?;
    if !directory.exists() {
        return Ok(Vec::new());
    }
    let mut files = Vec::new();
    for entry in fs::read_dir(&directory)? {
        let path = entry?.path();
        if path.extension().is_some_and(|ext| ext == "bin") {
            files.push(path);
        }
    }
    files.sort();
    if files.len() > MAX_PENDING {
        return Err("too many pending transactions".into());
    }
    let mut transactions = Vec::with_capacity(files.len());
    for path in files {
        if fs::metadata(&path)?.len() > MAX_TX_BYTES as u64 {
            return Err("oversized pending transaction".into());
        }
        let tx = decode_signed(&fs::read(&path)?)?;
        let name = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .ok_or("invalid pending transaction filename")?;
        if name != hex::encode(tx.txid()?) {
            return Err("pending transaction filename does not match txid".into());
        }
        transactions.push(tx);
    }
    let mut staged = chain.spends().clone();
    staged.apply_batch(&transactions, chain.height() + 1)?;
    Ok(transactions)
}

pub fn accept_transaction(
    blocks_dir: &Path,
    chain: &ChainV3,
    bytes: &[u8],
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let tx = decode_signed(bytes)?;
    let txid = tx.txid()?;
    let mut pending = load_pending(blocks_dir, chain)?;
    if pending.len() >= MAX_PENDING {
        return Err("pending transaction inbox is full".into());
    }
    pending.push(tx);
    let mut staged = chain.spends().clone();
    staged.apply_batch(&pending, chain.height() + 1)?;
    let directory = pending_dir(blocks_dir)?;
    fs::create_dir_all(&directory)?;
    let path = directory.join(format!("{}.bin", hex::encode(txid)));
    if path.exists() {
        return Err("transaction already pending".into());
    }
    let mut suffix = [0u8; 8];
    getrandom::getrandom(&mut suffix)?;
    let temporary = directory.join(format!("{}.{}.tmp", hex::encode(txid), hex::encode(suffix)));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    if let Err(error) = fs::rename(&temporary, &path) {
        let _ = fs::remove_file(&temporary);
        return Err(error.into());
    }
    Ok(txid)
}

pub fn remove_included(
    blocks_dir: &Path,
    transactions: &[Transaction],
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = pending_dir(blocks_dir)?;
    for tx in transactions {
        let path = directory.join(format!("{}.bin", hex::encode(tx.txid()?)));
        if path.exists() {
            fs::remove_file(path)?;
        }
    }
    Ok(())
}
