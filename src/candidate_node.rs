//! Public mainnet candidate runtime: one writer, cached validated state, bounded batches.
//! Passing local tests is not a mainnet launch approval or a throughput guarantee.
use crate::assets::SignedAssetTransaction;
use crate::dex::{MAX_DEX_OPERATION_BYTES, MAX_DEX_OPERATIONS, SignedDexOperation};
use crate::tsc1_chain_v2::{Chain, Hash, reward_at_height};
use crate::tsc1_chain_v3::{
    BlockV3, ChainV3, MAX_BLOCK_BYTES, MAX_TXS, load_blocks, persist_block,
    validate_asset_operation_fee,
};
use crate::tsc1_funded_output::create_reward_output;
use crate::tsc1_spend_state_v2::SpendState;
use crate::tsc1_tx_v2::Transaction;
use crate::{Address, network};
use std::{
    collections::{HashMap, HashSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
pub const MAX_BATCH_TXS: usize = 1_024;
pub const MAX_BATCH_BYTES: usize = 4 * 1024 * 1024;
const MAX_PENDING: usize = 18_000;
const MAX_PENDING_BYTES: usize = 64 * 1024 * 1024;
const MAX_PENDING_FILES: usize = 512;
const MINER_HASH_QUANTUM_CHECKS: usize = 16;
pub const CONFIRMATION_DEPTH: usize = 10;

/// Mine only at actual wall-clock time, strictly after the current tip.
/// This is miner policy, not a change to consensus timestamp validation.
pub fn mining_timestamp(now: u64, tip_timestamp: u64) -> Option<u64> {
    (now > tip_timestamp).then_some(now)
}

pub fn configured_duration_millis(key: &str, default_ms: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default_ms)
}

fn configured_miner_addresses() -> Result<Vec<String>> {
    if let Ok(path) = std::env::var(network::variable("MINER_ADDRESS_FILE")) {
        return match fs::read_to_string(path) {
            Ok(contents) => Ok(parse_miner_addresses(&contents)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(error) => Err(error.into()),
        };
    }
    Ok(std::env::var(network::variable("MINER_ADDRESS"))
        .ok()
        .map(|address| address.trim().to_owned())
        .filter(|address| !address.is_empty())
        .into_iter()
        .collect())
}

fn parse_miner_addresses(contents: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    contents
        .lines()
        .map(str::trim)
        .filter(|address| !address.is_empty())
        .filter(|address| seen.insert((*address).to_owned()))
        .map(str::to_owned)
        .collect()
}

#[derive(Clone)]
struct MiningProgress {
    reward_nonce: u64,
    block_nonce: u64,
    generation: u64,
}

#[derive(Default)]
struct MiningScheduler {
    addresses: Vec<String>,
    active: HashSet<String>,
    leased: HashSet<String>,
    progress: HashMap<String, MiningProgress>,
    next: usize,
}

impl MiningScheduler {
    fn set_addresses(&mut self, addresses: Vec<String>) {
        self.active = addresses.iter().cloned().collect();
        self.addresses = addresses;
        self.progress
            .retain(|address, _| self.active.contains(address));
        if self.addresses.is_empty() {
            self.next = 0;
        } else {
            self.next %= self.addresses.len();
        }
    }

    fn take_turn(&mut self) -> Option<(String, Option<MiningProgress>)> {
        if self.addresses.is_empty() {
            return None;
        }
        for offset in 0..self.addresses.len() {
            let index = (self.next + offset) % self.addresses.len();
            let address = &self.addresses[index];
            if self.leased.insert(address.clone()) {
                let address = address.clone();
                self.next = (index + 1) % self.addresses.len();
                return Some((address.clone(), self.progress.remove(&address)));
            }
        }
        None
    }

    fn is_active(&self, address: &str) -> bool {
        self.active.contains(address)
    }

    fn finish_turn(&mut self, address: String, progress: Option<MiningProgress>) {
        self.leased.remove(&address);
        if self.active.contains(&address) {
            if let Some(progress) = progress {
                self.progress.insert(address, progress);
            }
        } else {
            self.progress.remove(&address);
        }
    }
}

fn mining_worker_count(available_cpus: usize) -> usize {
    available_cpus.saturating_sub(1).max(1)
}

fn mine_for_worker(
    scheduler: Arc<Mutex<MiningScheduler>>,
    generation: Arc<AtomicU64>,
    state: Arc<Mutex<NodeState>>,
    wait: Duration,
) {
    loop {
        let turn = match scheduler.lock() {
            Ok(mut scheduler) => scheduler.take_turn(),
            Err(_) => return,
        };
        let Some((address, cached_progress)) = turn else {
            thread::sleep(wait);
            continue;
        };
        let recipient = match Address::parse(&address) {
            Ok(recipient) => recipient,
            Err(error) => {
                eprintln!("miner address {address}: {error}");
                if let Ok(mut scheduler) = scheduler.lock() {
                    scheduler.finish_turn(address, None);
                }
                thread::sleep(wait);
                continue;
            }
        };
        let work_generation = generation.load(Ordering::Acquire);
        let candidate = match state.lock() {
            Ok(state) => {
                let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
                    Ok(now) => now.as_secs(),
                    Err(error) => {
                        eprintln!("miner clock: {error}");
                        if let Ok(mut scheduler) = scheduler.lock() {
                            scheduler.finish_turn(address, None);
                        }
                        thread::sleep(wait);
                        continue;
                    }
                };
                mining_timestamp(now, state.chain.rewards().tip_timestamp())
                    .map(|timestamp| state.candidate(&recipient, timestamp))
                    .transpose()
            }
            Err(_) => Err("node state poisoned".into()),
        };
        let Some(mut block) = (match candidate {
            Ok(candidate) => candidate,
            Err(error) => {
                eprintln!("miner candidate for {address}: {error}");
                if let Ok(mut scheduler) = scheduler.lock() {
                    scheduler.finish_turn(address, None);
                }
                thread::sleep(wait);
                continue;
            }
        }) else {
            if let Ok(mut scheduler) = scheduler.lock() {
                scheduler.finish_turn(address, None);
            }
            thread::sleep(wait);
            continue;
        };
        if let Some(progress) = cached_progress.filter(|progress| {
            progress.generation == work_generation
        }) {
            block.reward.nonce = progress.reward_nonce;
            block.nonce = progress.block_nonce;
        }
        let mut checks = 0;
        let mined = block.mine_with_control(|| {
            checks += 1;
            checks <= MINER_HASH_QUANTUM_CHECKS
                && generation.load(Ordering::Acquire) == work_generation
                && scheduler
                    .lock()
                    .map(|scheduler| scheduler.is_active(&address))
                    .unwrap_or(false)
        });
        match mined {
            Ok(false) => {
                let progress = (generation.load(Ordering::Acquire) == work_generation)
                    .then_some(MiningProgress {
                        reward_nonce: block.reward.nonce,
                        block_nonce: block.nonce,
                        generation: work_generation,
                    });
                if let Ok(mut scheduler) = scheduler.lock() {
                    scheduler.finish_turn(address, progress);
                }
            }
            Err(error) => {
                eprintln!("miner work for {address}: {error}");
                if let Ok(mut scheduler) = scheduler.lock() {
                    scheduler.finish_turn(address, None);
                }
                thread::sleep(wait);
            }
            Ok(true) => {
                let still_active = scheduler
                    .lock()
                    .map(|scheduler| scheduler.is_active(&address))
                    .unwrap_or(false);
                let mut accepted = false;
                if still_active && generation.load(Ordering::Acquire) == work_generation {
                    match state.lock() {
                        Ok(mut state) => {
                            if generation.load(Ordering::Acquire) == work_generation
                                && block.previous_hash == state.chain.tip_hash()
                            {
                                match state.import_block(block.clone()) {
                                    Ok(_) => {
                                        generation.fetch_add(1, Ordering::AcqRel);
                                        println!(
                                            "miner={} height={} confirmed_transactions={}",
                                            address,
                                            state.chain.height(),
                                            state.confirmed_transactions()
                                        );
                                        accepted = true;
                                    }
                                    Err(error) => eprintln!("miner block for {address}: {error}"),
                                }
                            }
                        }
                        Err(_) => eprintln!("miner: node state poisoned"),
                    }
                }
                if let Ok(mut scheduler) = scheduler.lock() {
                    scheduler.finish_turn(address.clone(), None);
                }
                if accepted {
                    if let Err(error) = crate::tsc1_peer_v3::relay_block(&block) {
                        eprintln!("miner relay for {address}: {error}");
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod mining_clock_tests {
    #[test]
    fn parses_multiple_unique_miner_addresses() {
        assert_eq!(
            super::parse_miner_addresses("wallet-a\n\n wallet-b \nwallet-a\n"),
            ["wallet-a", "wallet-b"]
        );
    }

    #[test]
    fn parses_more_than_sixteen_miner_addresses() {
        let addresses = (0..20)
            .map(|index| format!("wallet-{index}"))
            .collect::<Vec<_>>();
        let contents = addresses.join("\n");

        assert_eq!(super::parse_miner_addresses(&contents), addresses);
    }

    #[test]
    fn scheduler_round_robins_all_wallets_and_leases_distinct_work() {
        let addresses = (0..20)
            .map(|index| format!("wallet-{index}"))
            .collect::<Vec<_>>();
        let mut scheduler = super::MiningScheduler::default();
        scheduler.set_addresses(addresses.clone());

        let first_turns = (0..4)
            .map(|_| scheduler.take_turn().unwrap().0)
            .collect::<Vec<_>>();
        assert_eq!(first_turns, addresses[..4]);

        for address in first_turns {
            scheduler.finish_turn(address, None);
        }
        let next_turns = (0..4)
            .map(|_| scheduler.take_turn().unwrap().0)
            .collect::<Vec<_>>();
        assert_eq!(next_turns, addresses[4..8]);
    }

    #[test]
    fn scheduler_stop_removes_only_the_selected_wallet() {
        let addresses = (0..20)
            .map(|index| format!("wallet-{index}"))
            .collect::<Vec<_>>();
        let mut scheduler = super::MiningScheduler::default();
        scheduler.set_addresses(addresses.clone());
        let (stopped, _) = scheduler.take_turn().unwrap();
        scheduler.set_addresses(addresses[1..].to_vec());
        assert!(!scheduler.is_active(&stopped));

        let mut remaining = Vec::new();
        while let Some((address, _)) = scheduler.take_turn() {
            remaining.push(address.clone());
            scheduler.finish_turn(address, None);
            if remaining.len() == 19 {
                break;
            }
        }
        assert_eq!(remaining.len(), 19);
        assert!(!remaining.contains(&stopped));
    }

    #[test]
    fn miner_worker_count_stays_within_available_cpus() {
        for cpus in 0..=32 {
            let workers = super::mining_worker_count(cpus);
            assert!(workers >= 1);
            assert!(workers <= cpus.max(1));
        }
        assert_eq!(super::mining_worker_count(4), 3);
    }

    #[test]
    fn waits_for_wall_clock_instead_of_inventing_future_timestamps() {
        assert_eq!(super::mining_timestamp(100, 220), None);
        assert_eq!(super::mining_timestamp(220, 220), None);
        assert_eq!(super::mining_timestamp(221, 220), Some(221));
        assert_eq!(super::mining_timestamp(99, 100), None);
        assert_eq!(super::mining_timestamp(u64::MAX, u64::MAX), None);
        assert_eq!(
            super::mining_timestamp(u64::MAX, u64::MAX - 1),
            Some(u64::MAX)
        );
    }

    #[test]
    fn reads_faster_poll_interval_overrides_from_env() {
        let key = "TSC1_DEVNET_V3_PEER_SYNC_INTERVAL_MS_TEST";
        std::env::set_var(key, "250");
        assert_eq!(super::configured_duration_millis(key, 2_000), 250);
        std::env::remove_var(key);
    }
}

pub struct NodeState {
    chain: ChainV3,
    pending: Vec<Transaction>,
    pending_state: SpendState,
    pending_ids: HashSet<Hash>,
    pending_bytes: usize,
    pending_assets: Vec<SignedAssetTransaction>,
    pending_dex: Vec<SignedDexOperation>,
    directory: PathBuf,
    queue_directory: PathBuf,
    sequence: u64,
    _writer: File,
}

pub fn writer_lock(directory: &Path) -> Result<File> {
    let parent = directory
        .parent()
        .ok_or("blocks directory requires a parent")?;
    fs::create_dir_all(parent)?;
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(parent.join("node-writer.lock"))?;
    file.try_lock()
        .map_err(|_| "another node process owns this data directory")?;
    Ok(file)
}

pub fn encode_batch(txs: &[Transaction]) -> Result<Vec<u8>> {
    if txs.is_empty() || txs.len() > MAX_BATCH_TXS {
        return Err("invalid batch count".into());
    }
    let mut bytes = (txs.len() as u16).to_le_bytes().to_vec();
    for tx in txs {
        let encoded = tx.encode()?;
        bytes.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&encoded);
        if bytes.len() > MAX_BATCH_BYTES {
            return Err("batch too large".into());
        }
    }
    Ok(bytes)
}

pub fn decode_batch(bytes: &[u8]) -> Result<Vec<Transaction>> {
    if bytes.len() < 2 || bytes.len() > MAX_BATCH_BYTES {
        return Err("invalid batch size".into());
    }
    let mut cursor = std::io::Cursor::new(bytes);
    let count = u16::from_le_bytes(read_array(&mut cursor)?) as usize;
    if count == 0 || count > MAX_BATCH_TXS {
        return Err("invalid batch count".into());
    }
    let mut txs = Vec::with_capacity(count);
    for _ in 0..count {
        let length = u32::from_le_bytes(read_array(&mut cursor)?) as usize;
        if length == 0 || length > 512 * 1024 || length > bytes.len() - cursor.position() as usize {
            return Err("invalid batch transaction length".into());
        }
        let mut encoded = vec![0; length];
        cursor.read_exact(&mut encoded)?;
        txs.push(crate::tsc1_pending_v3::decode_signed(&encoded)?);
    }
    if cursor.position() != bytes.len() as u64 {
        return Err("trailing batch bytes".into());
    }
    Ok(txs)
}

fn read_array<const N: usize>(reader: &mut impl Read) -> Result<[u8; N]> {
    let mut bytes = [0; N];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

impl NodeState {
    pub fn open(directory: &Path, genesis: Chain) -> Result<Self> {
        let writer = writer_lock(directory)?;
        let chain = load_blocks(directory, genesis)?;
        let queue_directory = directory
            .parent()
            .ok_or("invalid blocks directory")?
            .join("pending-batches");
        fs::create_dir_all(&queue_directory)?;
        let mut state = Self {
            pending_state: chain.spends().clone(),
            chain,
            pending: Vec::new(),
            pending_ids: HashSet::new(),
            pending_bytes: 0,
            pending_assets: Vec::new(),
            pending_dex: Vec::new(),
            directory: directory.to_owned(),
            queue_directory,
            sequence: 0,
            _writer: writer,
        };
        let mut files: Vec<_> = fs::read_dir(&state.queue_directory)?
            .collect::<std::io::Result<Vec<_>>>()?
            .into_iter()
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "bin"))
            .collect();
        files.sort();
        if files.len() > MAX_PENDING_FILES {
            return Err("too many persisted pending batches".into());
        }
        for file in files {
            let sequence: u64 = file
                .file_stem()
                .and_then(|name| name.to_str())
                .ok_or("invalid pending batch filename")?
                .parse()?;
            state.sequence = state.sequence.max(sequence);
            if fs::metadata(&file)?.len() > MAX_BATCH_BYTES as u64 {
                return Err("oversized persisted batch".into());
            }
            for tx in decode_batch(&fs::read(&file)?)? {
                let id = tx.txid()?;
                if state.pending_ids.contains(&id) {
                    continue;
                }
                if tx.expires_at_height > state.chain.height()
                    && tx
                        .inputs
                        .iter()
                        .all(|input| !state.chain.spends().has_spent_image(&input.key_image))
                {
                    state.pending_bytes += tx.encode()?.len() + 4;
                    if state.pending.len() >= MAX_PENDING || state.pending_bytes > MAX_PENDING_BYTES
                    {
                        return Err("pending capacity exceeded".into());
                    }
                    state.pending_ids.insert(id);
                    state.pending.push(tx);
                }
            }
        }
        let mut dex_files = fs::read_dir(&state.queue_directory)?
            .collect::<std::io::Result<Vec<_>>>()?
            .into_iter()
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "dex"))
            .collect::<Vec<_>>();
        dex_files.sort();
        if dex_files.len() > MAX_DEX_OPERATIONS {
            return Err("too many persisted dex operations".into());
        }
        for path in dex_files {
            if fs::metadata(&path)?.len() > MAX_DEX_OPERATION_BYTES as u64 {
                return Err("oversized persisted dex operation".into());
            }
            state
                .pending_dex
                .push(SignedDexOperation::decode(&fs::read(path)?)?);
        }
        state.rebase_operations();
        state.rebase_pending();
        state.clean_consumed_files()?;
        Ok(state)
    }

    pub fn chain(&self) -> &ChainV3 {
        &self.chain
    }
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
    pub fn confirmed_transactions(&self) -> u64 {
        self.chain
            .blocks()
            .iter()
            .take(self.chain.blocks().len().saturating_sub(CONFIRMATION_DEPTH))
            .map(|block| block.transactions.len() as u64)
            .sum()
    }

    pub fn accept_batch(&mut self, bytes: &[u8]) -> Result<Vec<Hash>> {
        let txs = decode_batch(bytes)?;
        if self.pending.len() + txs.len() > MAX_PENDING
            || self.pending_bytes + bytes.len() - 2 > MAX_PENDING_BYTES
        {
            return Err("pending queue full".into());
        }
        let ids: Vec<_> = txs
            .iter()
            .map(Transaction::txid)
            .collect::<std::result::Result<_, _>>()?;
        let inclusion_height = self.chain.height() + 1;
        for transaction in &txs {
            crate::tsc1_chain_v3::validate_tnb_transfer_fee_transaction(
                transaction,
                inclusion_height,
            )?;
        }
        let distinct: HashSet<_> = ids.iter().copied().collect();
        if distinct.len() != ids.len() || ids.iter().any(|id| self.pending_ids.contains(id)) {
            return Err("duplicate pending transaction".into());
        }
        if fs::read_dir(&self.queue_directory)?
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "bin"))
            .count()
            >= MAX_PENDING_FILES
        {
            return Err("pending batch file limit".into());
        }
        let mut staged = self.pending_state.clone();
        staged.apply_batch(&txs, inclusion_height)?;
        let sequence = self
            .sequence
            .checked_add(1)
            .ok_or("batch sequence overflow")?;
        let mut nonce = [0; 8];
        getrandom::getrandom(&mut nonce)?;
        let temporary = self
            .queue_directory
            .join(format!("{sequence:020}-{}.tmp", hex::encode(nonce)));
        let target = self.queue_directory.join(format!("{sequence:020}.bin"));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, &target)?;
        self.sequence = sequence;
        self.pending_bytes += bytes.len() - 2;
        self.pending_state = staged;
        self.pending_ids.extend(ids.iter().copied());
        self.pending.extend(txs);
        Ok(ids)
    }

    pub fn candidate(&self, recipient: &Address, timestamp: u64) -> Result<BlockV3> {
        let height = self.chain.height() + 1;
        let reward = create_reward_output(recipient, 0, reward_at_height(height))?;
        let mut size = 8192;
        for signed in &self.pending_assets {
            size += signed.transaction.encode()?.len() + 100;
        }
        for signed in &self.pending_dex {
            size += signed.encode().len() + 2;
        }

        let mut selected = Vec::new();
        for tx in self
            .pending
            .iter()
            .filter(|transaction| {
                crate::tsc1_chain_v3::validate_tnb_transfer_fee_transaction(
                    transaction,
                    height,
                )
                .is_ok()
            })
            .take(MAX_TXS)
        {
            size += tx.encode()?.len() + 4;
            if size > MAX_BLOCK_BYTES {
                break;
            }
            selected.push(tx.clone());
        }
        let mut block = self
            .chain
            .next_block_with_fees(reward, recipient, timestamp, selected)?;
        block.asset_transactions = self.pending_assets.clone();
        block.dex_operations = self.pending_dex.clone();
        block.encode()?;
        Ok(block)
    }

    pub fn accept_asset(&mut self, transaction: SignedAssetTransaction) -> Result<Hash> {
        transaction.verify()?;
        if self.pending_assets.len() >= 256 {
            return Err("pending asset capacity exceeded".into());
        }
        let mut staged = self.chain.assets().clone();
        let mut staged_spends = self.pending_state.clone();
        for pending in &self.pending_assets {
            if let Some(fee) = validate_asset_operation_fee(pending, self.chain.height() + 1, &staged)? {
                staged_spends.apply_batch(std::slice::from_ref(&fee), self.chain.height() + 1)?;
            }
            staged.apply(pending.transaction.clone())?;
        }
        let fee = validate_asset_operation_fee(&transaction, self.chain.height() + 1, &staged)?;
        staged.apply(transaction.transaction.clone())?;
        if let Some(fee) = fee {
            staged_spends.apply_batch(std::slice::from_ref(&fee), self.chain.height() + 1)?;
        }
        let id = transaction.transaction.txid()?;
        if self
            .pending_assets
            .iter()
            .any(|pending| pending.transaction.txid().ok() == Some(id))
        {
            return Err("duplicate pending asset transaction".into());
        }
        let mut dex = self.chain.dex().clone();
        for pending in &self.pending_dex {
            dex.apply(pending, &mut staged)?;
        }
        self.pending_assets.push(transaction);
        Ok(id)
    }

    pub fn pending_dex_count(&self) -> usize {
        self.pending_dex.len()
    }

    pub fn accept_dex(&mut self, operation: SignedDexOperation) -> Result<Hash> {
        operation.verify()?;
        if self.pending_dex.len() >= MAX_DEX_OPERATIONS {
            return Err("pending dex capacity exceeded".into());
        }
        let id = operation.id();
        if self.pending_dex.iter().any(|pending| pending.id() == id)
            || self.chain.dex().has_applied_operation(&id)
        {
            return Err("duplicate pending dex operation".into());
        }
        let mut assets = self.chain.assets().clone();
        let mut dex = self.chain.dex().clone();
        // Admission uses confirmed asset balances, so DEX queue recovery has no
        // dependency on the existing in-memory asset-operation queue.
        for pending in &self.pending_dex {
            dex.apply(pending, &mut assets)?;
        }
        dex.apply(&operation, &mut assets)?;
        // Also ensure pending asset operations cannot invalidate this candidate.
        let mut candidate_assets = self.chain.assets().clone();
        for pending in &self.pending_assets {
            candidate_assets.apply(pending.transaction.clone())?;
        }
        let mut candidate_dex = self.chain.dex().clone();
        for pending in &self.pending_dex {
            candidate_dex.apply(pending, &mut candidate_assets)?;
        }
        candidate_dex.apply(&operation, &mut candidate_assets)?;
        self.clean_dex_files()?;
        let target = self.queue_directory.join(format!(
            "{:020}-{}.dex",
            operation.sequence,
            hex::encode(id)
        ));
        let temporary = target.with_extension("dex-tmp");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(&operation.encode())?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, &target)?;
        self.pending_dex.push(operation);
        Ok(id)
    }

    fn rebase_operations(&mut self) {
        let mut assets = self.chain.assets().clone();
        self.pending_assets.retain(|operation| {
            let mut staged = assets.clone();
            if operation.verify().is_ok() && staged.apply(operation.transaction.clone()).is_ok() {
                assets = staged;
                true
            } else {
                false
            }
        });
        let mut dex = self.chain.dex().clone();
        self.pending_dex
            .retain(|operation| dex.apply(operation, &mut assets).is_ok());
    }

    fn clean_dex_files(&self) -> Result<()> {
        let ids: HashSet<_> = self
            .pending_dex
            .iter()
            .map(SignedDexOperation::id)
            .collect();
        for entry in fs::read_dir(&self.queue_directory)? {
            let path = entry?.path();
            if !path.extension().is_some_and(|ext| ext == "dex") {
                continue;
            }
            if fs::metadata(&path)?.len() > MAX_DEX_OPERATION_BYTES as u64 {
                return Err("oversized persisted dex operation".into());
            }
            let operation = SignedDexOperation::decode(&fs::read(&path)?)?;
            if !ids.contains(&operation.id()) {
                fs::remove_file(path)?;
            }
        }
        Ok(())
    }

    pub fn import_block(&mut self, block: BlockV3) -> Result<Hash> {
        let mut staged = self.chain.clone();
        staged.append(block.clone())?;
        persist_block(&self.directory, &block)?;
        self.chain = staged;
        self.pending_assets
            .retain(|pending| !block.asset_transactions.contains(pending));
        self.rebase_operations();
        // The disk commit is authoritative. Queue cleanup errors cannot roll it back.
        self.rebase_pending();
        if let Err(error) = self.clean_consumed_files() {
            eprintln!("pending cleanup: {error}");
        }
        Ok(self.chain.tip_hash())
    }

    fn rebase_pending(&mut self) {
        self.pending_state = self.chain.spends().clone();
        self.pending_ids.clear();
        let height = self.chain.height() + 1;
        self.pending.retain(|tx| {
            tx.expires_at_height >= height
                && tx
                    .inputs
                    .iter()
                    .all(|input| !self.chain.spends().has_spent_image(&input.key_image))
        });
        self.pending_bytes = self
            .pending
            .iter()
            .map(|tx| tx.encode().expect("decoded transaction").len() + 4)
            .sum();
        if self
            .pending_state
            .apply_batch(&self.pending, height)
            .is_ok()
        {
            self.pending_ids.extend(
                self.pending
                    .iter()
                    .map(|tx| tx.txid().expect("decoded transaction")),
            );
            return;
        }
        self.pending_state = self.chain.spends().clone();
        self.pending.retain(|tx| {
            if self
                .pending_state
                .apply_batch(std::slice::from_ref(tx), height)
                .is_ok()
            {
                self.pending_ids
                    .insert(tx.txid().expect("decoded transaction"));
                true
            } else {
                false
            }
        });
        self.pending_bytes = self
            .pending
            .iter()
            .map(|tx| tx.encode().expect("decoded transaction").len() + 4)
            .sum();
    }

    fn clean_consumed_files(&self) -> Result<()> {
        self.clean_dex_files()?;
        for entry in fs::read_dir(&self.queue_directory)? {
            let path = entry?.path();
            if !path.extension().is_some_and(|ext| ext == "bin") {
                continue;
            }
            if fs::metadata(&path)?.len() > MAX_BATCH_BYTES as u64 {
                return Err("oversized persisted batch".into());
            }
            let txs = decode_batch(&fs::read(&path)?)?;
            if !txs
                .iter()
                .any(|tx| tx.txid().is_ok_and(|id| self.pending_ids.contains(&id)))
            {
                fs::remove_file(&path)?;
            }
        }
        Ok(())
    }
}

pub fn handle_connection(mut stream: TcpStream, state: &Mutex<NodeState>) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(15)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;
    let magic = read_array::<8>(&mut stream)?;
    let genesis = read_array::<32>(&mut stream)?;
    if &magic != network::PEER_MAGIC
        || genesis
            != state
                .lock()
                .map_err(|_| "node state poisoned")?
                .chain
                .rewards()
                .genesis_hash()
    {
        return Err("wrong mainnet handshake".into());
    }
    stream.write_all(network::PEER_MAGIC)?;
    let request = read_array::<1>(&mut stream)?[0];
    match request {
        b'H' => {
            let state = state.lock().map_err(|_| "node state poisoned")?;
            stream.write_all(network::PEER_MAGIC)?;
            stream.write_all(&state.chain.height().to_le_bytes())?;
            stream.write_all(&state.chain.tip_hash())?;
            stream.write_all(&state.confirmed_transactions().to_le_bytes())?;
            stream.write_all(&(state.pending.len() as u32).to_le_bytes())?;
        }
        b'J' => {
            let operation_id = read_array::<32>(&mut stream)?;
            let state = state.lock().map_err(|_| "node state poisoned")?;
            let status = if state.chain.dex().has_applied_operation(&operation_id) {
                2u8
            } else if state.pending_dex.iter().any(|pending| pending.id() == operation_id) {
                1u8
            } else {
                0u8
            };
            stream.write_all(network::PEER_MAGIC)?;
            stream.write_all(&[status])?;
        }
        b'M' => {
            let offset = u32::from_le_bytes(read_array(&mut stream)?) as usize;
            if offset > MAX_PENDING {
                return Err("invalid pending offset".into());
            }
            let (tip, bytes) = {
                let state = state.lock().map_err(|_| "node state poisoned")?;
                let mut selected = Vec::new();
                let mut size = 2;
                for tx in state.pending.iter().skip(offset).take(MAX_BATCH_TXS) {
                    let length = tx.encode()?.len() + 4;
                    if size + length > MAX_BATCH_BYTES {
                        break;
                    }
                    size += length;
                    selected.push(tx.clone());
                }
                let bytes = if selected.is_empty() {
                    Vec::new()
                } else {
                    encode_batch(&selected)?
                };
                (state.chain.tip_hash(), bytes)
            };
            stream.write_all(network::PEER_MAGIC)?;
            stream.write_all(&tip)?;
            stream.write_all(&(bytes.len() as u32).to_le_bytes())?;
            stream.write_all(&bytes)?;
        }
        b'Q' | b'T' => {
            let length = u32::from_le_bytes(read_array(&mut stream)?) as usize;
            let limit = if request == b'T' {
                512 * 1024
            } else {
                MAX_BATCH_BYTES
            };
            if length == 0 || length > limit {
                return Err("invalid request size".into());
            }
            let mut bytes = vec![0; length];
            stream.read_exact(&mut bytes)?;
            if request == b'T' {
                bytes = encode_batch(&[crate::tsc1_pending_v3::decode_signed(&bytes)?])?;
            }
            let result = state
                .lock()
                .map_err(|_| "node state poisoned")?
                .accept_batch(&bytes);
            stream.write_all(network::PEER_MAGIC)?;
            match result {
                Ok(ids) => {
                    stream.write_all(&[1])?;
                    if request == b'Q' {
                        stream.write_all(&(ids.len() as u16).to_le_bytes())?;
                    }
                    for id in ids {
                        stream.write_all(&id)?;
                    }
                }
                Err(error) => {
                    stream.write_all(&[0])?;
                    if request == b'T' {
                        stream.write_all(&[0; 32])?;
                    } else {
                        stream.write_all(&0u16.to_le_bytes())?;
                    }
                    return Err(error);
                }
            }
        }
        b'A' => {
            let length = u32::from_le_bytes(read_array(&mut stream)?) as usize;
            if length == 0 || length > 512 * 1024 {
                return Err("invalid asset request size".into());
            }
            let mut bytes = vec![0; length];
            stream.read_exact(&mut bytes)?;
            let result = (|| -> Result<Hash> {
                let signed = SignedAssetTransaction::decode(&bytes)?;
                state
                    .lock()
                    .map_err(|_| "node state poisoned")?
                    .accept_asset(signed)
            })();
            stream.write_all(network::PEER_MAGIC)?;
            match result {
                Ok(id) => {
                    stream.write_all(&[1])?;
                    stream.write_all(&id)?;
                }
                Err(_) => {
                    stream.write_all(&[0])?;
                    stream.write_all(&[0; 32])?;
                }
            }
        }
        b'D' => {
            let length = u32::from_le_bytes(read_array(&mut stream)?) as usize;
            if length == 0 || length > MAX_DEX_OPERATION_BYTES {
                return Err("invalid dex request size".into());
            }
            let mut bytes = vec![0; length];
            stream.read_exact(&mut bytes)?;
            let operation = SignedDexOperation::decode(&bytes)?;
            let result = state
                .lock()
                .map_err(|_| "node state poisoned")?
                .accept_dex(operation);
            stream.write_all(network::PEER_MAGIC)?;
            match result {
                Ok(id) => {
                    stream.write_all(&[1])?;
                    stream.write_all(&id)?;
                }
                Err(_) => {
                    stream.write_all(&[0])?;
                    stream.write_all(&[0; 32])?;
                }
            }
        }
        b'B' => {
            let length = u32::from_le_bytes(read_array(&mut stream)?) as usize;
            if length == 0 || length > MAX_BLOCK_BYTES {
                return Err("invalid block size".into());
            }
            let mut bytes = vec![0; length];
            stream.read_exact(&mut bytes)?;
            let block = BlockV3::decode(&bytes)?;
            let result = state
                .lock()
                .map_err(|_| "node state poisoned")?
                .import_block(block);
            stream.write_all(network::PEER_MAGIC)?;
            match result {
                Ok(hash) => {
                    stream.write_all(&[1])?;
                    stream.write_all(&hash)?;
                }
                Err(error) => {
                    stream.write_all(&[0])?;
                    stream.write_all(&[0; 32])?;
                    return Err(error);
                }
            }
        }
        b'G' => {
            let first = u64::from_le_bytes(read_array(&mut stream)?);
            let count = u16::from_le_bytes(read_array(&mut stream)?) as usize;
            let anchor = read_array::<32>(&mut stream)?;
            if first == 0 || count == 0 || count > 64 {
                return Err("invalid block page".into());
            }
            let (height, accepted, blocks) = {
                let state = state.lock().map_err(|_| "node state poisoned")?;
                let start = usize::try_from(first - 1)?;
                let expected = if start == 0 {
                    ChainV3::from_genesis(Chain::from_genesis(
                        state.chain.rewards().genesis_block().clone(),
                    )?)?
                    .tip_hash()
                } else {
                    state
                        .chain
                        .blocks()
                        .get(start - 1)
                        .map(|block| block.hash())
                        .transpose()?
                        .unwrap_or([0; 32])
                };
                let accepted = start <= state.chain.blocks().len() && expected == anchor;
                let mut blocks = Vec::new();
                let mut total = 0;
                if accepted {
                    for block in state.chain.blocks().iter().skip(start).take(count) {
                        let encoded = block.encode()?;
                        if !blocks.is_empty() && total + encoded.len() > MAX_BLOCK_BYTES {
                            break;
                        }
                        total += encoded.len();
                        blocks.push(encoded);
                    }
                }
                (state.chain.height(), accepted, blocks)
            };
            stream.write_all(network::PEER_MAGIC)?;
            stream.write_all(&[u8::from(accepted)])?;
            stream.write_all(&height.to_le_bytes())?;
            stream.write_all(&(blocks.len() as u16).to_le_bytes())?;
            for block in blocks {
                stream.write_all(&(block.len() as u32).to_le_bytes())?;
                stream.write_all(&block)?;
            }
        }
        _ => return Err("unknown mainnet request".into()),
    }
    Ok(())
}

pub fn serve(bind: &str, directory: &Path) -> Result<()> {
    let state = Arc::new(Mutex::new(NodeState::open(
        directory,
        network::pinned_genesis()?,
    )?));
    let listener = TcpListener::bind(bind)?;
    let active = Arc::new(AtomicUsize::new(0));
    let admission = Arc::new(crate::tsc1_peer_v3::ConnectionAdmission::new());
    let peers = crate::tsc1_peer_v3::configured_peers()?;
    let peer_sync_interval = Duration::from_millis(configured_duration_millis(
        &network::variable("PEER_SYNC_INTERVAL_MS"),
        1_000,
    ));
    if !peers.is_empty() {
        let sync_state_ref = Arc::clone(&state);
        thread::spawn(move || {
            loop {
                for peer in &peers {
                    match sync_state(peer, &sync_state_ref) {
                        Ok(_) => {
                            if let Err(error) = sync_pending(peer, &sync_state_ref) {
                                eprintln!("pending sync {peer}: {error}");
                            }
                        }
                        Err(error) => eprintln!("sync {peer}: {error}"),
                    }
                }
                thread::sleep(peer_sync_interval);
            }
        });
    }
    let miner_wait = Duration::from_millis(configured_duration_millis(
        &network::variable("MINER_WAIT_INTERVAL_MS"),
        250,
    ));
    let miner_state = Arc::clone(&state);
    thread::spawn(move || {
        let generation = Arc::new(AtomicU64::new(0));
        let scheduler = Arc::new(Mutex::new(MiningScheduler::default()));
        let cpu_count = thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(1);
        let worker_count = mining_worker_count(cpu_count);
        for _ in 0..worker_count {
            let worker_scheduler = Arc::clone(&scheduler);
            let worker_generation = Arc::clone(&generation);
            let worker_state = Arc::clone(&miner_state);
            thread::spawn(move || {
                mine_for_worker(
                    worker_scheduler,
                    worker_generation,
                    worker_state,
                    miner_wait,
                );
            });
        }
        loop {
            let addresses = match configured_miner_addresses() {
                Ok(addresses) => addresses,
                Err(error) => {
                    eprintln!("miner configuration: {error}");
                    thread::sleep(miner_wait);
                    continue;
                }
            };
            match scheduler.lock() {
                Ok(mut scheduler) => scheduler.set_addresses(addresses),
                Err(_) => {
                    eprintln!("miner scheduler: state poisoned");
                    return;
                }
            }
            thread::sleep(miner_wait);
        }
    });
    println!(
        "network={} listening={}",
        network::NAME,
        listener.local_addr()?
    );
    for incoming in listener.incoming() {
        let stream = incoming?;
        if !admission.allow(stream.peer_addr()?.ip()) {
            continue;
        }
        if active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < 8).then_some(count + 1)
            })
            .is_err()
        {
            continue;
        }
        let state = Arc::clone(&state);
        let active = Arc::clone(&active);
        thread::spawn(move || {
            if let Err(error) = handle_connection(stream, &state) {
                eprintln!("mainnet request: {error}");
            }
            active.fetch_sub(1, Ordering::AcqRel);
        });
    }
    Ok(())
}

fn connect(peer: &str, genesis: Hash) -> Result<TcpStream> {
    use std::net::ToSocketAddrs;
    let mut connection = None;
    for address in peer.to_socket_addrs()? {
        if let Ok(stream) = TcpStream::connect_timeout(&address, Duration::from_secs(5)) {
            connection = Some(stream);
            break;
        }
    }
    let mut stream = connection.ok_or("could not connect to mainnet peer")?;
    stream.set_read_timeout(Some(Duration::from_secs(120)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;
    stream.write_all(network::PEER_MAGIC)?;
    stream.write_all(&genesis)?;
    if &read_array::<8>(&mut stream)? != network::PEER_MAGIC {
        return Err("wrong mainnet response".into());
    }
    Ok(stream)
}

pub fn submit_batch(peer: &str, bytes: &[u8]) -> Result<Vec<Hash>> {
    let txs = decode_batch(bytes)?;
    let mut stream = connect(peer, network::pinned_genesis()?.genesis_hash())?;
    send_batch(&mut stream, bytes, &txs)
}

fn send_batch(stream: &mut TcpStream, bytes: &[u8], txs: &[Transaction]) -> Result<Vec<Hash>> {
    stream.write_all(b"Q")?;
    stream.write_all(&(bytes.len() as u32).to_le_bytes())?;
    stream.write_all(bytes)?;
    if &read_array::<8>(stream)? != network::PEER_MAGIC {
        return Err("wrong batch response".into());
    }
    let accepted = read_array::<1>(stream)?[0];
    let count = u16::from_le_bytes(read_array(stream)?) as usize;
    if accepted != 1 || count != txs.len() {
        return Err("batch rejected".into());
    }
    let mut ids = Vec::with_capacity(count);
    for tx in txs {
        let id = read_array::<32>(stream)?;
        if id != tx.txid()? {
            return Err("wrong accepted transaction ID".into());
        }
        ids.push(id);
    }
    Ok(ids)
}

pub fn query_status(peer: &str) -> Result<(u64, Hash, u64, u32)> {
    let mut stream = connect(peer, network::pinned_genesis()?.genesis_hash())?;
    stream.write_all(b"H")?;
    if &read_array::<8>(&mut stream)? != network::PEER_MAGIC {
        return Err("wrong status response".into());
    }
    Ok((
        u64::from_le_bytes(read_array(&mut stream)?),
        read_array(&mut stream)?,
        u64::from_le_bytes(read_array(&mut stream)?),
        u32::from_le_bytes(read_array(&mut stream)?),
    ))
}

fn fetch_extension(peer: &str, local: &ChainV3) -> Result<ChainV3> {
    let genesis = Chain::from_genesis(local.rewards().genesis_block().clone())?;
    let genesis_hash = genesis.genesis_hash();
    let mut candidate = local.clone();
    let mut restarted = false;
    // Bound each sync cycle. An extending chain can catch up over successive cycles.
    for _ in 0..64 {
        let mut stream = connect(peer, genesis_hash)?;
        stream.write_all(b"G")?;
        stream.write_all(&(candidate.height() + 1).to_le_bytes())?;
        stream.write_all(&64u16.to_le_bytes())?;
        stream.write_all(&candidate.tip_hash())?;
        if &read_array::<8>(&mut stream)? != network::PEER_MAGIC {
            return Err("wrong sync response".into());
        }
        let accepted = read_array::<1>(&mut stream)?[0];
        let remote_height = u64::from_le_bytes(read_array(&mut stream)?);
        let count = u16::from_le_bytes(read_array(&mut stream)?) as usize;
        if count > 64 {
            return Err("oversized block page".into());
        }
        if accepted != 1 {
            if accepted != 0 || count != 0 || restarted {
                return Err("unstable or invalid remote chain".into());
            }
            candidate = ChainV3::from_genesis(genesis.clone())?;
            restarted = true;
            continue;
        }
        if count == 0 {
            if candidate.height() < remote_height {
                return Err("empty incomplete block page".into());
            }
            break;
        }
        let mut total = 0usize;
        for _ in 0..count {
            let length = u32::from_le_bytes(read_array(&mut stream)?) as usize;
            total = total.checked_add(length).ok_or("page length overflow")?;
            if length == 0 || length > MAX_BLOCK_BYTES || total > MAX_BLOCK_BYTES {
                return Err("oversized block page".into());
            }
            let mut bytes = vec![0; length];
            stream.read_exact(&mut bytes)?;
            candidate.append(BlockV3::decode(&bytes)?)?;
        }
        if candidate.height() >= remote_height {
            break;
        }
    }
    Ok(candidate)
}

fn sync_state(peer: &str, state: &Mutex<NodeState>) -> Result<u64> {
    let local = state
        .lock()
        .map_err(|_| "node state poisoned")?
        .chain
        .clone();
    let remote = fetch_extension(peer, &local)?;
    let mut state = state.lock().map_err(|_| "node state poisoned")?;
    if remote.cumulative_work() <= state.chain.cumulative_work() {
        return Ok(0);
    }
    let added = crate::tsc1_peer_v3::append_extension(&state.chain, &remote, &state.directory)?;
    state.chain = remote;
    state.rebase_pending();
    if let Err(error) = state.clean_consumed_files() {
        eprintln!("pending cleanup: {error}");
    }
    Ok(added)
}

pub fn sync_directory(peer: &str, directory: &Path) -> Result<u64> {
    let state = Mutex::new(NodeState::open(directory, network::pinned_genesis()?)?);
    sync_state(peer, &state)
}

#[cfg(test)]
#[path = "candidate_node_tests.rs"]
mod tests;

fn sync_pending(peer: &str, state: &Mutex<NodeState>) -> Result<()> {
    let genesis = state
        .lock()
        .map_err(|_| "node state poisoned")?
        .chain
        .rewards()
        .genesis_hash();
    let mut offset = 0usize;
    let mut remote_tip = None;
    for _ in 0..32 {
        let mut stream = connect(peer, genesis)?;
        stream.write_all(b"M")?;
        stream.write_all(&(offset as u32).to_le_bytes())?;
        if &read_array::<8>(&mut stream)? != network::PEER_MAGIC {
            return Err("wrong pending response".into());
        }
        let tip = read_array::<32>(&mut stream)?;
        if remote_tip.is_some_and(|known| known != tip) {
            return Ok(());
        }
        remote_tip = Some(tip);
        let length = u32::from_le_bytes(read_array(&mut stream)?) as usize;
        if length == 0 {
            break;
        }
        if length > MAX_BATCH_BYTES {
            return Err("oversized pending page".into());
        }
        let mut bytes = vec![0; length];
        stream.read_exact(&mut bytes)?;
        let txs = decode_batch(&bytes)?;
        offset += txs.len();
        if offset > MAX_PENDING {
            return Err("remote pending capacity exceeded".into());
        }
        let mut node = state.lock().map_err(|_| "node state poisoned")?;
        let missing: Vec<_> = txs
            .into_iter()
            .filter(|tx| {
                !node
                    .pending_ids
                    .contains(&tx.txid().expect("decoded transaction"))
                    && tx
                        .inputs
                        .iter()
                        .all(|input| !node.chain.spends().has_spent_image(&input.key_image))
            })
            .collect();
        if !missing.is_empty() {
            node.accept_batch(&encode_batch(&missing)?)?;
        }
    }
    Ok(())
}
