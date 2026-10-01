use super::*;
use crate::assets::{sign_issuer, AssetTransaction};
use crate::tsc1_funded_output::{create_funded_output_with_blinding, create_reward_output};
use crate::tsc1_private_amounts::random_blinding;
use crate::tsc1_spend_state_v2::transaction_output_id;
use crate::tsc1_tx_v2::{
    AuthorizationProof, NETWORK_ID, RING_SIZE, RingInput, key_image_for_secret,
};
use crate::{FOUNDER_ALLOCATION_NOX, WalletSecrets};
use bulletproofs::PedersenGens;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use rayon::prelude::*;

fn signed_outputs(
    state: &SpendState,
    wallet: &WalletSecrets,
    owned: Hash,
    payments: &[(Address, u64)],
    height: u64,
    eligible: &[Hash],
) -> Transaction {
    let output = state.output(&owned).unwrap();
    let recovered = wallet
        .scan_funded_output(output, state.output_index(&owned).unwrap())
        .unwrap();
    let secret = Scalar::from_canonical_bytes(recovered.one_time_spend)
        .into_option()
        .unwrap();
    assert_eq!(
        payments.iter().map(|(_, amount)| amount).sum::<u64>() + 1,
        recovered.amount_nox
    );
    let mut members: Vec<_> = eligible
        .iter()
        .copied()
        .filter(|id| *id != owned)
        .take(RING_SIZE - 1)
        .collect();
    members.push(owned);
    members.sort();
    let members: [Hash; RING_SIZE] = members.try_into().unwrap();
    let mut blinding = Scalar::ZERO;
    let outputs = payments
        .iter()
        .enumerate()
        .map(|(index, (address, amount))| {
            let blind = random_blinding().unwrap();
            blinding += blind;
            create_funded_output_with_blinding(address, index as u64, *amount, blind).unwrap()
        })
        .collect();
    let pseudo_output = PedersenGens::default()
        .commit(Scalar::from(recovered.amount_nox), blinding)
        .compress()
        .to_bytes();
    let placeholder = AuthorizationProof {
        challenge: Scalar::ONE,
        key_responses: [Scalar::ONE; RING_SIZE],
        amount_responses: [Scalar::ONE; RING_SIZE],
    }
    .encode();
    let mut tx = Transaction {
        network_id: NETWORK_ID,
        version: 2,
        expires_at_height: height + 1_000,
        inputs: vec![RingInput {
            asset_id: crate::assets::TNB_ASSET_ID,
            members,
            key_image: key_image_for_secret(secret),
            pseudo_output,
            authorization: placeholder,
        }],
        outputs,
        fee_nox: 1,
    };
    let rings = tx
        .ring_statements_with(height, |id| state.output(id))
        .unwrap();
    let signer = members.iter().position(|id| *id == owned).unwrap();
    tx.inputs[0].authorization = AuthorizationProof::sign(
        &tx.signing_hash().unwrap(),
        tx.inputs[0].key_image,
        &rings[0],
        signer,
        secret,
        recovered.blinding - blinding,
    )
    .unwrap()
    .encode();
    tx
}

fn unique_directory() -> PathBuf {
    let mut suffix = [0; 12];
    getrandom::getrandom(&mut suffix).unwrap();
    std::env::temp_dir().join(format!("tenebra-candidate-test-{}", hex::encode(suffix)))
}

/// Every spendable fixture output is obtained from a validated, mined chain.
/// No arbitrary funded outputs or synthetic settlement heights enter the measurement.
fn fixture(count: usize) -> (PathBuf, Chain, Vec<Transaction>, Address) {
    let directory = unique_directory();
    let founder = WalletSecrets::from_seed(&[201; 32]);
    let miner = WalletSecrets::from_seed(&[202; 32]);
    let recipient = WalletSecrets::from_seed(&[203; 32]);
    let genesis = Chain::new(
        create_reward_output(&founder.address(), 0, FOUNDER_ALLOCATION_NOX).unwrap(),
        1,
    )
    .unwrap();
    let mut chain = ChainV3::from_genesis(genesis.clone()).unwrap();
    for height in 1..=11 {
        let reward = create_reward_output(&miner.address(), 0, reward_at_height(height)).unwrap();
        let mut block = chain.next_block(reward, 1 + height * 30, vec![]);
        block.mine().unwrap();
        chain.append(block).unwrap();
    }
    let mut leaves = vec![genesis.genesis_block().reward_output_id()];
    while leaves.len() < count {
        let split_count = ((count - leaves.len()).div_ceil(15))
            .min(leaves.len())
            .min(MAX_TXS);
        let parents: Vec<_> = leaves.drain(..split_count).collect();
        let eligible = chain.spends().eligible_output_ids(chain.height() + 1);
        eprintln!(
            "fixture_splitting_parents={} existing_leaves={}",
            parents.len(),
            leaves.len()
        );
        let split: Vec<_> = parents
            .par_iter()
            .map(|id| {
                let owned = founder
                    .scan_funded_output(
                        chain.spends().output(id).unwrap(),
                        chain.spends().output_index(id).unwrap(),
                    )
                    .unwrap();
                let amount = (owned.amount_nox - 1) / 16;
                let remainder = (owned.amount_nox - 1) % 16;
                let payments: Vec<_> = (0..16)
                    .map(|index| {
                        (
                            founder.address(),
                            amount + if index == 0 { remainder } else { 0 },
                        )
                    })
                    .collect();
                signed_outputs(
                    chain.spends(),
                    &founder,
                    *id,
                    &payments,
                    chain.height() + 1,
                    &eligible,
                )
            })
            .collect();
        for tx in &split {
            for index in 0..16 {
                leaves.push(transaction_output_id(tx.txid().unwrap(), index));
            }
        }
        let height = chain.height() + 1;
        let reward = create_reward_output(&miner.address(), 0, reward_at_height(height)).unwrap();
        let mut block = chain
            .next_block_with_fees(reward, &miner.address(), 1 + height * 30, split)
            .unwrap();
        block.mine().unwrap();
        chain.append(block).unwrap();
    }
    eprintln!(
        "fixture_outputs={} history_height={}",
        leaves.len(),
        chain.height()
    );
    let eligible = chain.spends().eligible_output_ids(chain.height() + 1);
    let transactions: Vec<_> = leaves[..count]
        .par_iter()
        .map(|id| {
            let owned = founder
                .scan_funded_output(
                    chain.spends().output(id).unwrap(),
                    chain.spends().output_index(id).unwrap(),
                )
                .unwrap();
            signed_outputs(
                chain.spends(),
                &founder,
                *id,
                &[
                    (recipient.address(), 1),
                    (founder.address(), owned.amount_nox - 2),
                ],
                chain.height() + 1,
                &eligible,
            )
        })
        .collect();
    for block in chain.blocks() {
        persist_block(&directory.join("blocks"), block).unwrap();
    }
    (directory, genesis, transactions, miner.address())
}

#[test]
fn signed_one_of_one_nft_is_mined_validated_and_restored() {
    let root = unique_directory();
    let blocks = root.join("blocks");
    let founder = WalletSecrets::from_seed(&[211; 32]);
    let miner = WalletSecrets::from_seed(&[212; 32]);
    let genesis = Chain::new(
        create_reward_output(&founder.address(), 0, FOUNDER_ALLOCATION_NOX).unwrap(),
        1,
    )
    .unwrap();
    let mut node = NodeState::open(&blocks, genesis.clone()).unwrap();

    let issuer_secret = Scalar::from(213u64);
    let issuer = (issuer_secret * RISTRETTO_BASEPOINT_POINT)
        .compress()
        .to_bytes();
    let transaction = AssetTransaction::Create {
        issuer,
        nonce: 17,
        name: "Local NFT".into(),
        symbol: "NFT".into(),
        decimals: 0,
        max_supply: 1,
        initial_supply: 1,
    };
    let asset_id = crate::assets::AssetDefinition::derive_id(&issuer, 17);
    let signed = sign_issuer(&transaction, issuer_secret, &[214; 64]).unwrap();
    assert_eq!(node.accept_asset(signed.clone()).unwrap(), transaction.txid().unwrap());
    assert!(node.accept_asset(signed).is_err());

    let mut block = node
        .candidate(&miner.address(), node.chain.rewards().tip_timestamp() + 30)
        .unwrap();
    assert_eq!(block.asset_transactions.len(), 1);
    block.mine().unwrap();
    node.import_block(block).unwrap();
    assert_eq!(node.chain.assets().balance(&asset_id, &issuer), 1);
    let tip = node.chain.tip_hash();
    drop(node);

    let restored = NodeState::open(&blocks, genesis).unwrap();
    assert_eq!(restored.chain.tip_hash(), tip);
    assert_eq!(restored.chain.assets().balance(&asset_id, &issuer), 1);
    drop(restored);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn durable_batch_mined_confirmations_and_cache_rejection() {
    let (root, genesis, transactions, miner) = fixture(18);
    let blocks = root.join("blocks");
    let mut node = NodeState::open(&blocks, genesis.clone()).unwrap();
    assert!(NodeState::open(&blocks, genesis.clone()).is_err());
    let baseline = node.confirmed_transactions();
    let batch = encode_batch(&transactions).unwrap();
    node.accept_batch(&batch).unwrap();
    assert!(node.accept_batch(&batch).is_err());
    // A cache entry from mempool verification must not authorize altered proofs.
    let mut tampered = transactions[0].clone();
    tampered.inputs[0].authorization[40] ^= 1;
    assert!(
        node.chain
            .spends()
            .clone()
            .apply_batch(&[tampered], node.chain.height() + 1)
            .is_err()
    );
    assert!(
        node.chain
            .spends()
            .clone()
            .apply_batch(&transactions, transactions[0].expires_at_height + 1)
            .is_err()
    );
    drop(node);
    let mut node = NodeState::open(&blocks, genesis.clone()).unwrap();
    assert_eq!(node.pending_count(), 18);
    for _ in 0..=CONFIRMATION_DEPTH {
        let mut block = node
            .candidate(&miner, node.chain.rewards().tip_timestamp() + 30)
            .unwrap();
        block.mine().unwrap();
        node.import_block(block).unwrap();
    }
    assert_eq!(node.pending_count(), 0);
    assert!(node.confirmed_transactions() >= baseline + 18);
    let tip = node.chain.tip_hash();
    drop(node);
    let restored = NodeState::open(&blocks, genesis).unwrap();
    assert_eq!(restored.chain.tip_hash(), tip);
    assert_eq!(restored.pending_count(), 0);
    drop(restored);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn mainnet_pow_binds_all_block_fields_and_wide_transaction_count() {
    let (root, genesis, transactions, miner) = fixture(17);
    let mut node = NodeState::open(&root.join("blocks"), genesis).unwrap();
    node.accept_batch(&encode_batch(&transactions).unwrap())
        .unwrap();
    let mut block = node
        .candidate(&miner, node.chain.rewards().tip_timestamp() + 30)
        .unwrap();
    block.mine().unwrap();
    let hash = block.hash().unwrap();
    assert_eq!(
        BlockV3::decode(&block.encode().unwrap())
            .unwrap()
            .transactions
            .len(),
        17
    );
    let mut changed = block.clone();
    changed.transactions[0].fee_nox += 1;
    assert_ne!(hash, changed.hash().unwrap());
    changed = block.clone();
    changed.nonce += 1;
    assert_ne!(hash, changed.hash().unwrap());
    changed = block.clone();
    changed.reward.timestamp += 1;
    assert_ne!(hash, changed.hash().unwrap());
    node.import_block(block).unwrap();
    drop(node);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn batch_decoder_rejects_unbounded_and_trailing_input() {
    assert!(decode_batch(&[]).is_err());
    assert!(decode_batch(&0u16.to_le_bytes()).is_err());
    assert!(decode_batch(&((MAX_BATCH_TXS + 1) as u16).to_le_bytes()).is_err());
    assert!(decode_batch(&[1, 0, 255, 255, 255, 255]).is_err());
}

#[test]
#[ignore = "real TCP, disk, PoW and confirmation-depth pipeline; accelerated block timestamps, not sustained deployed TPS"]
fn benchmark_local_confirmed_pipeline() {
    let count = std::env::var("TENEBRA_BENCH_TRANSACTIONS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1_024);
    let (root, genesis, transactions, miner) = fixture(count);
    let state = Arc::new(Mutex::new(
        NodeState::open(&root.join("blocks"), genesis.clone()).unwrap(),
    ));
    let workload_ids: HashSet<_> = transactions.iter().map(|tx| tx.txid().unwrap()).collect();
    let confirmed_workload = |node: &NodeState| -> usize {
        node.chain
            .blocks()
            .iter()
            .take(node.chain.blocks().len().saturating_sub(CONFIRMATION_DEPTH))
            .flat_map(|block| block.transactions.iter())
            .filter(|tx| workload_ids.contains(&tx.txid().unwrap()))
            .count()
    };
    let frames: Vec<_> = transactions
        .chunks(MAX_BATCH_TXS)
        .map(|batch| encode_batch(batch).unwrap())
        .collect();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server_state = Arc::clone(&state);
    let requests = frames.len();
    let server = thread::spawn(move || {
        for _ in 0..requests {
            let (stream, _) = listener.accept().unwrap();
            handle_connection(stream, &server_state).unwrap();
        }
    });
    let start = std::time::Instant::now();
    for (frame, txs) in frames.iter().zip(transactions.chunks(MAX_BATCH_TXS)) {
        let mut stream = connect(&address.to_string(), genesis.genesis_hash()).unwrap();
        send_batch(&mut stream, frame, txs).unwrap();
    }
    server.join().unwrap();
    let accepted = start.elapsed();
    let mut blocks_mined = 0;
    while confirmed_workload(&state.lock().unwrap()) < count
        || state.lock().unwrap().pending_count() > 0
    {
        let mut node = state.lock().unwrap();
        let mut block = node
            .candidate(&miner, node.chain.rewards().tip_timestamp() + 30)
            .unwrap();
        block.mine().unwrap();
        node.import_block(block).unwrap();
        blocks_mined += 1;
        assert!(blocks_mined <= CONFIRMATION_DEPTH + count.div_ceil(MAX_TXS) + 4);
    }
    let elapsed = start.elapsed();
    assert_eq!(confirmed_workload(&state.lock().unwrap()), count);
    eprintln!("benchmark_scope=local_TCP_durable_PoW_confirmations_accelerated_timestamps");
    eprintln!(
        "measured_transactions={count} confirmation_depth={CONFIRMATION_DEPTH} blocks_mined={blocks_mined}"
    );
    eprintln!(
        "accept_ms={:.2} complete_ms={:.2} local_confirmed_pipeline_tps={:.2}",
        accepted.as_secs_f64() * 1000.0,
        elapsed.as_secs_f64() * 1000.0,
        count as f64 / elapsed.as_secs_f64()
    );
    eprintln!("sustained_deployed_mainnet_tps=NOT_MEASURED");
    let tip = state.lock().unwrap().chain.tip_hash();
    drop(state);
    let restored = NodeState::open(&root.join("blocks"), genesis).unwrap();
    assert_eq!(restored.chain.tip_hash(), tip);
    drop(restored);
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[ignore = "sustained local wall-clock TPS gate: prepares 20,000 proofs then runs 14 real 30-second intervals"]
fn benchmark_sustained_confirmed_tps() {
    const PER_BLOCK: usize = 5_000;
    const LOAD_BLOCKS: usize = 4;
    const INTERVAL_SECONDS: u64 = 30;
    let count = PER_BLOCK * LOAD_BLOCKS;
    eprintln!("phase=preparing_valid_chain_and_{count}_unique_signed_transactions");
    let (root, genesis, transactions, miner) = fixture(count);
    let state = Arc::new(Mutex::new(
        NodeState::open(&root.join("blocks"), genesis.clone()).unwrap(),
    ));
    let workload_ids: HashSet<_> = transactions.iter().map(|tx| tx.txid().unwrap()).collect();
    let confirmed_workload = |node: &NodeState| -> usize {
        node.chain
            .blocks()
            .iter()
            .take(node.chain.blocks().len().saturating_sub(CONFIRMATION_DEPTH))
            .flat_map(|block| block.transactions.iter())
            .filter(|tx| workload_ids.contains(&tx.txid().unwrap()))
            .count()
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server_state = Arc::clone(&state);
    let requests = LOAD_BLOCKS * PER_BLOCK.div_ceil(MAX_BATCH_TXS);
    let server = thread::spawn(move || {
        for _ in 0..requests {
            let (stream, _) = listener.accept().unwrap();
            handle_connection(stream, &server_state).unwrap();
        }
    });
    let start = std::time::Instant::now();
    let mut first_confirmation = None;
    let mut first_count = 0;
    let mut previous_confirmation = None;
    let mut previous_count = 0;
    let mut minimum_window_tps = f64::INFINITY;
    eprintln!(
        "phase=wall_clock_test interval_seconds={INTERVAL_SECONDS} confirmation_depth={CONFIRMATION_DEPTH}"
    );
    for step in 0..LOAD_BLOCKS + CONFIRMATION_DEPTH {
        if step < LOAD_BLOCKS {
            for txs in transactions[step * PER_BLOCK..(step + 1) * PER_BLOCK].chunks(MAX_BATCH_TXS)
            {
                let bytes = encode_batch(txs).unwrap();
                let mut stream = connect(&address.to_string(), genesis.genesis_hash()).unwrap();
                send_batch(&mut stream, &bytes, txs).unwrap();
            }
        }
        let deadline = start + Duration::from_secs((step as u64 + 1) * INTERVAL_SECONDS);
        if let Some(wait) = deadline.checked_duration_since(std::time::Instant::now()) {
            thread::sleep(wait);
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut node = state.lock().unwrap();
        // Real UTC timestamp; real proof of work; normal validation and disk commit.
        let mut block = node
            .candidate(&miner, now.max(node.chain.rewards().tip_timestamp() + 1))
            .unwrap();
        let included = block.transactions.len();
        block.mine().unwrap();
        node.import_block(block).unwrap();
        let confirmed = confirmed_workload(&node);
        let observed = std::time::Instant::now();
        if confirmed > 0 && first_confirmation.is_none() {
            first_confirmation = Some(observed);
            first_count = confirmed;
        }
        if confirmed > previous_count {
            if let Some(previous) = previous_confirmation {
                let rate = (confirmed - previous_count) as f64
                    / observed.duration_since(previous).as_secs_f64();
                minimum_window_tps = minimum_window_tps.min(rate);
                eprintln!("confirmed_window_tps={rate:.2}");
            }
            previous_confirmation = Some(observed);
            previous_count = confirmed;
        }
        eprintln!(
            "paced_block={} included={included} confirmed_workload={confirmed} pending={} elapsed_seconds={:.2}",
            step + 1,
            node.pending_count(),
            start.elapsed().as_secs_f64()
        );
    }
    server.join().unwrap();
    let node = state.lock().unwrap();
    assert_eq!(confirmed_workload(&node), count);
    assert_eq!(node.pending_count(), 0);
    let confirmation_window = previous_confirmation
        .unwrap()
        .duration_since(first_confirmation.unwrap())
        .as_secs_f64();
    let steady_tps = (count - first_count) as f64 / confirmation_window;
    let tip = node.chain.tip_hash();
    drop(node);
    drop(state);
    // Recovery is required as well as an in-memory counter.
    let restored = NodeState::open(&root.join("blocks"), genesis).unwrap();
    assert_eq!(restored.chain.tip_hash(), tip);
    assert_eq!(confirmed_workload(&restored), count);
    drop(restored);
    fs::remove_dir_all(root).unwrap();
    eprintln!(
        "benchmark_scope=single_local_node_TCP_disk_real_UTC_PoW_ten_successor_confirmations"
    );
    eprintln!("steady_confirmation_window_seconds={confirmation_window:.2}");
    eprintln!(
        "steady_confirmed_tps={steady_tps:.2} minimum_window_confirmed_tps={minimum_window_tps:.2}"
    );
    eprintln!("external_server_tps=NOT_MEASURED public_network_competition=NOT_MEASURED");
    assert!(
        confirmation_window >= 85.0,
        "not a sustained measurement window"
    );
    assert!(
        steady_tps >= 150.0 && minimum_window_tps >= 150.0,
        "150 confirmed TPS gate failed"
    );
}

#[test]
fn incremental_sync_checks_links_and_matches_persisted_tip() {
    let (source_root, genesis, _, _) = fixture(1);
    let source = Mutex::new(NodeState::open(&source_root.join("blocks"), genesis.clone()).unwrap());
    let expected = source.lock().unwrap().chain.tip_hash();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        handle_connection(stream, &source).unwrap();
    });
    let target_root = unique_directory();
    let target = Mutex::new(NodeState::open(&target_root.join("blocks"), genesis.clone()).unwrap());
    assert_eq!(sync_state(&address.to_string(), &target).unwrap(), 11);
    server.join().unwrap();
    assert_eq!(target.lock().unwrap().chain.tip_hash(), expected);
    drop(target);
    let restored = NodeState::open(&target_root.join("blocks"), genesis).unwrap();
    assert_eq!(restored.chain.tip_hash(), expected);
    drop(restored);
    fs::remove_dir_all(source_root).unwrap();
    fs::remove_dir_all(target_root).unwrap();
}

#[test]
fn public_pending_pages_are_validated_and_persisted_by_another_node() {
    let (source_root, genesis, transactions, _) = fixture(18);
    let mut source = NodeState::open(&source_root.join("blocks"), genesis.clone()).unwrap();
    source
        .accept_batch(&encode_batch(&transactions).unwrap())
        .unwrap();
    let target_root = unique_directory();
    for block in source.chain.blocks() {
        persist_block(&target_root.join("blocks"), block).unwrap();
    }
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let state = Mutex::new(source);
        for _ in 0..2 {
            let (stream, _) = listener.accept().unwrap();
            handle_connection(stream, &state).unwrap();
        }
    });
    let target = Mutex::new(NodeState::open(&target_root.join("blocks"), genesis.clone()).unwrap());
    sync_pending(&address.to_string(), &target).unwrap();
    assert_eq!(target.lock().unwrap().pending_count(), 18);
    server.join().unwrap();
    drop(target);
    let restored = NodeState::open(&target_root.join("blocks"), genesis).unwrap();
    assert_eq!(restored.pending_count(), 18);
    drop(restored);
    fs::remove_dir_all(source_root).unwrap();
    fs::remove_dir_all(target_root).unwrap();
}

#[test]
fn cached_runtime_rejects_foreign_handshakes_and_accepts_public_status() {
    let root = unique_directory();
    let genesis = network::pinned_genesis().unwrap();
    let hash = genesis.genesis_hash();
    let state = Mutex::new(NodeState::open(&root.join("blocks"), genesis).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        for valid in [false, false, true] {
            let (stream, _) = listener.accept().unwrap();
            assert_eq!(handle_connection(stream, &state).is_ok(), valid);
        }
    });
    for wrong_genesis in [false, true] {
        let mut stream = TcpStream::connect(address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .write_all(if wrong_genesis {
                network::PEER_MAGIC
            } else {
                b"TSC1P3V8"
            })
            .unwrap();
        stream
            .write_all(if wrong_genesis { &[0; 32] } else { &hash })
            .unwrap();
        assert!(read_array::<8>(&mut stream).is_err());
    }
    let (height, _, confirmed, pending) = query_status(&address.to_string()).unwrap();
    assert_eq!((height, confirmed, pending), (0, 0, 0));
    server.join().unwrap();
    fs::remove_dir_all(root).unwrap();
}
