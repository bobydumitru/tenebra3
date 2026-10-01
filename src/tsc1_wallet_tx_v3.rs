//! Offline multi-input transaction construction for the isolated v3 devnet.

use crate::assets::TNB_ASSET_ID;
use crate::tsc1_chain_v2::Hash;
use crate::tsc1_chain_v3::{asset_creation_fee_secret, asset_issuer_transfer_fee_secret, asset_transfer_fee_secret, ChainV3, ASSET_CREATION_FEE_NOX};
use crate::tsc1_funded_output::{
    RecoveredOutput, create_funded_output_with_blinding, create_public_fee_output,
};
use crate::tsc1_private_amounts::random_blinding;
use crate::tsc1_spend_state_v2::transaction_output_id;
use crate::tsc1_tx_v2::{
    AUTHORIZATION_BYTES, AuthorizationProof, MAX_INPUTS, NETWORK_ID, RING_SIZE, RingInput, Transaction,
    key_image_for_secret,
};
use crate::{Address, WalletSecrets};
use bulletproofs::PedersenGens;
use curve25519_dalek::scalar::Scalar;
use std::collections::HashSet;

fn random_index(upper: usize) -> Result<usize, &'static str> {
    let upper = upper as u64;
    let zone = u64::MAX - u64::MAX % upper;
    loop {
        let mut bytes = [0u8; 8];
        getrandom::getrandom(&mut bytes).map_err(|_| "OS randomness unavailable")?;
        let value = u64::from_le_bytes(bytes);
        if value < zone {
            return Ok((value % upper) as usize);
        }
    }
}

fn choose_ring(mut eligible: Vec<Hash>, owned: Hash) -> Result<[Hash; RING_SIZE], &'static str> {
    eligible.retain(|id| *id != owned);
    if eligible.len() < RING_SIZE - 1 {
        return Err("not enough mature outputs for a private ring");
    }
    for end in (1..eligible.len()).rev() {
        let index = random_index(end + 1)?;
        eligible.swap(end, index);
    }
    let mut ring: Vec<_> = eligible.into_iter().take(RING_SIZE - 1).collect();
    ring.push(owned);
    ring.sort();
    ring.try_into().map_err(|_| "invalid ring size")
}

type OwnedInput = (Hash, RecoveredOutput, Scalar);

fn select_mature_tnb_inputs(
    chain: &ChainV3,
    wallet: &WalletSecrets,
    required: u64,
) -> Result<(u64, Vec<Hash>, Vec<OwnedInput>, u64), &'static str> {
    let height = chain.height().checked_add(1).ok_or("height overflow")?;
    let spends = chain.spends();
    let eligible = spends
        .eligible_output_ids(height)
        .into_iter()
        .filter(|id| {
            spends
                .output(id)
                .is_some_and(|output| output.amount.asset_id == TNB_ASSET_ID)
        })
        .collect::<Vec<_>>();
    let eligible_set: HashSet<_> = eligible.iter().copied().collect();
    let mut candidates = Vec::with_capacity(eligible.len());
    for block in chain.blocks().iter().rev() {
        for tx in block.transactions.iter().rev() {
            let txid = tx.txid()?;
            candidates.extend(
                (0..tx.outputs.len())
                    .rev()
                    .map(|index| transaction_output_id(txid, index)),
            );
        }
        candidates.push(block.reward.reward_output_id());
    }
    let mut seen = HashSet::with_capacity(candidates.len());
    candidates.retain(|id| eligible_set.contains(id) && seen.insert(*id));
    candidates.extend(eligible.iter().copied().filter(|id| seen.insert(*id)));

    let mut owned_candidates = Vec::new();
    let mut covering_output = None;
    for id in candidates {
        let output = spends.output(&id).ok_or("missing spend output")?;
        let index = spends.output_index(&id).ok_or("missing output index")?;
        if let Some(recovered) = wallet.scan_funded_output(output, index) {
            let secret =
                Option::<Scalar>::from(Scalar::from_canonical_bytes(recovered.one_time_spend))
                    .ok_or("invalid owned spend key")?;
            if !spends.has_spent_image(&key_image_for_secret(secret)) {
                if recovered.amount_nox >= required {
                    covering_output = Some((id, recovered, secret));
                    break;
                }
                owned_candidates.push((id, recovered, secret));
            }
        }
    }

    let mut selected = if let Some(output) = covering_output {
        vec![output]
    } else {
        owned_candidates.sort_unstable_by(|left, right| {
            right
                .1
                .amount_nox
                .cmp(&left.1.amount_nox)
                .then_with(|| left.0.cmp(&right.0))
        });
        owned_candidates.into_iter().take(MAX_INPUTS).collect()
    };
    let mut selected_total = 0u64;
    for (_, output, _) in &selected {
        selected_total = selected_total
            .checked_add(output.amount_nox)
            .ok_or("input amount overflow")?;
    }
    if selected_total < required {
        return Err("no mature unspent outputs cover amount and fee");
    }
    selected.shrink_to_fit();
    Ok((height, eligible, selected, selected_total))
}

pub fn create_signed_transfer(
    chain: &ChainV3,
    wallet: &WalletSecrets,
    recipient: &Address,
    amount_nox: u64,
    fee_nox: u64,
) -> Result<Transaction, &'static str> {
    if amount_nox == 0 || fee_nox == 0 {
        return Err("amount and fee must be positive");
    }
    let required = amount_nox
        .checked_add(fee_nox)
        .ok_or("amount plus fee overflow")?;
    let spends = chain.spends();
    let (height, eligible, selected, selected_total) =
        select_mature_tnb_inputs(chain, wallet, required)?;
    let recipient_blinding = random_blinding().map_err(|_| "OS randomness unavailable")?;
    let mut outputs = vec![create_funded_output_with_blinding(
        recipient,
        0,
        amount_nox,
        recipient_blinding,
    )?];
    if crate::network::IS_MAINNET
        && height >= crate::tsc1_fee::FEE_POLICY_ACTIVATION_HEIGHT
    {
        crate::tsc1_private_amounts::attach_tnb_transfer_fee_proof(
            &mut outputs[0].amount,
            amount_nox,
            fee_nox,
            &recipient_blinding,
        )
        .map_err(|_| "failed to prove the 1 percent TNB transfer fee")?;
    }
    let change = selected_total - required;
    let mut output_blinding = recipient_blinding;
    if change > 0 {
        let change_blinding = random_blinding().map_err(|_| "OS randomness unavailable")?;
        outputs.push(create_funded_output_with_blinding(
            &wallet.address(),
            1,
            change,
            change_blinding,
        )?);
        output_blinding += change_blinding;
    }
    let placeholder = AuthorizationProof {
        challenge: Scalar::ONE,
        key_responses: [Scalar::ONE; RING_SIZE],
        amount_responses: [Scalar::ONE; RING_SIZE],
    }
    .encode();
    debug_assert_eq!(placeholder.len(), AUTHORIZATION_BYTES);
    let mut pseudo_blindings = Vec::with_capacity(selected.len());
    let mut remaining_blinding = output_blinding;
    for _ in 1..selected.len() {
        let blinding = random_blinding().map_err(|_| "OS randomness unavailable")?;
        pseudo_blindings.push(blinding);
        remaining_blinding -= blinding;
    }
    pseudo_blindings.push(remaining_blinding);
    let generators = PedersenGens::default();
    let mut inputs = Vec::with_capacity(selected.len());
    for ((owned_id, owned, secret), pseudo_blinding) in
        selected.iter().zip(pseudo_blindings.iter())
    {
        inputs.push(RingInput {
            asset_id: TNB_ASSET_ID,
            members: choose_ring(eligible.clone(), *owned_id)?,
            key_image: key_image_for_secret(*secret),
            pseudo_output: generators
                .commit(Scalar::from(owned.amount_nox), *pseudo_blinding)
                .compress()
                .to_bytes(),
            authorization: placeholder.clone(),
        });
    }
    let mut tx = Transaction {
        network_id: NETWORK_ID,
        version: 2,
        expires_at_height: height.checked_add(10).ok_or("expiry overflow")?,
        inputs,
        outputs,
        fee_nox,
    };
    let statements = tx.ring_statements_with(height, |id| spends.output(id))?;
    let signing_hash = tx.signing_hash()?;
    for (index, ((owned_id, owned, secret), pseudo_blinding)) in selected
        .iter()
        .zip(pseudo_blindings.iter())
        .enumerate()
    {
        let signer = tx.inputs[index]
            .members
            .iter()
            .position(|id| id == owned_id)
            .ok_or("owned output missing from ring")?;
        tx.inputs[index].authorization = AuthorizationProof::sign(
            &signing_hash,
            tx.inputs[index].key_image,
            &statements[index],
            signer,
            *secret,
            owned.blinding - pseudo_blinding,
        )?
        .encode();
    }
    let mut staged = spends.clone();
    staged.apply_batch(&[tx.clone()], height)?;
    Ok(tx)
}

pub fn create_signed_asset_creation_fee(
    chain: &ChainV3,
    wallet: &WalletSecrets,
    asset_txid: Hash,
) -> Result<Transaction, &'static str> {
    create_signed_asset_creation_fee_amount(chain, wallet, asset_txid, ASSET_CREATION_FEE_NOX)
}

pub fn create_signed_asset_creation_fee_for_asset(
    chain: &ChainV3,
    wallet: &WalletSecrets,
    asset_transaction: &crate::assets::AssetTransaction,
) -> Result<Transaction, &'static str> {
    let fee_expiry_height = chain.height().checked_add(11).ok_or("fee expiry overflow")?;
    let amount = crate::tsc1_chain_v3::asset_creation_fee_nox(asset_transaction, fee_expiry_height)?;
    create_signed_asset_creation_fee_amount(chain, wallet, asset_transaction.txid()?, amount)
}

fn create_signed_asset_creation_fee_amount(
    chain: &ChainV3,
    wallet: &WalletSecrets,
    asset_txid: Hash,
    amount: u64,
) -> Result<Transaction, &'static str> {
    let address = Address::parse(include_str!("../config/treasury-address.txt"))?;
    create_signed_asset_operation_fee(
        chain,
        wallet,
        vec![(address, amount, asset_creation_fee_secret(asset_txid))],
        "no mature unspent outputs cover asset creation fee",
    )
}

pub fn create_signed_asset_transfer_fee(
    chain: &ChainV3,
    wallet: &WalletSecrets,
    asset_txid: Hash,
    network_fee_nox: u64,
    issuer_fee_nox: u64,
    issuer_treasury: Option<Address>,
) -> Result<Transaction, &'static str> {
    let network_treasury = Address::parse(include_str!("../config/treasury-address.txt"))?;
    let mut fee_outputs = vec![(network_treasury, network_fee_nox, asset_transfer_fee_secret(asset_txid))];
    if issuer_fee_nox > 0 {
        fee_outputs.push((issuer_treasury.ok_or("issuer fee treasury missing")?, issuer_fee_nox, asset_issuer_transfer_fee_secret(asset_txid)));
    } else if issuer_treasury.is_some() {
        return Err("unexpected issuer fee treasury");
    }
    create_signed_asset_operation_fee(
        chain,
        wallet,
        fee_outputs,
        "no mature unspent outputs cover asset transfer fee",
    )
}

fn create_signed_asset_operation_fee(
    chain: &ChainV3,
    wallet: &WalletSecrets,
    fee_outputs: Vec<(Address, u64, Scalar)>,
    insufficient_funds_message: &'static str,
) -> Result<Transaction, &'static str> {
    if fee_outputs.is_empty() || fee_outputs.iter().any(|(_, amount, _)| *amount == 0) { return Err("asset operation fee must be positive"); }
    let total_fee = fee_outputs.iter().try_fold(0u64, |sum, (_, amount, _)| sum.checked_add(*amount).ok_or("fee overflow"))?;
    let mut outputs = fee_outputs.iter().map(|(address, amount, secret)| create_public_fee_output(address, *amount, *secret)).collect::<Result<Vec<_>, _>>()?;
    let required = total_fee.checked_add(1).ok_or("fee overflow")?;
    let spends = chain.spends();
    let (height, eligible, selected, selected_total) =
        select_mature_tnb_inputs(chain, wallet, required)
            .map_err(|_| insufficient_funds_message)?;
    let change = selected_total - required;
    let mut output_blinding = Scalar::ZERO;
    if change > 0 {
        let change_blinding = random_blinding().map_err(|_| "OS randomness unavailable")?;
        outputs.push(create_funded_output_with_blinding(
            &wallet.address(),
            1,
            change,
            change_blinding,
        )?);
        output_blinding = change_blinding;
    }
    let placeholder = AuthorizationProof {
        challenge: Scalar::ONE,
        key_responses: [Scalar::ONE; RING_SIZE],
        amount_responses: [Scalar::ONE; RING_SIZE],
    }
    .encode();
    let mut pseudo_blindings = Vec::with_capacity(selected.len());
    let mut remaining_blinding = output_blinding;
    for _ in 1..selected.len() {
        let blinding = random_blinding().map_err(|_| "OS randomness unavailable")?;
        pseudo_blindings.push(blinding);
        remaining_blinding -= blinding;
    }
    pseudo_blindings.push(remaining_blinding);
    let generators = PedersenGens::default();
    let mut inputs = Vec::with_capacity(selected.len());
    for ((owned_id, owned, secret), pseudo_blinding) in
        selected.iter().zip(pseudo_blindings.iter())
    {
        inputs.push(RingInput {
            asset_id: TNB_ASSET_ID,
            members: choose_ring(eligible.clone(), *owned_id)?,
            key_image: key_image_for_secret(*secret),
            pseudo_output: generators
                .commit(Scalar::from(owned.amount_nox), *pseudo_blinding)
                .compress()
                .to_bytes(),
            authorization: placeholder.clone(),
        });
    }
    let mut tx = Transaction {
        network_id: NETWORK_ID,
        version: 2,
        expires_at_height: height.checked_add(10).ok_or("height overflow")?,
        inputs,
        outputs,
        fee_nox: 1,
    };
    let statements = tx.ring_statements_with(height, |id| spends.output(id))?;
    let signing_hash = tx.signing_hash()?;
    for (index, ((owned_id, owned, secret), pseudo_blinding)) in selected
        .iter()
        .zip(pseudo_blindings.iter())
        .enumerate()
    {
        let signer = tx.inputs[index]
            .members
            .iter()
            .position(|id| id == owned_id)
            .ok_or("owned output missing from ring")?;
        tx.inputs[index].authorization = AuthorizationProof::sign(
            &signing_hash,
            tx.inputs[index].key_image,
            &statements[index],
            signer,
            *secret,
            owned.blinding - pseudo_blinding,
        )?
        .encode();
    }
    Ok(tx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FOUNDER_ALLOCATION_NOX;
    use crate::tsc1_chain_v2::{Chain, reward_at_height};
    use crate::tsc1_chain_v3::{load_blocks, persist_block};
    use crate::tsc1_funded_output::create_reward_output;
    use crate::tsc1_peer_v3::{
        publish_block, serve_connection_with_genesis, serve_connection_with_peers, submit,
    };
    use crate::tsc1_pending_v3::{load_pending, remove_included};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    // Synthetic servers below bypass the production connection entry point.
    // Mirror its candidate handshake here; production validation is unchanged.
    fn candidate_handshake_for_test(mut stream: &std::net::TcpStream) {
        if !crate::network::IS_MAINNET {
            return;
        }
        use std::io::{Read, Write};
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        let mut magic = [0; 8];
        let mut genesis = [0; 32];
        stream.read_exact(&mut magic).unwrap();
        stream.read_exact(&mut genesis).unwrap();
        assert_eq!(&magic, crate::network::PEER_MAGIC);
        assert_eq!(
            genesis,
            crate::network::pinned_genesis().unwrap().genesis_hash()
        );
        stream.write_all(crate::network::PEER_MAGIC).unwrap();
    }

    #[test]
    fn signed_transfer_with_change_enters_mined_block() {
        let founder = WalletSecrets::from_seed(&[101; 32]);
        let recipient = WalletSecrets::from_seed(&[102; 32]);
        let genesis = Chain::new(
            create_reward_output(&founder.address(), 0, FOUNDER_ALLOCATION_NOX).unwrap(),
            1,
        )
        .unwrap();
        let genesis_for_server = genesis.clone();
        let mut nonce = [0u8; 8];
        getrandom::getrandom(&mut nonce).unwrap();
        let root =
            std::env::temp_dir().join(format!("tsc1-v3-pending-test-{}", hex::encode(nonce)));
        std::fs::create_dir(&root).unwrap();
        let blocks_dir = root.join("blocks");
        let peer_b_blocks = root.join("peer-b").join("blocks");
        let mut chain = ChainV3::from_genesis(genesis).unwrap();
        for height in 1..=25 {
            let miner = WalletSecrets::from_seed(&[height as u8; 32]);
            let reward =
                create_reward_output(&miner.address(), 0, reward_at_height(height)).unwrap();
            let mut block = chain.next_block(reward, height + 1, Vec::new());
            block.mine().unwrap();
            persist_block(&blocks_dir, &block).unwrap();
            persist_block(&peer_b_blocks, &block).unwrap();
            chain.append(block).unwrap();
        }
        let tx = create_signed_transfer(&chain, &founder, &recipient.address(), 100, 10).unwrap();
        assert_eq!(tx.outputs.len(), 2);
        let peer_b_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let peer_b_address = peer_b_listener.local_addr().unwrap();
        let peer_b_dir = peer_b_blocks.clone();
        let peer_b_genesis = genesis_for_server.clone();
        let genesis_for_verify = genesis_for_server.clone();
        let (peer_b_ready, peer_b_received) = mpsc::channel();
        let peer_b_server = thread::spawn(move || {
            for request in 0..2 {
                let (stream, _) = peer_b_listener.accept().unwrap();
                candidate_handshake_for_test(&stream);
                serve_connection_with_genesis(stream, &peer_b_dir, peer_b_genesis.clone()).unwrap();
                if request == 0 {
                    peer_b_ready.send(()).unwrap();
                }
            }
        });
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server_dir = blocks_dir.clone();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            candidate_handshake_for_test(&stream);
            serve_connection_with_peers(
                stream,
                &server_dir,
                genesis_for_server,
                vec![peer_b_address.to_string()],
            )
            .unwrap();
        });
        let txid = submit(&address.to_string(), &tx.encode().unwrap()).unwrap();
        server.join().unwrap();
        peer_b_received
            .recv_timeout(Duration::from_secs(30))
            .unwrap();
        assert_eq!(txid, tx.txid().unwrap());
        let queued = load_pending(&blocks_dir, &chain).unwrap();
        assert_eq!(queued.len(), 1);
        assert_eq!(load_pending(&peer_b_blocks, &chain).unwrap().len(), 1);
        let miner = WalletSecrets::from_seed(&[103; 32]);
        let reward = create_reward_output(&miner.address(), 0, reward_at_height(26)).unwrap();
        let mut block = chain
            .next_block_with_fees(reward, &miner.address(), 27, queued)
            .unwrap();
        block.mine().unwrap();
        let included = block.transactions.clone();
        chain.append(block).unwrap();
        let change_id = transaction_output_id(tx.txid().unwrap(), 1);
        let larger_transfer =
            create_signed_transfer(&chain, &founder, &recipient.address(), 2_000, 20).unwrap();
        assert!(larger_transfer.inputs[0].members.contains(&change_id));
        persist_block(&blocks_dir, chain.blocks().last().unwrap()).unwrap();
        remove_included(&blocks_dir, &included).unwrap();
        publish_block(&peer_b_address.to_string(), chain.blocks().last().unwrap()).unwrap();
        peer_b_server.join().unwrap();
        assert_eq!(
            load_blocks(&peer_b_blocks, genesis_for_verify)
                .unwrap()
                .tip_hash(),
            chain.tip_hash(),
        );
        assert_eq!(chain.wallet_balance_nox(&recipient), Ok(100));
        assert_eq!(
            chain.wallet_balance_nox(&founder),
            Ok(FOUNDER_ALLOCATION_NOX - 110)
        );
        assert!(load_pending(&blocks_dir, &chain).unwrap().is_empty());
        for height in 1..=26 {
            std::fs::remove_file(blocks_dir.join(format!("{height:020}.bin"))).unwrap();
            std::fs::remove_file(peer_b_blocks.join(format!("{height:020}.bin"))).unwrap();
        }
        std::fs::remove_dir(blocks_dir).unwrap();
        std::fs::remove_dir(peer_b_blocks).unwrap();
        std::fs::remove_dir(root.join("peer-b").join("pending")).unwrap();
        std::fs::remove_dir(root.join("peer-b")).unwrap();
        std::fs::remove_dir(root.join("pending")).unwrap();
        std::fs::remove_dir(root).unwrap();
    }
}
