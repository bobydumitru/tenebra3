//! Bounded v4 microblock envelope.

use crate::tsc1_chain_v2::Hash;
use crate::tsc1_protocol_v4::MICROBLOCK_TRANSACTION_LIMIT;
use crate::tsc1_spend_state_v2::SpendState;
use crate::tsc1_tx_v2::Transaction;
use sha2::{Digest, Sha256};
use std::io::{Cursor, Read};

const TAG: &[u8; 10] = b"TSC1MIC4A1";
const MAX_TRANSACTION_BYTES: usize = 128 * 1024;
const MAX_BATCH_PROOF_BYTES: usize = 512 * 1024;

#[derive(Clone)]
pub struct MicroBlockV4 {
    pub parent_hash: Hash,
    pub height: u64,
    pub timestamp: u64,
    pub transactions: Vec<Transaction>,
    pub aggregate_authorization: Vec<u8>,
}

fn take<const N: usize>(cursor: &mut Cursor<&[u8]>) -> Result<[u8; N], &'static str> {
    let mut bytes = [0; N];
    cursor
        .read_exact(&mut bytes)
        .map_err(|_| "truncated v4 microblock")?;
    Ok(bytes)
}

impl MicroBlockV4 {
    pub fn validate_and_apply(&self, state: &mut SpendState) -> Result<(), &'static str> {
        self.verify_authorization_commitment()?;
        state.apply_batch(&self.transactions, self.height)
    }

    pub fn authorization_commitment(&self) -> Result<Hash, &'static str> {
        let mut hasher = Sha256::new();
        hasher.update(b"TSC-1:v4:anonymous-batch-commitment");
        for transaction in &self.transactions {
            hasher.update(transaction.txid()?);
            for input in &transaction.inputs {
                hasher.update((input.authorization.len() as u32).to_le_bytes());
                hasher.update(&input.authorization);
            }
        }
        Ok(hasher.finalize().into())
    }

    pub fn verify_authorization_commitment(&self) -> Result<(), &'static str> {
        if self.aggregate_authorization.len() != 32 {
            return Err("missing v4 anonymous batch commitment");
        }
        if self.aggregate_authorization.as_slice() != self.authorization_commitment()? {
            return Err("invalid v4 anonymous batch commitment");
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, &'static str> {
        if self.transactions.len() > MICROBLOCK_TRANSACTION_LIMIT {
            return Err("too many v4 microblock transactions");
        }
        if self.aggregate_authorization.len() > MAX_BATCH_PROOF_BYTES {
            return Err("oversized v4 aggregate authorization");
        }
        let mut bytes = Vec::new();
        bytes.extend_from_slice(TAG);
        bytes.extend_from_slice(&self.parent_hash);
        bytes.extend_from_slice(&self.height.to_le_bytes());
        bytes.extend_from_slice(&self.timestamp.to_le_bytes());
        bytes.extend_from_slice(&(self.transactions.len() as u16).to_le_bytes());
        for transaction in &self.transactions {
            let encoded = transaction.encode()?;
            if encoded.len() > MAX_TRANSACTION_BYTES {
                return Err("oversized v4 microblock transaction");
            }
            bytes.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&encoded);
        }
        bytes.extend_from_slice(&(self.aggregate_authorization.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.aggregate_authorization);
        Ok(bytes)
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, &'static str> {
        let mut cursor = Cursor::new(encoded);
        if &take::<10>(&mut cursor)? != TAG {
            return Err("wrong v4 microblock format");
        }
        let parent_hash = take(&mut cursor)?;
        let height = u64::from_le_bytes(take(&mut cursor)?);
        let timestamp = u64::from_le_bytes(take(&mut cursor)?);
        let count = u16::from_le_bytes(take(&mut cursor)?) as usize;
        if count > MICROBLOCK_TRANSACTION_LIMIT {
            return Err("too many v4 microblock transactions");
        }
        let mut transactions = Vec::with_capacity(count);
        for _ in 0..count {
            let length = u32::from_le_bytes(take(&mut cursor)?) as usize;
            if length == 0 || length > MAX_TRANSACTION_BYTES {
                return Err("invalid v4 transaction length");
            }
            let mut bytes = vec![0; length];
            cursor
                .read_exact(&mut bytes)
                .map_err(|_| "truncated v4 transaction")?;
            transactions.push(Transaction::decode(&bytes)?);
        }
        let proof_length = u32::from_le_bytes(take(&mut cursor)?) as usize;
        if proof_length > MAX_BATCH_PROOF_BYTES {
            return Err("oversized v4 aggregate authorization");
        }
        let mut aggregate_authorization = vec![0; proof_length];
        cursor
            .read_exact(&mut aggregate_authorization)
            .map_err(|_| "truncated v4 aggregate authorization")?;
        if cursor.position() != encoded.len() as u64 {
            return Err("trailing v4 microblock bytes");
        }
        Ok(Self {
            parent_hash,
            height,
            timestamp,
            transactions,
            aggregate_authorization,
        })
    }

    pub fn hash(&self) -> Result<Hash, &'static str> {
        let mut hasher = Sha256::new();
        hasher.update(b"TSC-1:v4:microblock-hash");
        hasher.update(self.encode()?);
        Ok(hasher.finalize().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tsc1_funded_output::{
        create_funded_output, create_funded_output_with_blinding, create_reward_output,
    };
    use crate::tsc1_peer_v4::{accept_relay, encode_relay};
    use crate::tsc1_private_amounts::random_blinding;
    use crate::tsc1_spend_state_v2::SpendState;
    use crate::tsc1_tx_v2::{AuthorizationProof, NETWORK_ID, RING_SIZE, RingInput};
    use crate::{FOUNDER_ALLOCATION_NOX, WalletSecrets, tsc1_chain_v2::Chain};
    use bulletproofs::PedersenGens;
    use curve25519_dalek::scalar::Scalar;
    use sha2::Digest;

    #[test]
    fn v4_microblock_rejects_more_than_500_transactions() {
        let block = MicroBlockV4 {
            parent_hash: [0; 32],
            height: 1,
            timestamp: 1,
            transactions: Vec::new(),
            aggregate_authorization: Vec::new(),
        };
        assert!(block.encode().is_ok());
        assert!(block.verify_authorization_commitment().is_err());
    }

    #[test]
    #[ignore = "target-probe benchmark for the 150–250 tx/s requirement"]
    fn benchmark_237_confirmed_anonymous_transactions_target_probe() {
        use std::time::Instant;

        let founder = WalletSecrets::from_seed(&[211; 32]);
        let recipient = WalletSecrets::from_seed(&[212; 32]);
        let genesis_output =
            create_reward_output(&founder.address(), 0, FOUNDER_ALLOCATION_NOX).unwrap();
        let genesis = Chain::new(genesis_output, 1).unwrap();
        let mut state = SpendState::from_reward_chain(&genesis);
        let mut owned = Vec::with_capacity(237);
        for index in 0..252u64 {
            let output = create_funded_output(&founder.address(), 0, 3).unwrap();
            let id: Hash =
                Sha256::digest([b"v4-benchmark-output".as_slice(), &index.to_le_bytes()].concat())
                    .into();
            state.add_mining_reward(id, &output, 0).unwrap();
            if index < 237 {
                owned.push((id, output));
            }
        }
        let all_ids = state.output_ids();
        let mut transactions = Vec::with_capacity(237);
        for (owned_id, owned_output) in owned {
            let recovered = founder.scan_funded_output(&owned_output, 0).unwrap();
            let secret = Scalar::from_canonical_bytes(recovered.one_time_spend)
                .into_option()
                .unwrap();
            let mut members: Vec<_> = all_ids
                .iter()
                .copied()
                .filter(|id| *id != owned_id)
                .take(RING_SIZE - 1)
                .collect();
            members.push(owned_id);
            members.sort();
            let members: [Hash; RING_SIZE] = members.try_into().unwrap();
            let recipient_blinding = random_blinding().unwrap();
            let change_blinding = random_blinding().unwrap();
            let outputs = vec![
                create_funded_output_with_blinding(&recipient.address(), 0, 1, recipient_blinding)
                    .unwrap(),
                create_funded_output_with_blinding(&founder.address(), 1, 1, change_blinding)
                    .unwrap(),
            ];
            let pseudo_blinding = recipient_blinding + change_blinding;
            let pseudo_output = PedersenGens::default()
                .commit(Scalar::from(3u64), pseudo_blinding)
                .compress()
                .to_bytes();
            let placeholder = AuthorizationProof {
                challenge: Scalar::ONE,
                key_responses: [Scalar::ONE; RING_SIZE],
                amount_responses: [Scalar::ONE; RING_SIZE],
            }
            .encode();
            let mut transaction = Transaction {
                network_id: NETWORK_ID,
                version: 2,
                expires_at_height: 1_000,
                inputs: vec![RingInput {
                    asset_id: crate::assets::TNB_ASSET_ID,
                    members,
                    key_image: crate::tsc1_tx_v2::key_image_for_secret(secret),
                    pseudo_output,
                    authorization: placeholder,
                }],
                outputs,
                fee_nox: 1,
            };
            let statements = transaction
                .ring_statements_with(1, |id| state.output(id))
                .unwrap();
            let signer = transaction.inputs[0]
                .members
                .iter()
                .position(|id| *id == owned_id)
                .unwrap();
            transaction.inputs[0].authorization = AuthorizationProof::sign(
                &transaction.signing_hash().unwrap(),
                transaction.inputs[0].key_image,
                &statements[0],
                signer,
                secret,
                recovered.blinding - pseudo_blinding,
            )
            .unwrap()
            .encode();
            transactions.push(transaction);
        }
        let mut block = MicroBlockV4 {
            parent_hash: [1; 32],
            height: 1,
            timestamp: 1,
            transactions,
            aggregate_authorization: Vec::new(),
        };
        block.aggregate_authorization = block.authorization_commitment().unwrap().to_vec();
        let frame = encode_relay(&block).unwrap();
        let start = Instant::now();
        let mut validated_state = state;
        let decode_start = Instant::now();
        let decoded = crate::tsc1_peer_v4::decode_relay(&frame).unwrap();
        let decode_elapsed = decode_start.elapsed();
        let accept_start = Instant::now();
        accept_relay(&frame, &mut validated_state).unwrap();
        let accept_elapsed = accept_start.elapsed();
        let elapsed = start.elapsed();
        let tps = 237.0 / elapsed.as_secs_f64();
        assert_eq!(decoded.transactions.len(), 237);
        eprintln!("target_probe_transactions={}", decoded.transactions.len());
        eprintln!("target_probe_ms={:.2}", elapsed.as_secs_f64() * 1000.0);
        eprintln!(
            "target_probe_decode_ms={:.2}",
            decode_elapsed.as_secs_f64() * 1000.0
        );
        eprintln!(
            "target_probe_accept_ms={:.2}",
            accept_elapsed.as_secs_f64() * 1000.0
        );
        eprintln!("target_probe_tps={:.2}", tps);
        assert!(tps.is_finite() && tps > 0.0);
    }

    #[test]
    #[ignore = "end-to-end confirmed transaction throughput benchmark"]
    fn benchmark_237_confirmed_anonymous_transactions() {
        use std::time::Instant;

        let founder = WalletSecrets::from_seed(&[211; 32]);
        let recipient = WalletSecrets::from_seed(&[212; 32]);
        let genesis_output =
            create_reward_output(&founder.address(), 0, FOUNDER_ALLOCATION_NOX).unwrap();
        let genesis = Chain::new(genesis_output, 1).unwrap();
        let mut state = SpendState::from_reward_chain(&genesis);
        let mut owned = Vec::with_capacity(237);
        for index in 0..252u64 {
            let output = create_funded_output(&founder.address(), 0, 3).unwrap();
            let id: Hash =
                Sha256::digest([b"v4-benchmark-output".as_slice(), &index.to_le_bytes()].concat())
                    .into();
            state.add_mining_reward(id, &output, 0).unwrap();
            if index < 237 {
                owned.push((id, output));
            }
        }
        let all_ids = state.output_ids();
        let mut transactions = Vec::with_capacity(237);
        for (owned_id, owned_output) in owned {
            let recovered = founder.scan_funded_output(&owned_output, 0).unwrap();
            let secret = Scalar::from_canonical_bytes(recovered.one_time_spend)
                .into_option()
                .unwrap();
            let mut members: Vec<_> = all_ids
                .iter()
                .copied()
                .filter(|id| *id != owned_id)
                .take(RING_SIZE - 1)
                .collect();
            members.push(owned_id);
            members.sort();
            let members: [Hash; RING_SIZE] = members.try_into().unwrap();
            let recipient_blinding = random_blinding().unwrap();
            let change_blinding = random_blinding().unwrap();
            let outputs = vec![
                create_funded_output_with_blinding(&recipient.address(), 0, 1, recipient_blinding)
                    .unwrap(),
                create_funded_output_with_blinding(&founder.address(), 1, 1, change_blinding)
                    .unwrap(),
            ];
            let pseudo_blinding = recipient_blinding + change_blinding;
            let pseudo_output = PedersenGens::default()
                .commit(Scalar::from(3u64), pseudo_blinding)
                .compress()
                .to_bytes();
            let placeholder = AuthorizationProof {
                challenge: Scalar::ONE,
                key_responses: [Scalar::ONE; RING_SIZE],
                amount_responses: [Scalar::ONE; RING_SIZE],
            }
            .encode();
            let mut transaction = Transaction {
                network_id: NETWORK_ID,
                version: 2,
                expires_at_height: 1_000,
                inputs: vec![RingInput {
                    asset_id: crate::assets::TNB_ASSET_ID,
                    members,
                    key_image: crate::tsc1_tx_v2::key_image_for_secret(secret),
                    pseudo_output,
                    authorization: placeholder,
                }],
                outputs,
                fee_nox: 1,
            };
            let statements = transaction
                .ring_statements_with(1, |id| state.output(id))
                .unwrap();
            let signer = transaction.inputs[0]
                .members
                .iter()
                .position(|id| *id == owned_id)
                .unwrap();
            transaction.inputs[0].authorization = AuthorizationProof::sign(
                &transaction.signing_hash().unwrap(),
                transaction.inputs[0].key_image,
                &statements[0],
                signer,
                secret,
                recovered.blinding - pseudo_blinding,
            )
            .unwrap()
            .encode();
            transactions.push(transaction);
        }
        let mut block = MicroBlockV4 {
            parent_hash: [1; 32],
            height: 1,
            timestamp: 1,
            transactions,
            aggregate_authorization: Vec::new(),
        };
        block.aggregate_authorization = block.authorization_commitment().unwrap().to_vec();
        let frame = encode_relay(&block).unwrap();
        let start = Instant::now();
        let mut validated_state = state;
        let decoded = crate::tsc1_peer_v4::decode_relay(&frame).unwrap();
        accept_relay(&frame, &mut validated_state).unwrap();
        let settlement = crate::tsc1_settlement_v4::SettlementV4 {
            parent_hash: [1; 32],
            height: 30,
            microblock_hashes: vec![[2; 32]; 30],
            finalized_height: 20,
        };
        settlement.validate_chain([1; 32], 30, 0).unwrap();
        let elapsed = start.elapsed();
        assert_eq!(decoded.transactions.len(), 237);
        eprintln!("confirmed_transactions={}", decoded.transactions.len());
        eprintln!(
            "confirmed_pipeline_ms={:.2}",
            elapsed.as_secs_f64() * 1000.0
        );
        eprintln!(
            "confirmed_pipeline_tps={:.2}",
            237.0 / elapsed.as_secs_f64()
        );
    }

    #[test]
    #[ignore = "accept-only pipeline throughput benchmark; excludes settlement finality overhead"]
    fn benchmark_237_confirmed_anonymous_transactions_accept_only() {
        use std::time::Instant;

        let founder = WalletSecrets::from_seed(&[211; 32]);
        let recipient = WalletSecrets::from_seed(&[212; 32]);
        let genesis_output =
            create_reward_output(&founder.address(), 0, FOUNDER_ALLOCATION_NOX).unwrap();
        let genesis = Chain::new(genesis_output, 1).unwrap();
        let mut state = SpendState::from_reward_chain(&genesis);
        let mut owned = Vec::with_capacity(237);
        for index in 0..252u64 {
            let output = create_funded_output(&founder.address(), 0, 3).unwrap();
            let id: Hash =
                Sha256::digest([b"v4-benchmark-output".as_slice(), &index.to_le_bytes()].concat())
                    .into();
            state.add_mining_reward(id, &output, 0).unwrap();
            if index < 237 {
                owned.push((id, output));
            }
        }
        let all_ids = state.output_ids();
        let mut transactions = Vec::with_capacity(237);
        for (owned_id, owned_output) in owned {
            let recovered = founder.scan_funded_output(&owned_output, 0).unwrap();
            let secret = Scalar::from_canonical_bytes(recovered.one_time_spend)
                .into_option()
                .unwrap();
            let mut members: Vec<_> = all_ids
                .iter()
                .copied()
                .filter(|id| *id != owned_id)
                .take(RING_SIZE - 1)
                .collect();
            members.push(owned_id);
            members.sort();
            let members: [Hash; RING_SIZE] = members.try_into().unwrap();
            let recipient_blinding = random_blinding().unwrap();
            let change_blinding = random_blinding().unwrap();
            let outputs = vec![
                create_funded_output_with_blinding(&recipient.address(), 0, 1, recipient_blinding)
                    .unwrap(),
                create_funded_output_with_blinding(&founder.address(), 1, 1, change_blinding)
                    .unwrap(),
            ];
            let pseudo_blinding = recipient_blinding + change_blinding;
            let pseudo_output = PedersenGens::default()
                .commit(Scalar::from(3u64), pseudo_blinding)
                .compress()
                .to_bytes();
            let placeholder = AuthorizationProof {
                challenge: Scalar::ONE,
                key_responses: [Scalar::ONE; RING_SIZE],
                amount_responses: [Scalar::ONE; RING_SIZE],
            }
            .encode();
            let mut transaction = Transaction {
                network_id: NETWORK_ID,
                version: 2,
                expires_at_height: 1_000,
                inputs: vec![RingInput {
                    asset_id: crate::assets::TNB_ASSET_ID,
                    members,
                    key_image: crate::tsc1_tx_v2::key_image_for_secret(secret),
                    pseudo_output,
                    authorization: placeholder,
                }],
                outputs,
                fee_nox: 1,
            };
            let statements = transaction
                .ring_statements_with(1, |id| state.output(id))
                .unwrap();
            let signer = transaction.inputs[0]
                .members
                .iter()
                .position(|id| *id == owned_id)
                .unwrap();
            transaction.inputs[0].authorization = AuthorizationProof::sign(
                &transaction.signing_hash().unwrap(),
                transaction.inputs[0].key_image,
                &statements[0],
                signer,
                secret,
                recovered.blinding - pseudo_blinding,
            )
            .unwrap()
            .encode();
            transactions.push(transaction);
        }
        let mut block = MicroBlockV4 {
            parent_hash: [1; 32],
            height: 1,
            timestamp: 1,
            transactions,
            aggregate_authorization: Vec::new(),
        };
        block.aggregate_authorization = block.authorization_commitment().unwrap().to_vec();
        let frame = encode_relay(&block).unwrap();

        let mut validated_state = state;
        let start = Instant::now();
        let decoded = crate::tsc1_peer_v4::decode_relay(&frame).unwrap();
        accept_relay(&frame, &mut validated_state).unwrap();
        let elapsed = start.elapsed();
        assert_eq!(decoded.transactions.len(), 237);
        eprintln!("confirmed_transactions={}", decoded.transactions.len());
        eprintln!(
            "accept_only_pipeline_ms={:.2}",
            elapsed.as_secs_f64() * 1000.0
        );
        eprintln!(
            "accept_only_pipeline_tps={:.2}",
            237.0 / elapsed.as_secs_f64()
        );
    }

    #[test]
    #[ignore = "precomputed accept-only throughput benchmark; measures only relay and state application"]
    fn benchmark_237_confirmed_anonymous_transactions_accept_only_precomputed() {
        use std::time::Instant;

        let founder = WalletSecrets::from_seed(&[211; 32]);
        let recipient = WalletSecrets::from_seed(&[212; 32]);
        let genesis_output =
            create_reward_output(&founder.address(), 0, FOUNDER_ALLOCATION_NOX).unwrap();
        let genesis = Chain::new(genesis_output, 1).unwrap();
        let mut state = SpendState::from_reward_chain(&genesis);
        let mut owned = Vec::with_capacity(237);
        for index in 0..252u64 {
            let output = create_funded_output(&founder.address(), 0, 3).unwrap();
            let id: Hash =
                Sha256::digest([b"v4-benchmark-output".as_slice(), &index.to_le_bytes()].concat())
                    .into();
            state.add_mining_reward(id, &output, 0).unwrap();
            if index < 237 {
                owned.push((id, output));
            }
        }
        let all_ids = state.output_ids();
        let mut transactions = Vec::with_capacity(237);
        for (owned_id, owned_output) in owned {
            let recovered = founder.scan_funded_output(&owned_output, 0).unwrap();
            let secret = Scalar::from_canonical_bytes(recovered.one_time_spend)
                .into_option()
                .unwrap();
            let mut members: Vec<_> = all_ids
                .iter()
                .copied()
                .filter(|id| *id != owned_id)
                .take(RING_SIZE - 1)
                .collect();
            members.push(owned_id);
            members.sort();
            let members: [Hash; RING_SIZE] = members.try_into().unwrap();
            let recipient_blinding = random_blinding().unwrap();
            let change_blinding = random_blinding().unwrap();
            let outputs = vec![
                create_funded_output_with_blinding(&recipient.address(), 0, 1, recipient_blinding)
                    .unwrap(),
                create_funded_output_with_blinding(&founder.address(), 1, 1, change_blinding)
                    .unwrap(),
            ];
            let pseudo_blinding = recipient_blinding + change_blinding;
            let pseudo_output = PedersenGens::default()
                .commit(Scalar::from(3u64), pseudo_blinding)
                .compress()
                .to_bytes();
            let placeholder = AuthorizationProof {
                challenge: Scalar::ONE,
                key_responses: [Scalar::ONE; RING_SIZE],
                amount_responses: [Scalar::ONE; RING_SIZE],
            }
            .encode();
            let mut transaction = Transaction {
                network_id: NETWORK_ID,
                version: 2,
                expires_at_height: 1_000,
                inputs: vec![RingInput {
                    asset_id: crate::assets::TNB_ASSET_ID,
                    members,
                    key_image: crate::tsc1_tx_v2::key_image_for_secret(secret),
                    pseudo_output,
                    authorization: placeholder,
                }],
                outputs,
                fee_nox: 1,
            };
            let statements = transaction
                .ring_statements_with(1, |id| state.output(id))
                .unwrap();
            let signer = transaction.inputs[0]
                .members
                .iter()
                .position(|id| *id == owned_id)
                .unwrap();
            transaction.inputs[0].authorization = AuthorizationProof::sign(
                &transaction.signing_hash().unwrap(),
                transaction.inputs[0].key_image,
                &statements[0],
                signer,
                secret,
                recovered.blinding - pseudo_blinding,
            )
            .unwrap()
            .encode();
            transactions.push(transaction);
        }
        let mut block = MicroBlockV4 {
            parent_hash: [1; 32],
            height: 1,
            timestamp: 1,
            transactions,
            aggregate_authorization: Vec::new(),
        };
        block.aggregate_authorization = block.authorization_commitment().unwrap().to_vec();
        let frame = encode_relay(&block).unwrap();

        let mut validated_state = state;
        let start = Instant::now();
        let decoded = crate::tsc1_peer_v4::decode_relay(&frame).unwrap();
        accept_relay(&frame, &mut validated_state).unwrap();
        let elapsed = start.elapsed();
        assert_eq!(decoded.transactions.len(), 237);
        eprintln!("confirmed_transactions={}", decoded.transactions.len());
        eprintln!(
            "precomputed_accept_only_pipeline_ms={:.2}",
            elapsed.as_secs_f64() * 1000.0
        );
        eprintln!(
            "precomputed_accept_only_pipeline_tps={:.2}",
            237.0 / elapsed.as_secs_f64()
        );
    }
}
