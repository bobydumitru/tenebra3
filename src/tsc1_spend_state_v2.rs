//! In-memory atomic spend state for a future transaction-bearing devnet.

use crate::tsc1_chain_v2::{Chain, Hash};
use crate::tsc1_funded_output::FundedOutput;
use crate::tsc1_tx_v2::{AuthorizationProof, Transaction};
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct SpendState {
    outputs: HashMap<Hash, FundedOutput>,
    spent_images: HashSet<Hash>,
    destinations: HashSet<Hash>,
    reward_heights: HashMap<Hash, u64>,
    reward_maturity: u64,
    output_indices: HashMap<Hash, u64>,
    // Only successful cryptographic verification inserts keys. Never persisted.
    verified_proofs: Arc<Mutex<HashSet<Hash>>>,
}

pub fn transaction_output_id(txid: Hash, index: usize) -> Hash {
    let mut hash = Sha256::new();
    hash.update(b"TSC-1:tx-output-id:v1");
    hash.update(txid);
    hash.update((index as u32).to_le_bytes());
    hash.finalize().into()
}

impl SpendState {
    pub fn from_reward_chain(chain: &Chain) -> Self {
        let mut outputs = HashMap::new();
        let mut destinations = HashSet::new();
        let mut reward_heights = HashMap::new();
        let mut output_indices = HashMap::new();
        for block in chain.blocks() {
            outputs.insert(block.reward_output_id(), block.reward_output.clone());
            destinations.insert(block.reward_output.destination.destination);
            reward_heights.insert(block.reward_output_id(), block.height);
            output_indices.insert(block.reward_output_id(), 0);
        }
        Self {
            outputs,
            spent_images: HashSet::new(),
            destinations,
            reward_heights,
            reward_maturity: 0,
            output_indices,
            verified_proofs: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    pub fn with_reward_maturity(mut self, blocks: u64) -> Self {
        self.reward_maturity = blocks;
        self
    }

    pub fn output(&self, id: &Hash) -> Option<&FundedOutput> {
        self.outputs.get(id)
    }

    pub fn output_index(&self, id: &Hash) -> Option<u64> {
        self.output_indices.get(id).copied()
    }

    pub fn eligible_output_ids(&self, height: u64) -> Vec<Hash> {
        self.output_ids()
            .into_iter()
            .filter(|id| {
                self.reward_heights
                    .get(id)
                    .is_none_or(|origin| height >= origin.saturating_add(self.reward_maturity))
            })
            .collect()
    }

    pub fn has_spent_image(&self, image: &Hash) -> bool {
        self.spent_images.contains(image)
    }

    pub fn output_count(&self) -> usize {
        self.outputs.len()
    }

    pub fn output_ids(&self) -> Vec<Hash> {
        let mut ids: Vec<_> = self.outputs.keys().copied().collect();
        ids.sort();
        ids
    }

    pub fn add_reward_output(
        &mut self,
        id: Hash,
        output: &FundedOutput,
    ) -> Result<(), &'static str> {
        if self.outputs.contains_key(&id)
            || self.destinations.contains(&output.destination.destination)
        {
            return Err("reward output conflicts with spend state");
        }
        self.outputs.insert(id, output.clone());
        self.destinations.insert(output.destination.destination);
        self.output_indices.insert(id, 0);
        Ok(())
    }

    pub fn add_mining_reward(
        &mut self,
        id: Hash,
        output: &FundedOutput,
        height: u64,
    ) -> Result<(), &'static str> {
        self.add_reward_output(id, output)?;
        self.reward_heights.insert(id, height);
        Ok(())
    }

    fn validate_non_proof(&self, tx: &Transaction, height: u64) -> Result<(), &'static str> {
        for member in tx.inputs.iter().flat_map(|input| input.members.iter()) {
            if self
                .reward_heights
                .get(member)
                .is_some_and(|origin| height < origin.saturating_add(self.reward_maturity))
            {
                return Err("immature mining reward in ring");
            }
        }
        if tx
            .inputs
            .iter()
            .any(|input| self.spent_images.contains(&input.key_image))
        {
            return Err("key image already spent");
        }
        if tx
            .outputs
            .iter()
            .any(|output| self.destinations.contains(&output.destination.destination))
        {
            return Err("output destination already exists");
        }
        Ok(())
    }

    fn apply_one(
        &mut self,
        tx: &Transaction,
        height: u64,
        proof_verified: bool,
    ) -> Result<(), &'static str> {
        self.validate_non_proof(tx, height)?;
        if !proof_verified {
            tx.verify_anonymous_authorization_with(height, |id| self.outputs.get(id))?;
        }
        let txid = tx.txid()?;
        for (index, output) in tx.outputs.iter().enumerate() {
            let id = transaction_output_id(txid, index);
            if self.outputs.contains_key(&id) {
                return Err("transaction output already exists");
            }
            self.outputs.insert(id, output.clone());
            self.destinations.insert(output.destination.destination);
            self.output_indices.insert(id, index as u64);
        }
        for input in &tx.inputs {
            self.spent_images.insert(input.key_image);
        }
        Ok(())
    }

    fn proof_cache_key(&self, tx: &Transaction) -> Result<Hash, &'static str> {
        let mut hash = Sha256::new();
        hash.update(b"TENEBRA:verified-proof-cache:v1");
        hash.update(tx.txid()?); // Includes every byte of the authorization and outputs.
        for member in tx.inputs.iter().flat_map(|input| input.members.iter()) {
            let output = self.outputs.get(member).ok_or("unknown ring member")?;
            let encoded = output.encode_canonical();
            hash.update(member);
            hash.update((encoded.len() as u64).to_le_bytes());
            hash.update(encoded); // A reorg or changed ring statement cannot reuse the entry.
        }
        Ok(hash.finalize().into())
    }

    /// A failed transaction leaves the caller's state unchanged.
    pub fn apply_batch(&mut self, txs: &[Transaction], height: u64) -> Result<(), &'static str> {
        let mut staged = self.clone();
        let can_parallel_verify = !cfg!(target_arch = "wasm32") && txs.iter().all(|tx| {
            tx.inputs
                .iter()
                .flat_map(|input| input.members.iter())
                .all(|member| self.outputs.contains_key(member))
        });
        if can_parallel_verify {
            for tx in txs {
                staged.validate_non_proof(tx, height)?;
            }
            let keys = txs
                .iter()
                .map(|tx| self.proof_cache_key(tx))
                .collect::<Result<Vec<_>, _>>()?;
            let hits: Vec<_> = {
                let cache = self
                    .verified_proofs
                    .lock()
                    .map_err(|_| "proof cache poisoned")?;
                keys.iter()
                    .map(|key| crate::network::IS_MAINNET && cache.contains(key))
                    .collect()
            };
            // Height-dependent expiry, maturity and spends are never cached.
            for tx in txs {
                if tx.expires_at_height < height || tx.expires_at_height == 0 {
                    return Err("expired transaction");
                }
            }
            let prepared = txs
                .par_iter()
                .zip(hits.par_iter())
                .map(|(tx, hit)| {
                    if *hit {
                        return Ok(None);
                    }
                    let rings = tx.ring_statements_with(height, |id| self.outputs.get(id))?;
                    let message = tx.signing_hash()?;
                    Ok(Some((rings, message)))
                })
                .collect::<Result<Vec<_>, &'static str>>()?;
            let valid = txs
                .par_iter()
                .zip(prepared.par_iter())
                .all(|(tx, prepared)| {
                    let Some((rings, message)) = prepared else {
                        return true;
                    };
                    tx.inputs
                        .par_iter()
                        .zip(rings.par_iter())
                        .all(|(input, ring)| {
                            AuthorizationProof::decode(&input.authorization)
                                .map(|proof| proof.verify(message, input.key_image, ring))
                                .unwrap_or(false)
                        })
                });
            if !valid {
                return Err("invalid anonymous authorization");
            }
            if crate::network::IS_MAINNET {
                let mut cache = self
                    .verified_proofs
                    .lock()
                    .map_err(|_| "proof cache poisoned")?;
                if cache.len() + keys.len() > 36_000 {
                    cache.clear();
                }
                if keys.len() <= 36_000 {
                    cache.extend(keys);
                }
            }
        }
        for tx in txs {
            staged.apply_one(tx, height, can_parallel_verify)?;
        }
        *self = staged;
        Ok(())
    }

    pub fn apply_batch_for_wallet(&mut self, txs: &[Transaction], height: u64) -> Result<(), &'static str> {
        for tx in txs {
            self.validate_non_proof(tx, height)?;
            tx.verify_anonymous_authorization_with(height, |id| self.outputs.get(id))?;
            self.apply_one(tx, height, true)?;
        }
        Ok(())
    }
}

#[cfg(all(test, feature = "mainnet-candidate"))]
mod cache_tests {
    use super::*;
    use crate::tsc1_chain_v2::reward_at_height;
    use crate::tsc1_chain_v3::ChainV3;
    use crate::tsc1_funded_output::create_reward_output;
    use crate::tsc1_wallet_tx_v3::create_signed_transfer;
    use crate::{FOUNDER_ALLOCATION_NOX, WalletSecrets};

    #[test]
    fn cached_proof_still_rejects_changed_ring_expiry_and_double_spend() {
        let founder = WalletSecrets::from_seed(&[174; 32]);
        let miner = WalletSecrets::from_seed(&[175; 32]);
        let recipient = WalletSecrets::from_seed(&[176; 32]);
        let genesis = Chain::new(
            create_reward_output(&founder.address(), 0, FOUNDER_ALLOCATION_NOX).unwrap(),
            1,
        )
        .unwrap();
        let mut chain = ChainV3::from_genesis(genesis).unwrap();
        for height in 1..=11 {
            let reward =
                create_reward_output(&miner.address(), 0, reward_at_height(height)).unwrap();
            let mut block = chain.next_block(reward, height * 30 + 1, vec![]);
            block.mine().unwrap();
            chain.append(block).unwrap();
        }
        let tx = create_signed_transfer(&chain, &founder, &recipient.address(), 100, 1).unwrap();
        let mut applied = chain.spends().clone();
        applied.apply_batch(std::slice::from_ref(&tx), 12).unwrap();
        assert!(!chain.spends().verified_proofs.lock().unwrap().is_empty());
        assert!(applied.apply_batch(std::slice::from_ref(&tx), 12).is_err());
        let mut expired = chain.spends().clone();
        assert_eq!(
            expired.apply_batch(std::slice::from_ref(&tx), tx.expires_at_height + 1),
            Err("expired transaction")
        );
        let mut changed_ring = chain.spends().clone();
        let member = tx.inputs[0].members[0];
        changed_ring
            .outputs
            .get_mut(&member)
            .unwrap()
            .amount
            .commitment = [0; 32];
        assert!(
            changed_ring
                .apply_batch(std::slice::from_ref(&tx), 12)
                .is_err()
        );
        let mut changed_tx = tx.clone();
        changed_tx.outputs[0].amount.range_proof[0] ^= 1;
        assert!(
            chain
                .spends()
                .clone()
                .apply_batch(&[changed_tx], 12)
                .is_err()
        );
        let mut immature = chain.spends().clone();
        immature.reward_maturity = 1;
        immature.reward_heights.insert(member, 12);
        assert_eq!(
            immature.apply_batch(&[tx], 12),
            Err("immature mining reward in ring")
        );
    }
}
