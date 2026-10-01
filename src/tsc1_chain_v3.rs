//! Isolated transaction-bearing devnet candidate; not a public consensus protocol.

use crate::assets::{AssetKind, AssetLedger, AssetTransaction, SignedAssetTransaction};
use crate::dex::{DexState, MAX_DEX_OPERATION_BYTES, MAX_DEX_OPERATIONS, SignedDexOperation};
use crate::tsc1_chain_v2::{Block, Chain, Hash, TARGET_BLOCK_SECONDS};
use crate::tsc1_fee::transaction_fee_payouts;
use crate::tsc1_funded_output::{FundedOutput, create_public_fee_output, create_reward_output};
use crate::tsc1_spend_state_v2::SpendState;
use crate::tsc1_tx_v2::{Transaction, key_image_for_secret};
use crate::{Address, WalletSecrets, output_from_ephemeral_secret};
use bulletproofs::PedersenGens;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha256, Sha512};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::io::{Cursor, Read};
use std::path::Path;
#[cfg(not(target_arch = "wasm32"))]
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(target_arch = "wasm32")]
#[link(wasm_import_module = "./env.js")]
unsafe extern "C" {
    fn unix_time() -> u64;
}

const TAG: &[u8; 10] = if crate::network::IS_MAINNET {
    b"TNB1BLK001"
} else {
    b"TSC1BLK3F1"
};
const BASE_DIFFICULTY_BITS: u8 = 12;
const MAX_DIFFICULTY_BITS: u8 = if crate::network::IS_MAINNET { 120 } else { 24 };
const RETARGET_WINDOW: usize = 16;
const MAX_FUTURE_DRIFT_SECONDS: u64 = 120;
// Allow reward outputs to be spendable immediately in the live wallet flow.
// In this build the spendability check is driven by output maturity, not by
// a long lock-up period, so the wallet can send funds with a positive fee.
const REWARD_MATURITY_BLOCKS: u64 = 0;
pub const FINALITY_DEPTH: u64 = 10;
// Protocol capacity is not a measured confirmation rate.
pub const MAX_TXS: usize = if crate::network::IS_MAINNET {
    9_000
} else {
    16
};
const MAX_TX_BYTES: usize = 512 * 1024;
pub(crate) const MAX_BLOCK_BYTES: usize = if crate::network::IS_MAINNET {
    64 * 1024 * 1024
} else {
    MAX_TXS * MAX_TX_BYTES + 8192
};
const TREASURY_ADDRESS: &str = include_str!("../config/treasury-address.txt");
pub const ASSET_CREATION_FEE_NOX: u64 = 10_000_000_000;
pub const FUNGIBLE_ASSET_CREATION_FEE_NOX: u64 = 100_000_000_000;
pub const ASSET_CREATION_FEE_ACTIVATION_HEIGHT: u64 = 17_718;
pub const GLOBAL_ASSET_TRANSFER_FEE_ACTIVATION_HEIGHT: u64 = 20_000;

pub fn asset_creation_fee_nox(
    transaction: &AssetTransaction,
    height: u64,
) -> Result<u64, &'static str> {
    let is_nft = match transaction {
        AssetTransaction::Create { .. } => false,
        AssetTransaction::CreateWithOptions { kind, .. } => *kind == AssetKind::Nft,
        _ => return Err("asset creation fee requested for non-creation transaction"),
    };
    if is_nft
        || !crate::network::IS_MAINNET
        || height < crate::tsc1_fee::FEE_POLICY_ACTIVATION_HEIGHT
    {
        Ok(ASSET_CREATION_FEE_NOX)
    } else {
        Ok(FUNGIBLE_ASSET_CREATION_FEE_NOX)
    }
}

pub(crate) fn validate_tnb_transfer_fee_transaction(
    transaction: &Transaction,
    height: u64,
) -> Result<(), &'static str> {
    if !crate::network::IS_MAINNET || height < crate::tsc1_fee::FEE_POLICY_ACTIVATION_HEIGHT {
        return Ok(());
    }
    let payment = transaction
        .outputs
        .first()
        .ok_or("TNB transfer payment output missing")?;
    if payment.amount.asset_id != crate::assets::TNB_ASSET_ID
        || !crate::tsc1_private_amounts::verify_tnb_transfer_fee_proof(
            &payment.amount,
            transaction.fee_nox,
        )
    {
        return Err("missing or invalid confidential 1 percent TNB transfer fee proof");
    }
    Ok(())
}

pub fn asset_creation_fee_secret(asset_txid: Hash) -> Scalar {
    let mut hash = Sha512::new();
    hash.update(b"TSC-1:asset-creation-fee:v1");
    hash.update(asset_txid);
    let secret = Scalar::from_hash(hash);
    if secret == Scalar::ZERO { Scalar::ONE } else { secret }
}

pub fn asset_transfer_fee_secret(asset_txid: Hash) -> Scalar {
    let mut hash = Sha512::new();
    hash.update(b"TSC-1:asset-transfer-fee:v1");
    hash.update(asset_txid);
    let secret = Scalar::from_hash(hash);
    if secret == Scalar::ZERO { Scalar::ONE } else { secret }
}

pub fn asset_issuer_transfer_fee_secret(asset_txid: Hash) -> Scalar {
    let mut hash = Sha512::new();
    hash.update(b"TSC-1:asset-issuer-transfer-fee:v1");
    hash.update(asset_txid);
    let secret = Scalar::from_hash(hash);
    if secret == Scalar::ZERO { Scalar::ONE } else { secret }
}

pub(crate) fn validate_asset_creation_fee(
    signed: &SignedAssetTransaction,
    height: u64,
) -> Result<Option<crate::tsc1_tx_v2::Transaction>, &'static str> {
    match &signed.transaction {
        AssetTransaction::Create { .. } | AssetTransaction::CreateWithOptions { .. } => {
            if height < ASSET_CREATION_FEE_ACTIVATION_HEIGHT {
                return Ok(None);
            }
            let fee = signed.creation_fee.as_ref().ok_or("asset creation fee required")?;
            fee.validate_public(height)?;
            let required_fee = asset_creation_fee_nox(
                &signed.transaction,
                height.max(fee.expires_at_height),
            )?;
            let expected = output_from_ephemeral_secret(
                &Address::parse(TREASURY_ADDRESS)?,
                0,
                asset_creation_fee_secret(signed.transaction.txid()?),
            )?;
            let commitment = PedersenGens::default()
                .commit(Scalar::from(required_fee), Scalar::ZERO)
                .compress()
                .to_bytes();
            if fee.outputs.iter().filter(|output| {
                output.amount.asset_id == crate::assets::TNB_ASSET_ID
                    && output.amount.commitment == commitment
                    && output.destination == expected
            }).count() != 1 {
                return Err("invalid asset creation treasury payment");
            }
            Ok(Some(fee.clone()))
        }
        _ if signed.creation_fee.is_some() => Err("fee attached to non-creation asset"),
        _ => Ok(None),
    }
}

pub(crate) fn validate_asset_operation_fee(
    signed: &SignedAssetTransaction,
    height: u64,
    assets: &AssetLedger,
) -> Result<Option<crate::tsc1_tx_v2::Transaction>, &'static str> {
    validate_issuer_fee_cap(&signed.transaction, height)?;
    let AssetTransaction::Transfer { asset_id, amount, .. } = &signed.transaction else {
        return validate_asset_creation_fee(signed, height);
    };
    let asset = match assets.registry.get(asset_id) {
        Some(asset) => asset,
        None => return Err("unknown asset"),
    };
        if crate::network::IS_MAINNET
            && height >= crate::tsc1_fee::FEE_POLICY_ACTIVATION_HEIGHT
            && asset.issuer_fee_bps > crate::assets::MAX_ISSUER_TRANSFER_FEE_BPS
        {
            return Err("issuer transfer fee exceeds 8 percent");
        }
    let fee = match &signed.creation_fee {
        Some(fee) => fee,
        None if height < GLOBAL_ASSET_TRANSFER_FEE_ACTIVATION_HEIGHT => return Ok(None),
        None => return Err("global asset transfer fee required"),
    };
    let required_fee = crate::assets::global_asset_transfer_fee_nox(*amount, asset.decimals)?;
    fee.validate_public(height)?;
    let expected = output_from_ephemeral_secret(
        &Address::parse(TREASURY_ADDRESS)?,
        0,
        asset_transfer_fee_secret(signed.transaction.txid()?),
    )?;
    if !fee_has_exact_treasury_output(fee, required_fee, expected) {
        return Err("invalid global asset transfer treasury payment");
    }
    if asset.issuer_fee_bps > 0 {
        let issuer_fee = crate::assets::transfer_fee_nox(*amount, asset.decimals, asset.issuer_fee_bps)?;
        let treasury = asset.issuer_treasury.as_ref().ok_or("issuer fee treasury missing")?;
        let issuer_expected = output_from_ephemeral_secret(treasury, 0, asset_issuer_transfer_fee_secret(signed.transaction.txid()?))?;
        if !fee_has_exact_treasury_output(fee, issuer_fee, issuer_expected) {
            return Err("invalid issuer transfer treasury payment");
        }
    }
    Ok(Some(fee.clone()))
}

fn validate_issuer_fee_cap(
    transaction: &AssetTransaction,
    height: u64,
) -> Result<(), &'static str> {
    if !crate::network::IS_MAINNET
        || height < crate::tsc1_fee::FEE_POLICY_ACTIVATION_HEIGHT
    {
        return Ok(());
    }
    let issuer_fee_bps = match transaction {
        AssetTransaction::CreateWithOptions { issuer_fee_bps, .. }
        | AssetTransaction::UpdateOptions { issuer_fee_bps, .. } => *issuer_fee_bps,
        _ => 0,
    };
    if issuer_fee_bps > crate::assets::MAX_ISSUER_TRANSFER_FEE_BPS {
        return Err("issuer transfer fee exceeds 8 percent");
    }
    Ok(())
}

fn fee_has_exact_treasury_output(fee: &crate::tsc1_tx_v2::Transaction, amount: u64, expected: crate::OneTimeOutput) -> bool {
    let commitment = PedersenGens::default().commit(Scalar::from(amount), Scalar::ZERO).compress().to_bytes();
    fee.outputs.iter().filter(|output| {
        output.amount.asset_id == crate::assets::TNB_ASSET_ID
            && output.amount.commitment == commitment
            && output.destination == expected
    }).count() == 1
}

fn hash_meets_difficulty(hash: &Hash, bits: u8) -> bool {
    if !(BASE_DIFFICULTY_BITS..=MAX_DIFFICULTY_BITS).contains(&bits) {
        return false;
    }
    let full_bytes = (bits / 8) as usize;
    hash[..full_bytes].iter().all(|byte| *byte == 0)
        && (bits.is_multiple_of(8) || hash[full_bytes] >> (8 - bits % 8) == 0)
}

fn treasury_secret(previous_hash: Hash, height: u64) -> Scalar {
    let mut hash = Sha512::new();
    hash.update(b"TSC-1:public-treasury-output:v3b");
    hash.update(previous_hash);
    hash.update(height.to_le_bytes());
    let scalar = Scalar::from_hash(hash);
    if scalar == Scalar::ZERO {
        Scalar::ONE
    } else {
        scalar
    }
}

fn fee_output_id(block_hash: Hash, role: u8) -> Hash {
    let mut hash = Sha256::new();
    hash.update(b"TSC-1:fee-output-id:v3b");
    hash.update(block_hash);
    hash.update([role]);
    hash.finalize().into()
}

fn valid_fee_output(output: Option<&FundedOutput>, amount: u64) -> bool {
    match (output, amount) {
        (None, 0) => true,
        (Some(output), amount) if amount > 0 => {
            output.amount.asset_id == crate::assets::TNB_ASSET_ID
                && output.verify_public()
                && output.amount.commitment
                    == PedersenGens::default()
                        .commit(Scalar::from(amount), Scalar::ZERO)
                        .compress()
                        .to_bytes()
        }
        _ => false,
    }
}

fn block_fee_payouts(total_transaction_fees: u64, height: u64) -> Result<(u64, u64), &'static str> {
    let (miner_fees, treasury_fees) = transaction_fee_payouts(total_transaction_fees, height);
    let treasury_reward = crate::tsc1_chain_v2::treasury_mining_reward_at_height(height);
    let treasury_total = treasury_fees
        .checked_add(treasury_reward)
        .ok_or("treasury payout overflow")?;
    Ok((miner_fees, treasury_total))
}

fn take<const N: usize>(cursor: &mut Cursor<&[u8]>) -> Result<[u8; N], &'static str> {
    let mut bytes = [0; N];
    cursor
        .read_exact(&mut bytes)
        .map_err(|_| "truncated v3 block")?;
    Ok(bytes)
}

fn decode_optional_output(
    cursor: &mut Cursor<&[u8]>,
) -> Result<Option<FundedOutput>, &'static str> {
    match take::<1>(cursor)?[0] {
        0 => Ok(None),
        1 => {
            let len = u32::from_le_bytes(take(cursor)?) as usize;
            if len == 0 || len > 2048 {
                return Err("invalid fee output length");
            }
            let mut bytes = vec![0; len];
            cursor
                .read_exact(&mut bytes)
                .map_err(|_| "truncated fee output")?;
            Ok(Some(FundedOutput::decode_canonical(&bytes)?))
        }
        _ => Err("invalid fee output flag"),
    }
}

fn encode_optional_output(
    bytes: &mut Vec<u8>,
    output: Option<&FundedOutput>,
) -> Result<(), &'static str> {
    match output {
        None => bytes.push(0),
        Some(output) => {
            let encoded = output.encode_canonical();
            if encoded.len() > 2048 {
                return Err("oversized fee output");
            }
            bytes.push(1);
            bytes.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&encoded);
        }
    }
    Ok(())
}

#[derive(Clone)]
pub struct BlockV3 {
    pub previous_hash: Hash,
    pub reward: Block,
    pub transactions: Vec<Transaction>,
    pub miner_fee_output: Option<FundedOutput>,
    pub treasury_fee_output: Option<FundedOutput>,
    pub asset_transactions: Vec<SignedAssetTransaction>,
    pub dex_operations: Vec<SignedDexOperation>,
    pub difficulty_bits: u8,
    pub nonce: u64,
}

impl BlockV3 {
    pub fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() > MAX_BLOCK_BYTES {
            return Err("oversized v3 block");
        }
        let mut cursor = Cursor::new(bytes);
        if &take::<10>(&mut cursor)? != TAG {
            return Err("wrong v3 block format");
        }
        let previous_hash = take(&mut cursor)?;
        let reward_len = u32::from_le_bytes(take(&mut cursor)?) as usize;
        if reward_len == 0 || reward_len > 2048 {
            return Err("invalid reward block length");
        }
        let mut reward_bytes = vec![0; reward_len];
        cursor
            .read_exact(&mut reward_bytes)
            .map_err(|_| "truncated v3 block")?;
        let reward = Block::decode(&reward_bytes)?;
        let count = if crate::network::IS_MAINNET {
            u16::from_le_bytes(take::<2>(&mut cursor)?) as usize
        } else {
            take::<1>(&mut cursor)?[0] as usize
        };
        if count > MAX_TXS {
            return Err("too many block transactions");
        }
        let mut transactions = Vec::with_capacity(count);
        for _ in 0..count {
            let len = u32::from_le_bytes(take(&mut cursor)?) as usize;
            if len == 0 || len > MAX_TX_BYTES {
                return Err("invalid block transaction length");
            }
            let mut encoded = vec![0; len];
            cursor
                .read_exact(&mut encoded)
                .map_err(|_| "truncated v3 block")?;
            transactions.push(Transaction::decode(&encoded)?);
        }
        let miner_fee_output = decode_optional_output(&mut cursor)?;
        let treasury_fee_output = decode_optional_output(&mut cursor)?;
        let asset_transactions = if cursor.get_ref().len() - cursor.position() as usize == 9 {
            Vec::new()
        } else {
            let count = take::<2>(&mut cursor)?;
            let count = u16::from_le_bytes(count) as usize;
            if count > 256 {
                return Err("too many asset transactions");
            }
            let mut transactions = Vec::with_capacity(count);
            for _ in 0..count {
                let len = u32::from_le_bytes(take(&mut cursor)?) as usize;
                if len == 0 || len > 4096 {
                    return Err("invalid asset transaction length");
                }
                let mut encoded = vec![0; len];
                cursor
                    .read_exact(&mut encoded)
                    .map_err(|_| "truncated asset transaction")?;
                transactions.push(SignedAssetTransaction::decode(&encoded)?);
            }
            transactions
        };
        let dex_operations = if cursor.get_ref().len() - cursor.position() as usize == 9 {
            Vec::new()
        } else {
            if &take::<4>(&mut cursor)? != b"DEX1" {
                return Err("wrong dex block extension");
            }
            let count = u16::from_le_bytes(take(&mut cursor)?) as usize;
            if count == 0 || count > MAX_DEX_OPERATIONS {
                return Err("invalid dex operation count");
            }
            let mut operations = Vec::with_capacity(count);
            for _ in 0..count {
                let len = u16::from_le_bytes(take(&mut cursor)?) as usize;
                if len == 0 || len > MAX_DEX_OPERATION_BYTES {
                    return Err("invalid dex operation length");
                }
                let mut encoded = vec![0; len];
                cursor
                    .read_exact(&mut encoded)
                    .map_err(|_| "truncated dex block operation")?;
                operations.push(SignedDexOperation::decode(&encoded)?);
            }
            operations
        };
        let difficulty_bits = take::<1>(&mut cursor)?[0];
        let nonce = u64::from_le_bytes(take(&mut cursor)?);
        if cursor.position() != bytes.len() as u64 {
            return Err("trailing v3 block bytes");
        }
        Ok(Self {
            previous_hash,
            reward,
            transactions,
            miner_fee_output,
            treasury_fee_output,
            asset_transactions,
            dex_operations,
            difficulty_bits,
            nonce,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, &'static str> {
        if self.transactions.len() > MAX_TXS {
            return Err("too many block transactions");
        }
        let reward = self.reward.encode();
        if reward.len() > 2048 {
            return Err("oversized reward block");
        }
        let mut bytes = Vec::new();
        bytes.extend_from_slice(TAG);
        bytes.extend_from_slice(&self.previous_hash);
        bytes.extend_from_slice(&(reward.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&reward);
        if crate::network::IS_MAINNET {
            bytes.extend_from_slice(&(self.transactions.len() as u16).to_le_bytes());
        } else {
            bytes.push(self.transactions.len() as u8);
        }
        for tx in &self.transactions {
            let encoded = tx.encode()?;
            if encoded.len() > MAX_TX_BYTES {
                return Err("oversized block transaction");
            }
            bytes.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&encoded);
        }
        encode_optional_output(&mut bytes, self.miner_fee_output.as_ref())?;
        encode_optional_output(&mut bytes, self.treasury_fee_output.as_ref())?;
        if self.asset_transactions.len() > 256 || self.dex_operations.len() > MAX_DEX_OPERATIONS {
            return Err("too many block operations");
        }
        if !self.asset_transactions.is_empty() || !self.dex_operations.is_empty() {
            bytes.extend_from_slice(&(self.asset_transactions.len() as u16).to_le_bytes());
            for signed in &self.asset_transactions {
                let encoded = signed.encode()?;
                if encoded.len() > 4096 {
                    return Err("oversized asset transaction");
                }
                bytes.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
                bytes.extend_from_slice(&encoded);
            }
        }
        if !self.dex_operations.is_empty() {
            bytes.extend_from_slice(b"DEX1");
            bytes.extend_from_slice(&(self.dex_operations.len() as u16).to_le_bytes());
            for operation in &self.dex_operations {
                let encoded = operation.encode();
                if encoded.len() > MAX_DEX_OPERATION_BYTES {
                    return Err("oversized dex operation");
                }
                bytes.extend_from_slice(&(encoded.len() as u16).to_le_bytes());
                bytes.extend_from_slice(&encoded);
            }
        }
        bytes.push(self.difficulty_bits);
        bytes.extend_from_slice(&self.nonce.to_le_bytes());
        if bytes.len() > MAX_BLOCK_BYTES {
            return Err("oversized v3 block");
        }
        Ok(bytes)
    }

    pub fn hash(&self) -> Result<Hash, &'static str> {
        if crate::network::IS_MAINNET {
            return Ok(Self::mainnet_pow_hash(
                &self.mainnet_content_hash()?,
                self.nonce,
            ));
        }
        let mut hash = Sha256::new();
        hash.update(b"TSC-1:transaction-block:v3");
        hash.update(self.encode()?);
        Ok(hash.finalize().into())
    }

    fn mainnet_content_hash(&self) -> Result<Hash, &'static str> {
        let bytes = self.encode()?;
        Ok(Sha256::digest(&bytes[..bytes.len() - 8]).into())
    }

    fn mainnet_pow_hash(content: &Hash, nonce: u64) -> Hash {
        let mut hash = Sha256::new();
        hash.update(b"TENEBRA:mainnet:pow:v1");
        hash.update(crate::tsc1_tx_v2::NETWORK_ID);
        hash.update(content);
        hash.update(nonce.to_le_bytes());
        hash.finalize().into()
    }

    pub fn mine(&mut self) -> Result<(), &'static str> {
        if self.mine_with_control(|| true)? {
            Ok(())
        } else {
            Err("mining cancelled")
        }
    }

    pub fn mine_with_control<F>(&mut self, mut should_continue: F) -> Result<bool, &'static str>
    where
        F: FnMut() -> bool,
    {
        if !(BASE_DIFFICULTY_BITS..=MAX_DIFFICULTY_BITS).contains(&self.difficulty_bits) {
            return Err("invalid v3 difficulty");
        }
        if !self.reward.mine_with_control(&mut should_continue)? {
            return Ok(false);
        }
        let content = if crate::network::IS_MAINNET {
            Some(self.mainnet_content_hash()?)
        } else {
            None
        };
        let mut checks_remaining = 0;
        loop {
            if checks_remaining == 0 {
                if !should_continue() {
                    return Ok(false);
                }
                checks_remaining = 256;
            }
            checks_remaining -= 1;
            let hash = match content {
                Some(ref content) => Self::mainnet_pow_hash(content, self.nonce),
                None => self.hash()?,
            };
            if hash_meets_difficulty(&hash, self.difficulty_bits) {
                return Ok(true);
            }
            self.nonce = self.nonce.checked_add(1).ok_or("v3 nonce exhausted")?;
        }
    }
}

#[derive(Clone)]
pub struct ChainV3 {
    rewards: Chain,
    spends: SpendState,
    blocks: Vec<BlockV3>,
    tip_hash: Hash,
    cumulative_work: u128,
    assets: AssetLedger,
    dex: DexState,
}

impl ChainV3 {
    pub fn from_genesis(genesis: Chain) -> Result<Self, &'static str> {
        if genesis.height() != 0 {
            return Err("v3 requires genesis-only anchor");
        }
        let mut hash = Sha256::new();
        hash.update(b"TSC-1:v3f-genesis-anchor");
        hash.update(genesis.genesis_hash());
        let tip_hash = hash.finalize().into();
        let spends =
            SpendState::from_reward_chain(&genesis).with_reward_maturity(REWARD_MATURITY_BLOCKS);
        Ok(Self {
            rewards: genesis,
            spends,
            blocks: Vec::new(),
            tip_hash,
            cumulative_work: 0,
            assets: AssetLedger::default(),
            dex: DexState::default(),
        })
    }

    pub fn from_pinned_genesis() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self::from_genesis(crate::network::pinned_genesis()?)?)
    }

    pub fn height(&self) -> u64 {
        self.rewards.height()
    }
    pub fn tip_hash(&self) -> Hash {
        self.tip_hash
    }
    pub fn cumulative_work(&self) -> u128 {
        self.cumulative_work
    }

    pub fn finalized_height(&self) -> u64 {
        // Public PoW confirmations are probabilistic, not an irreversible checkpoint.
        if crate::network::IS_MAINNET {
            0
        } else {
            self.height().saturating_sub(FINALITY_DEPTH)
        }
    }
    pub fn next_difficulty_bits(&self) -> u8 {
        let Some(last) = self.blocks.last() else {
            return BASE_DIFFICULTY_BITS;
        };
        let bits = last.difficulty_bits;
        if !self.blocks.len().is_multiple_of(RETARGET_WINDOW) {
            return bits;
        }
        let first = &self.blocks[self.blocks.len() - RETARGET_WINDOW];
        let elapsed = last.reward.timestamp.saturating_sub(first.reward.timestamp);
        let expected = (RETARGET_WINDOW as u64 - 1) * TARGET_BLOCK_SECONDS;
        if elapsed < expected / 2 {
            bits.saturating_add(1).min(MAX_DIFFICULTY_BITS)
        } else if elapsed > expected * 2 {
            bits.saturating_sub(1).max(BASE_DIFFICULTY_BITS)
        } else {
            bits
        }
    }
    pub fn rewards(&self) -> &Chain {
        &self.rewards
    }
    pub fn spends(&self) -> &SpendState {
        &self.spends
    }
    pub fn dex(&self) -> &DexState {
        &self.dex
    }
    pub fn assets(&self) -> &AssetLedger {
        &self.assets
    }

    pub fn wallet_balance_nox(&self, wallet: &WalletSecrets) -> Result<u64, &'static str> {
        let mut balance = 0u64;
        let mut count_output = |output: &FundedOutput, index: u64| -> Result<(), &'static str> {
            if output.amount.asset_id != crate::assets::TNB_ASSET_ID {
                return Ok(());
            }
            if let Some(recovered) = wallet.scan_funded_output(output, index) {
                let secret =
                    Option::<Scalar>::from(Scalar::from_canonical_bytes(recovered.one_time_spend))
                        .ok_or("invalid recovered spend key")?;
                if !self.spends.has_spent_image(&key_image_for_secret(secret)) {
                    balance = balance
                        .checked_add(recovered.amount_nox)
                        .ok_or("wallet balance overflow")?;
                }
            }
            Ok(())
        };
        count_output(&self.rewards.genesis_block().reward_output, 0)?;
        for block in &self.blocks {
            count_output(&block.reward.reward_output, 0)?;
            if let Some(output) = &block.miner_fee_output {
                count_output(output, 0)?;
            }
            if let Some(output) = &block.treasury_fee_output {
                count_output(output, 0)?;
            }
            for signed in &block.asset_transactions {
                if let Some(fee) = &signed.creation_fee {
                    for (index, output) in fee.outputs.iter().enumerate() {
                        count_output(output, index as u64)?;
                    }
                }
            }
            for tx in &block.transactions {
                for (index, output) in tx.outputs.iter().enumerate() {
                    count_output(output, index as u64)?;
                }
            }
        }
        Ok(balance)
    }
    pub fn blocks(&self) -> &[BlockV3] {
        &self.blocks
    }

    pub fn encode(&self) -> Result<Vec<u8>, &'static str> {
        if self.blocks.len() > u32::MAX as usize {
            return Err("too many v3 blocks");
        }
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"TSC1CHN3F1");
        bytes.extend_from_slice(&self.rewards.genesis_hash());
        bytes.extend_from_slice(&(self.blocks.len() as u32).to_le_bytes());
        for block in &self.blocks {
            let encoded = block.encode()?;
            bytes.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&encoded);
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8], genesis: Chain) -> Result<Self, &'static str> {
        let mut cursor = Cursor::new(bytes);
        if &take::<10>(&mut cursor)? != b"TSC1CHN3F1" {
            return Err("wrong v3 chain format");
        }
        if take::<32>(&mut cursor)? != genesis.genesis_hash() {
            return Err("v3 genesis hash mismatch");
        }
        let count = u32::from_le_bytes(take(&mut cursor)?) as usize;
        if count > 1_000_000 {
            return Err("too many v3 blocks");
        }
        let mut chain = Self::from_genesis(genesis)?;
        for _ in 0..count {
            let len = u32::from_le_bytes(take(&mut cursor)?) as usize;
            if len == 0 || len > MAX_BLOCK_BYTES {
                return Err("invalid v3 block length");
            }
            let mut encoded = vec![0; len];
            cursor
                .read_exact(&mut encoded)
                .map_err(|_| "truncated v3 chain")?;
            chain.append(BlockV3::decode(&encoded)?)?;
        }
        if cursor.position() != bytes.len() as u64 {
            return Err("trailing v3 chain bytes");
        }
        Ok(chain)
    }

    pub fn next_block(
        &self,
        reward_output: FundedOutput,
        timestamp: u64,
        transactions: Vec<Transaction>,
    ) -> BlockV3 {
        BlockV3 {
            previous_hash: self.tip_hash,
            reward: self.rewards.next_block(reward_output, timestamp),
            transactions,
            miner_fee_output: None,
            treasury_fee_output: None,
            asset_transactions: Vec::new(),
            dex_operations: Vec::new(),
            difficulty_bits: self.next_difficulty_bits(),
            nonce: 0,
        }
    }

    pub fn next_block_with_fees(
        &self,
        reward_output: FundedOutput,
        miner_fee_address: &Address,
        timestamp: u64,
        transactions: Vec<Transaction>,
    ) -> Result<BlockV3, &'static str> {
        let total = transactions.iter().try_fold(0u64, |sum, tx| {
            sum.checked_add(tx.fee_nox).ok_or("block fee overflow")
        })?;
        let mut block = self.next_block(reward_output, timestamp, transactions);
        let (miner, treasury) = block_fee_payouts(total, block.reward.height)?;
        if miner > 0 {
            block.miner_fee_output = Some(create_reward_output(miner_fee_address, 0, miner)?);
        }
        if treasury > 0 {
            let address = Address::parse(TREASURY_ADDRESS)?;
            block.treasury_fee_output = Some(create_public_fee_output(
                &address,
                treasury,
                treasury_secret(block.previous_hash, block.reward.height),
            )?);
        }
        Ok(block)
    }

    pub fn append(&mut self, block: BlockV3) -> Result<(), &'static str> {
        if block.previous_hash != self.tip_hash {
            return Err("invalid v3 block link");
        }
        #[cfg(target_arch = "wasm32")]
        let now = unsafe { unix_time() };
        #[cfg(not(target_arch = "wasm32"))]
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "system clock before unix epoch")?
            .as_secs();
        if block.reward.timestamp > now.saturating_add(MAX_FUTURE_DRIFT_SECONDS) {
            return Err("v3 block timestamp too far in future");
        }
        if block.difficulty_bits != self.next_difficulty_bits() {
            return Err("wrong v3 difficulty");
        }
        let hash = block.hash()?;
        if !hash_meets_difficulty(&hash, block.difficulty_bits) {
            return Err("insufficient v3 proof of work");
        }
        let cumulative_work = self
            .cumulative_work
            .checked_add(1u128 << block.difficulty_bits)
            .ok_or("v3 cumulative work overflow")?;
        let total_fee = block.transactions.iter().try_fold(0u64, |sum, tx| {
            sum.checked_add(tx.fee_nox).ok_or("block fee overflow")
        })?;
        for transaction in &block.transactions {
            validate_tnb_transfer_fee_transaction(transaction, block.reward.height)?;
        }
        let (miner_fee, treasury_fee) = block_fee_payouts(total_fee, block.reward.height)?;
        if !valid_fee_output(block.miner_fee_output.as_ref(), miner_fee)
            || !valid_fee_output(block.treasury_fee_output.as_ref(), treasury_fee)
        {
            return Err("invalid fee payout amount");
        }
        if let Some(output) = &block.treasury_fee_output {
            let address = Address::parse(TREASURY_ADDRESS)?;
            let expected = output_from_ephemeral_secret(
                &address,
                0,
                treasury_secret(block.previous_hash, block.reward.height),
            )?;
            if output.destination != expected {
                return Err("wrong treasury destination");
            }
        }
        let mut rewards = self.rewards.clone();
        rewards.append_wallet_reward_with_treasury_reward(
            block.reward.clone(),
            crate::tsc1_chain_v2::treasury_mining_reward_at_height(block.reward.height),
        )?;
        let mut spends = self.spends.clone();
        let mut assets = self.assets.clone();
        let mut asset_fee_transactions = Vec::new();
        for transaction in &block.asset_transactions {
            transaction.verify()?;
            if let Some(fee) = validate_asset_operation_fee(transaction, block.reward.height, &assets)? {
                asset_fee_transactions.push(fee);
            }
            assets.apply(transaction.transaction.clone())?;
        }
        let mut dex = self.dex.clone();
        for operation in &block.dex_operations {
            dex.apply_at_height(operation, &mut assets, block.reward.height)?;
        }
        let mut spend_transactions = asset_fee_transactions;
        spend_transactions.extend(block.transactions.clone());
        spends.apply_batch(&spend_transactions, block.reward.height)?;
        spends.add_mining_reward(
            block.reward.reward_output_id(),
            &block.reward.reward_output,
            block.reward.height,
        )?;
        if let Some(output) = &block.miner_fee_output {
            spends.add_reward_output(fee_output_id(hash, 0), output)?;
        }
        if let Some(output) = &block.treasury_fee_output {
            spends.add_reward_output(fee_output_id(hash, 1), output)?;
        }
        self.rewards = rewards;
        self.spends = spends;
        self.tip_hash = hash;
        self.cumulative_work = cumulative_work;
        self.assets = assets;
        self.dex = dex;
        self.blocks.push(block);
        Ok(())
    }

    pub fn append_wallet_state(&mut self, block: BlockV3) -> Result<(), &'static str> {
        if block.previous_hash != self.tip_hash {
            return Err("invalid v3 block link");
        }
        #[cfg(target_arch = "wasm32")]
        let now = unsafe { unix_time() };
        #[cfg(not(target_arch = "wasm32"))]
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "system clock before unix epoch")?
            .as_secs();
        if block.reward.timestamp > now.saturating_add(MAX_FUTURE_DRIFT_SECONDS) {
            return Err("v3 block timestamp too far in future");
        }
        if block.difficulty_bits != self.next_difficulty_bits() {
            return Err("wrong v3 difficulty");
        }
        let hash = block.hash()?;
        if !hash_meets_difficulty(&hash, block.difficulty_bits) {
            return Err("insufficient v3 proof of work");
        }
        let cumulative_work = self
            .cumulative_work
            .checked_add(1u128 << block.difficulty_bits)
            .ok_or("v3 cumulative work overflow")?;
        let total_fee = block.transactions.iter().try_fold(0u64, |sum, tx| {
            sum.checked_add(tx.fee_nox).ok_or("block fee overflow")
        })?;
        for transaction in &block.transactions {
            validate_tnb_transfer_fee_transaction(transaction, block.reward.height)?;
        }
        let (miner_fee, treasury_fee) = block_fee_payouts(total_fee, block.reward.height)?;
        if !valid_fee_output(block.miner_fee_output.as_ref(), miner_fee)
            || !valid_fee_output(block.treasury_fee_output.as_ref(), treasury_fee)
        {
            return Err("invalid fee payout amount");
        }
        if let Some(output) = &block.treasury_fee_output {
            let address = Address::parse(TREASURY_ADDRESS)?;
            let expected = output_from_ephemeral_secret(
                &address,
                0,
                treasury_secret(block.previous_hash, block.reward.height),
            )?;
            if output.destination != expected {
                return Err("wrong treasury destination");
            }
        }
        self.rewards.append_wallet_reward_with_treasury_reward(
            block.reward.clone(),
            crate::tsc1_chain_v2::treasury_mining_reward_at_height(block.reward.height),
        )?;
        let mut spend_transactions = Vec::new();
        for transaction in &block.asset_transactions {
            if let Some(fee) = &transaction.creation_fee { spend_transactions.push(fee.clone()); }
        }
        spend_transactions.extend(block.transactions.clone());
        self.spends.apply_batch_for_wallet(&spend_transactions, block.reward.height)?;
        self.spends.add_mining_reward(
            block.reward.reward_output_id(),
            &block.reward.reward_output,
            block.reward.height,
        )?;
        if let Some(output) = &block.miner_fee_output {
            self.spends.add_reward_output(fee_output_id(hash, 0), output)?;
        }
        if let Some(output) = &block.treasury_fee_output {
            self.spends.add_reward_output(fee_output_id(hash, 1), output)?;
        }
        for transaction in &block.asset_transactions {
            transaction.verify()?;
            validate_asset_operation_fee(transaction, block.reward.height, &self.assets)?;
            self.assets.apply(transaction.transaction.clone())?;
        }
        for operation in &block.dex_operations {
            self.dex.apply_at_height(operation, &mut self.assets, block.reward.height)?;
        }
        self.tip_hash = hash;
        self.cumulative_work = cumulative_work;
        self.blocks.push(block);
        Ok(())
    }
}

pub fn load_blocks(
    directory: &Path,
    genesis: Chain,
) -> Result<ChainV3, Box<dyn std::error::Error>> {
    let mut chain = ChainV3::from_genesis(genesis)?;
    if !directory.exists() {
        return Ok(chain);
    }
    let mut files = Vec::new();
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.extension().is_some_and(|ext| ext == "bin") {
            let height: u64 = path
                .file_stem()
                .ok_or("invalid v3 block filename")?
                .to_str()
                .ok_or("invalid v3 block filename")?
                .parse()?;
            files.push((height, path));
        }
    }
    files.sort_by_key(|(height, _)| *height);
    for (height, path) in files {
        if height != chain.height() + 1 {
            return Err("missing or duplicate v3 block".into());
        }
        if fs::metadata(&path)?.len() > MAX_BLOCK_BYTES as u64 {
            return Err("oversized v3 block".into());
        }
        chain.append(BlockV3::decode(&fs::read(path)?)?)?;
    }
    Ok(chain)
}

pub fn persist_block(directory: &Path, block: &BlockV3) -> Result<(), Box<dyn std::error::Error>> {
    let encoded = block.encode()?;
    fs::create_dir_all(directory)?;
    let target = directory.join(format!("{:020}.bin", block.reward.height));
    if target.exists() {
        return Err("v3 block already persisted".into());
    }
    let mut suffix = [0u8; 8];
    getrandom::getrandom(&mut suffix)?;
    let temporary = directory.join(format!(
        "{:020}.{}.tmp",
        block.reward.height,
        hex::encode(suffix)
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    file.write_all(&encoded)?;
    file.sync_all()?;
    drop(file);
    fs::rename(temporary, target)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_asset_transfer_fee_activates_at_height_twenty_thousand() {
        let secret = Scalar::from(19u64);
        let issuer = (secret * RISTRETTO_BASEPOINT_POINT).compress().to_bytes();
        let mut assets = AssetLedger::default();
        let asset_id = assets.apply(AssetTransaction::Create {
            issuer,
            nonce: 1,
            name: "Fee Test".into(),
            symbol: "FEE".into(),
            decimals: 9,
            max_supply: 1_000,
            initial_supply: 1_000,
        }).unwrap();
        let transfer = AssetTransaction::Transfer {
            asset_id,
            from: issuer,
            to: [7u8; 32],
            amount: 100,
        };
        let signed = crate::assets::sign_issuer(&transfer, secret, &[3u8; 64]).unwrap();
        assert_eq!(validate_asset_operation_fee(&signed, GLOBAL_ASSET_TRANSFER_FEE_ACTIVATION_HEIGHT - 1, &assets), Ok(None));
        assert_eq!(validate_asset_operation_fee(&signed, GLOBAL_ASSET_TRANSFER_FEE_ACTIVATION_HEIGHT, &assets), Err("global asset transfer fee required"));
    }

    #[test]
    #[cfg(feature = "mainnet-candidate")]
    fn token_and_nft_creation_fees_activate_at_height_twenty_two_thousand() {
        let token = AssetTransaction::Create {
            issuer: [1; 32],
            nonce: 1,
            name: "Token".into(),
            symbol: "TOK".into(),
            decimals: 9,
            max_supply: 100,
            initial_supply: 100,
        };
        let nft = AssetTransaction::CreateWithOptions {
            issuer: [1; 32],
            nonce: 2,
            name: "NFT".into(),
            symbol: "NFT".into(),
            decimals: 0,
            max_supply: 1,
            initial_supply: 1,
            mintable: false,
            burnable: false,
            issuer_fee_bps: 0,
            issuer_treasury: None,
            kind: AssetKind::Nft,
        };

        assert_eq!(asset_creation_fee_nox(&token, 21_999), Ok(ASSET_CREATION_FEE_NOX));
        assert_eq!(asset_creation_fee_nox(&nft, 21_999), Ok(ASSET_CREATION_FEE_NOX));
        assert_eq!(asset_creation_fee_nox(&token, 22_000), Ok(FUNGIBLE_ASSET_CREATION_FEE_NOX));
        assert_eq!(asset_creation_fee_nox(&nft, 22_000), Ok(ASSET_CREATION_FEE_NOX));
    }

    #[test]
    #[cfg(feature = "mainnet-candidate")]
    fn issuer_fee_cap_activates_at_height_twenty_two_thousand() {
        let mut policy = AssetTransaction::CreateWithOptions {
            issuer: [1; 32],
            nonce: 3,
            name: "Fee capped".into(),
            symbol: "CAP".into(),
            decimals: 9,
            max_supply: 100,
            initial_supply: 100,
            mintable: false,
            burnable: false,
            issuer_fee_bps: 801,
            issuer_treasury: None,
            kind: AssetKind::Fungible,
        };
        assert_eq!(validate_issuer_fee_cap(&policy, 21_999), Ok(()));
        assert_eq!(
            validate_issuer_fee_cap(&policy, 22_000),
            Err("issuer transfer fee exceeds 8 percent")
        );
        if let AssetTransaction::CreateWithOptions { issuer_fee_bps, .. } = &mut policy {
            *issuer_fee_bps = 800;
        }
        assert_eq!(validate_issuer_fee_cap(&policy, 22_000), Ok(()));
    }

    #[test]
    #[cfg(feature = "mainnet-candidate")]
    fn transfer_of_legacy_asset_over_eight_percent_is_rejected_after_activation() {
        let issuer_secret = Scalar::from(31u64);
        let issuer = (issuer_secret * RISTRETTO_BASEPOINT_POINT).compress().to_bytes();
        let issuer_treasury = crate::Address {
            view: (Scalar::from(32u64) * RISTRETTO_BASEPOINT_POINT).compress().to_bytes(),
            spend: (Scalar::from(33u64) * RISTRETTO_BASEPOINT_POINT).compress().to_bytes(),
        };
        let mut assets = AssetLedger::default();
        let asset_id = assets
            .apply(AssetTransaction::CreateWithOptions {
                issuer,
                nonce: 31,
                name: "Legacy high fee".into(),
                symbol: "LHF".into(),
                decimals: 9,
                max_supply: 100,
                initial_supply: 100,
                mintable: false,
                burnable: false,
                issuer_fee_bps: 1_000,
                issuer_treasury: Some(issuer_treasury),
                kind: AssetKind::Fungible,
            })
            .unwrap();
        let transfer = AssetTransaction::Transfer {
            asset_id,
            from: issuer,
            to: [9; 32],
            amount: 10,
        };
        let signed = crate::assets::sign_issuer(&transfer, issuer_secret, &[4; 64]).unwrap();

        assert_eq!(
            validate_asset_operation_fee(&signed, 22_000, &assets),
            Err("issuer transfer fee exceeds 8 percent")
        );
    }

    #[test]
    #[cfg(feature = "mainnet-candidate")]
    fn block_payouts_keep_reward_split_separate_from_transaction_fees() {
        assert_eq!(block_fee_payouts(100, 21_999), Ok((90, 10)));
        let reward_treasury = crate::tsc1_chain_v2::treasury_mining_reward_at_height(22_000);
        assert_eq!(block_fee_payouts(100, 22_000), Ok((0, 100 + reward_treasury)));
        let scheduled = ((22_000u128 * crate::MINING_ALLOCATION_NOX as u128)
            / crate::tsc1_chain_v2::EMISSION_BLOCKS as u128)
            - ((21_999u128 * crate::MINING_ALLOCATION_NOX as u128)
                / crate::tsc1_chain_v2::EMISSION_BLOCKS as u128);
        assert_eq!(
            crate::tsc1_chain_v2::reward_at_height(22_000) + reward_treasury,
            scheduled as u64
        );
    }

    #[test]
    #[cfg(feature = "mainnet-candidate")]
    fn mainnet_tnb_transfer_requires_confidential_one_percent_proof_at_activation() {
        let recipient = WalletSecrets::from_seed(&[119; 32]);
        let blinding = crate::tsc1_private_amounts::random_blinding().unwrap();
        let amount = 1_234u64;
        let mut payment = crate::tsc1_funded_output::create_funded_output_with_blinding(
            &recipient.address(),
            0,
            amount,
            blinding,
        )
        .unwrap();
        let fee = amount.div_ceil(100);
        crate::tsc1_private_amounts::attach_tnb_transfer_fee_proof(
            &mut payment.amount,
            amount,
            fee,
            &blinding,
        )
        .unwrap();
        let mut transaction = Transaction {
            network_id: crate::tsc1_tx_v2::NETWORK_ID,
            version: 2,
            expires_at_height: 22_010,
            inputs: Vec::new(),
            outputs: vec![payment.clone()],
            fee_nox: fee,
        };

        assert_eq!(
            validate_tnb_transfer_fee_transaction(&transaction, 22_000),
            Ok(())
        );
        transaction.fee_nox -= 1;
        assert_eq!(
            validate_tnb_transfer_fee_transaction(&transaction, 22_000),
            Err("missing or invalid confidential 1 percent TNB transfer fee proof")
        );
        transaction.fee_nox = fee;
        transaction.outputs[0].amount.range_proof =
            crate::tsc1_private_amounts::prove_amount(
                amount,
                &blinding,
                &crate::assets::TNB_ASSET_ID,
            )
            .unwrap()
            .range_proof;
        assert_eq!(
            validate_tnb_transfer_fee_transaction(&transaction, 22_000),
            Err("missing or invalid confidential 1 percent TNB transfer fee proof")
        );
        assert_eq!(
            validate_tnb_transfer_fee_transaction(&transaction, 21_999),
            Ok(())
        );
    }
    use crate::FOUNDER_ALLOCATION_NOX;
    use crate::WalletSecrets;
    use crate::tsc1_chain_v2::reward_at_height;
    use crate::tsc1_funded_output::create_reward_output;
    use crate::tsc1_tx_v2::MAX_INPUTS;
    use crate::tsc1_wallet_tx_v3::{
        create_signed_asset_creation_fee, create_signed_transfer,
    };
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;

    #[test]
    fn block_mining_stops_when_control_is_cancelled() {
        let founder = WalletSecrets::from_seed(&[1; 32]);
        let miner = WalletSecrets::from_seed(&[2; 32]);
        let genesis = Chain::new(
            create_reward_output(&founder.address(), 0, FOUNDER_ALLOCATION_NOX).unwrap(),
            1,
        )
        .unwrap();
        let chain = ChainV3::from_genesis(genesis).unwrap();
        let reward = create_reward_output(&miner.address(), 0, reward_at_height(1)).unwrap();
        let mut block = chain.next_block(reward, 2, Vec::new());

        assert!(!block.mine_with_control(|| false).unwrap());
        assert_eq!(block.nonce, 0);
    }

    fn add_mature_ring_blocks(mut chain: ChainV3, count: u64) -> ChainV3 {
        for height in 1..=count {
            let miner = WalletSecrets::from_seed(&[(120 + height) as u8; 32]);
            let reward = create_reward_output(&miner.address(), 0, reward_at_height(height)).unwrap();
            let mut block = chain.next_block(reward, height * 30 + 1, Vec::new());
            block.mine().unwrap();
            chain.append(block).unwrap();
        }
        chain
    }

    #[test]
    fn wallet_chain_rebuild_matches_consensus_and_checks_signatures() {
        let founder = WalletSecrets::from_seed(&[71; 32]);
        let miner = WalletSecrets::from_seed(&[72; 32]);
        let recipient = WalletSecrets::from_seed(&[73; 32]);
        let genesis = Chain::new(
            create_reward_output(&founder.address(), 0, FOUNDER_ALLOCATION_NOX).unwrap(),
            1,
        )
        .unwrap();
        let mut consensus = ChainV3::from_genesis(genesis.clone()).unwrap();
        let mut wallet = ChainV3::from_genesis(genesis).unwrap();
        for height in 1..=11 {
            let reward =
                create_reward_output(&miner.address(), 0, reward_at_height(height)).unwrap();
            let mut block = consensus.next_block(reward, height * 30 + 1, Vec::new());
            block.mine().unwrap();
            consensus.append(block.clone()).unwrap();
            wallet.append_wallet_state(block).unwrap();
        }

        let tx = create_signed_transfer(&wallet, &founder, &recipient.address(), 100, 10).unwrap();
        let reward = create_reward_output(&miner.address(), 0, reward_at_height(12)).unwrap();
        let mut block = wallet
            .next_block_with_fees(reward, &miner.address(), 12 * 30 + 1, vec![tx.clone()])
            .unwrap();
        block.mine().unwrap();
        consensus.append(block.clone()).unwrap();
        wallet.append_wallet_state(block).unwrap();
        assert_eq!(wallet.tip_hash(), consensus.tip_hash());
        assert_eq!(wallet.wallet_balance_nox(&founder), consensus.wallet_balance_nox(&founder));
        assert_eq!(wallet.wallet_balance_nox(&recipient), Ok(100));

        let mut invalid_tx = tx;
        invalid_tx.inputs[0].authorization[0] ^= 1;
        let reward = create_reward_output(&miner.address(), 0, reward_at_height(13)).unwrap();
        let mut invalid_block = wallet
            .next_block_with_fees(reward, &miner.address(), 13 * 30 + 1, vec![invalid_tx])
            .unwrap();
        invalid_block.mine().unwrap();
        assert!(wallet.append_wallet_state(invalid_block).is_err());
    }

    #[test]
    fn v3_block_round_trip_and_link_validation() {
        let founder = WalletSecrets::from_seed(&[81; 32]);
        let genesis_output =
            create_reward_output(&founder.address(), 0, FOUNDER_ALLOCATION_NOX).unwrap();
        let genesis = Chain::new(genesis_output, 1).unwrap();
        let genesis_for_decode = genesis.clone();
        let mut chain = ChainV3::from_genesis(genesis).unwrap();
        let miner = WalletSecrets::from_seed(&[82; 32]);
        let reward = create_reward_output(&miner.address(), 0, reward_at_height(1)).unwrap();
        let mut block = chain.next_block(reward, 2, Vec::new());
        block.mine().unwrap();
        let encoded = block.encode().unwrap();
        let decoded = BlockV3::decode(&encoded).unwrap();
        assert_eq!(decoded.hash().unwrap(), block.hash().unwrap());
        assert!(BlockV3::decode(&encoded[..encoded.len() - 1]).is_err());
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(BlockV3::decode(&trailing).is_err());
        let mut wrong_link = block.clone();
        wrong_link.previous_hash[0] ^= 1;
        wrong_link.mine().unwrap();
        assert!(chain.append(wrong_link).is_err());
        assert_eq!(chain.height(), 0);
        let mut wrong_difficulty = block.clone();
        wrong_difficulty.difficulty_bits += 1;
        wrong_difficulty.mine().unwrap();
        assert_eq!(chain.append(wrong_difficulty), Err("wrong v3 difficulty"));
        chain.append(decoded.clone()).unwrap();
        assert_eq!(chain.height(), 1);
        assert_eq!(chain.cumulative_work(), 1u128 << BASE_DIFFICULTY_BITS);
        let mut suffix = [0u8; 8];
        getrandom::getrandom(&mut suffix).unwrap();
        let directory =
            std::env::temp_dir().join(format!("tsc1-v3-block-test-{}", hex::encode(suffix)));
        persist_block(&directory, &decoded).unwrap();
        let restored_files = load_blocks(&directory, genesis_for_decode.clone()).unwrap();
        assert_eq!(restored_files.tip_hash(), chain.tip_hash());
        let file = directory.join("00000000000000000001.bin");
        let mut damaged = fs::read(&file).unwrap();
        damaged[0] ^= 1;
        fs::write(&file, damaged).unwrap();
        assert!(load_blocks(&directory, genesis_for_decode.clone()).is_err());
        fs::remove_file(file).unwrap();
        fs::remove_dir(directory).unwrap();
        let encoded_chain = chain.encode().unwrap();
        let restored = ChainV3::decode(&encoded_chain, genesis_for_decode.clone()).unwrap();
        assert_eq!(restored.tip_hash(), chain.tip_hash());
        assert!(
            ChainV3::decode(
                &encoded_chain[..encoded_chain.len() - 1],
                genesis_for_decode.clone()
            )
            .is_err()
        );
        let mut trailing_chain = encoded_chain;
        trailing_chain.push(0);
        assert!(ChainV3::decode(&trailing_chain, genesis_for_decode).is_err());
    }

    #[test]
    fn founder_reward_is_spendable_immediately() {
        let founder = WalletSecrets::from_seed(&[83; 32]);
        let genesis = Chain::new(
            create_reward_output(&founder.address(), 0, FOUNDER_ALLOCATION_NOX).unwrap(),
            1,
        )
        .unwrap();
        let chain = ChainV3::from_genesis(genesis).unwrap();
        let spends = chain.spends().clone();
        let eligible = spends.eligible_output_ids(chain.height() + 1);
        assert!(!eligible.is_empty());
        assert_eq!(REWARD_MATURITY_BLOCKS, 0);
    }

    #[test]
    fn wallet_transfer_combines_fragmented_outputs_up_to_protocol_limit() {
        let anchor = WalletSecrets::from_seed(&[84; 32]);
        let founder = WalletSecrets::from_seed(&[85; 32]);
        let recipient = WalletSecrets::from_seed(&[86; 32]);
        let genesis = Chain::new(
            create_reward_output(&anchor.address(), 0, FOUNDER_ALLOCATION_NOX).unwrap(),
            1,
        )
        .unwrap();
        let mut chain = ChainV3::from_genesis(genesis).unwrap();
        for _ in 0..MAX_INPUTS {
            let output = create_reward_output(&founder.address(), 0, 1_500_000_000_000).unwrap();
            let id = output.destination.destination;
            chain.spends.add_mining_reward(id, &output, 0).unwrap();
        }

        let tx = create_signed_transfer(
            &chain,
            &founder,
            &recipient.address(),
            20_000_000_000_000,
            200_000_000_000,
        )
        .unwrap();

        assert!(tx.inputs.len() > 2);
        assert!(tx.inputs.len() <= MAX_INPUTS);
        chain.spends.apply_batch(&[tx], 1).unwrap();

        let issuer = WalletSecrets::from_seed(&[87; 32]);
        for _ in 0..MAX_INPUTS {
            let output = create_reward_output(&issuer.address(), 0, 1_000_000_000).unwrap();
            let id = output.destination.destination;
            chain.spends.add_mining_reward(id, &output, 0).unwrap();
        }
        let fee_tx = create_signed_asset_creation_fee(&chain, &issuer, [88; 32]).unwrap();
        assert!(fee_tx.inputs.len() > 1);
        chain.spends.apply_batch(&[fee_tx], 1).unwrap();

        let delayed_large_output_wallet = WalletSecrets::from_seed(&[89; 32]);
        for index in 1u8..=MAX_INPUTS as u8 {
            let output =
                create_reward_output(&delayed_large_output_wallet.address(), 0, 1_000_000_000)
                    .unwrap();
            chain
                .spends
                .add_mining_reward([index; 32], &output, 0)
                .unwrap();
        }
        let large_output = create_reward_output(
            &delayed_large_output_wallet.address(),
            0,
            25_000_000_000_000,
        )
        .unwrap();
        let large_output_id = [u8::MAX; 32];
        chain
            .spends
            .add_mining_reward(large_output_id, &large_output, 0)
            .unwrap();
        let ordered_tx = create_signed_transfer(
            &chain,
            &delayed_large_output_wallet,
            &recipient.address(),
            20_000_000_000_000,
            200_000_000_000,
        )
        .unwrap();
        assert_eq!(ordered_tx.inputs.len(), 1);
        assert!(ordered_tx.inputs[0].members.contains(&large_output_id));
    }

    #[test]
    fn rejects_mined_block_too_far_in_future() {
        let founder = WalletSecrets::from_seed(&[83; 32]);
        let genesis = Chain::new(
            create_reward_output(&founder.address(), 0, FOUNDER_ALLOCATION_NOX).unwrap(),
            1,
        )
        .unwrap();
        let mut chain = ChainV3::from_genesis(genesis).unwrap();
        let miner = WalletSecrets::from_seed(&[84; 32]);
        let reward = create_reward_output(&miner.address(), 0, reward_at_height(1)).unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut block = chain.next_block(reward, now + MAX_FUTURE_DRIFT_SECONDS + 60, Vec::new());
        block.mine().unwrap();
        assert_eq!(
            chain.append(block),
            Err("v3 block timestamp too far in future")
        );
        assert_eq!(chain.height(), 0);
    }

    #[test]
    fn block_round_trip_applies_asset_operations_to_chain_ledger() {
        let founder = WalletSecrets::from_seed(&[85; 32]);
        let genesis = Chain::new(
            create_reward_output(&founder.address(), 0, FOUNDER_ALLOCATION_NOX).unwrap(),
            1,
        )
        .unwrap();
        let chain = ChainV3::from_genesis(genesis).unwrap();
        let mut chain = add_mature_ring_blocks(chain, 16);
        let miner = WalletSecrets::from_seed(&[86; 32]);
        let issuer = (Scalar::from(9u64) * curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT)
            .compress()
            .to_bytes();
        let create = crate::assets::AssetTransaction::Create {
            issuer,
            nonce: 1,
            name: "Project Coin".into(),
            symbol: "PRJ".into(),
            decimals: 6,
            max_supply: 1_000,
            initial_supply: 100,
        };
        let asset_id = crate::assets::AssetDefinition::derive_id(&issuer, 1);
        let reward = create_reward_output(&miner.address(), 0, reward_at_height(17)).unwrap();
        let mut block = chain.next_block(reward, 17 * 30 + 1, Vec::new());
        let mut signed_create = crate::assets::sign_issuer(&create, Scalar::from(9u64), &[4u8; 64]).unwrap();
        signed_create.creation_fee = Some(crate::tsc1_wallet_tx_v3::create_signed_asset_creation_fee(&chain, &founder, create.txid().unwrap()).unwrap());
        block.asset_transactions.push(signed_create);
        block.mine().unwrap();
        let encoded = block.encode().unwrap();
        let decoded = BlockV3::decode(&encoded).unwrap();
        chain.append(decoded).unwrap();
        assert_eq!(chain.assets().balance(&asset_id, &issuer), 100);
        assert_eq!(
            chain.assets().registry.get(&asset_id).unwrap().symbol,
            "PRJ"
        );
    }

    #[test]
    fn wallet_balance_includes_change_from_asset_creation_fee() {
        let founder = WalletSecrets::from_seed(&[85; 32]);
        let genesis = Chain::new(
            create_reward_output(&founder.address(), 0, FOUNDER_ALLOCATION_NOX).unwrap(),
            1,
        )
        .unwrap();
        let chain = ChainV3::from_genesis(genesis).unwrap();
        let mut chain = add_mature_ring_blocks(chain, 32);
        let issuer_secret = Scalar::from(9u64);
        let issuer = (issuer_secret * RISTRETTO_BASEPOINT_POINT)
            .compress()
            .to_bytes();
        let create = crate::assets::AssetTransaction::Create {
            issuer,
            nonce: 1,
            name: "Fee change fixture".into(),
            symbol: "FCF".into(),
            decimals: 9,
            max_supply: 1_000,
            initial_supply: 1_000,
        };
        let mut signed = crate::assets::sign_issuer(&create, issuer_secret, &[4u8; 64]).unwrap();
        signed.creation_fee = Some(
            create_signed_asset_creation_fee(&chain, &founder, create.txid().unwrap()).unwrap(),
        );
        let reward = create_reward_output(&WalletSecrets::from_seed(&[86; 32]).address(), 0, reward_at_height(33)).unwrap();
        let mut block = chain.next_block(reward, 33 * 30 + 1, Vec::new());
        block.asset_transactions.push(signed);
        block.mine().unwrap();
        chain.append_wallet_state(block).unwrap();

        assert_eq!(
            chain.wallet_balance_nox(&founder),
            Ok(FOUNDER_ALLOCATION_NOX - crate::tsc1_chain_v3::ASSET_CREATION_FEE_NOX - 1),
        );
    }

    #[test]
    fn block_round_trip_rebuilds_dex_state_and_rejects_duplicate_pool_creation() {
        let founder = WalletSecrets::from_seed(&[87; 32]);
        let genesis = Chain::new(
            create_reward_output(&founder.address(), 0, FOUNDER_ALLOCATION_NOX).unwrap(),
            1,
        )
        .unwrap();
        let genesis_for_decode = genesis.clone();
        let chain = ChainV3::from_genesis(genesis).unwrap();
        let mut chain = add_mature_ring_blocks(chain, 16);
        let miner = WalletSecrets::from_seed(&[88; 32]);
        let issuer_secret = Scalar::from(17u64);
        let issuer = (issuer_secret * RISTRETTO_BASEPOINT_POINT).compress().to_bytes();
        let provider_secret = Scalar::from(18u64);
        let provider = (provider_secret * RISTRETTO_BASEPOINT_POINT).compress().to_bytes();
        let create_a = crate::assets::AssetTransaction::Create {
            issuer,
            nonce: 1,
            name: "Alpha".into(),
            symbol: "ALP".into(),
            decimals: 6,
            max_supply: 1_000,
            initial_supply: 100,
        };
        let create_b = crate::assets::AssetTransaction::Create {
            issuer,
            nonce: 2,
            name: "Beta".into(),
            symbol: "BET".into(),
            decimals: 6,
            max_supply: 1_000,
            initial_supply: 100,
        };
        let asset_a = crate::assets::AssetDefinition::derive_id(&issuer, 1);
        let asset_b = crate::assets::AssetDefinition::derive_id(&issuer, 2);
        let funding = crate::tsc1_wallet_tx_v3::create_signed_transfer(&chain, &founder, &miner.address(), 20_000_000_000, 1).unwrap();
        let funding_reward = create_reward_output(&miner.address(), 0, reward_at_height(17)).unwrap();
        let mut funding_block = chain.next_block_with_fees(funding_reward, &miner.address(), 17 * 30 + 1, vec![funding]).unwrap();
        funding_block.mine().unwrap();
        chain.append(funding_block).unwrap();
        let reward = create_reward_output(&miner.address(), 0, reward_at_height(18)).unwrap();
        let mut block = chain.next_block(reward, 18 * 30 + 1, Vec::new());
        let mut signed_a = crate::assets::sign_issuer(&create_a, issuer_secret, &[5u8; 64]).unwrap();
        signed_a.creation_fee = Some(crate::tsc1_wallet_tx_v3::create_signed_asset_creation_fee(&chain, &founder, create_a.txid().unwrap()).unwrap());
        let mut signed_b = crate::assets::sign_issuer(&create_b, issuer_secret, &[6u8; 64]).unwrap();
        signed_b.creation_fee = Some(crate::tsc1_wallet_tx_v3::create_signed_asset_creation_fee(&chain, &miner, create_b.txid().unwrap()).unwrap());
        block.asset_transactions.push(signed_a);
        block.asset_transactions.push(signed_b);
        block.asset_transactions.push(
            crate::assets::sign_issuer(
                &crate::assets::AssetTransaction::Transfer {
                    asset_id: asset_a,
                    from: issuer,
                    to: provider,
                    amount: 100,
                },
                issuer_secret,
                &[7u8; 64],
            )
            .unwrap(),
        );
        block.asset_transactions.push(
            crate::assets::sign_issuer(
                &crate::assets::AssetTransaction::Transfer {
                    asset_id: asset_b,
                    from: issuer,
                    to: provider,
                    amount: 100,
                },
                issuer_secret,
                &[8u8; 64],
            )
            .unwrap(),
        );
        let pool_op = crate::dex::DexOperation::CreatePool {
            asset_a,
            asset_b,
            amount_a: 50,
            amount_b: 50,
            provider,
        };
        let pool_signed = crate::dex::sign(&pool_op, provider_secret, &[9u8; 64]);
        block.dex_operations.push(pool_signed.clone());
        block.mine().unwrap();
        chain.append(block.clone()).unwrap();
        assert_eq!(chain.dex().pools.len(), 1);
        assert!(chain.dex().has_applied_operation(&pool_signed.id()));
        let encoded = chain.encode().unwrap();
        let restored = ChainV3::decode(&encoded, genesis_for_decode).unwrap();
        assert_eq!(restored.dex().pools.len(), 1);
        assert!(restored.dex().has_applied_operation(&pool_signed.id()));
        let mut duplicate_ledger = restored.assets().clone();
        let mut restored_dex = restored.dex().clone();
        let duplicate = crate::dex::sign(&pool_op, provider_secret, &[10u8; 64]);
        assert_eq!(
            restored_dex.apply(&duplicate, &mut duplicate_ledger),
            Err("dex operation already applied")
        );
    }
}
