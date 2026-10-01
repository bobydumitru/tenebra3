use sha2::{Digest, Sha256};
use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, ristretto::CompressedRistretto, scalar::Scalar};
use sha2::Sha512;
use std::collections::BTreeMap;

pub type AssetId = [u8; 32];

pub const TNB_ASSET_ID: AssetId = [0; 32];
pub const TNB_DECIMALS: u8 = 9;
pub const MAX_ISSUER_TRANSFER_FEE_BPS: u16 = 800;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AssetKind {
    #[default]
    Fungible,
    Nft,
}

pub fn transfer_fee_nox(amount: u64, asset_decimals: u8, fee_bps: u16) -> Result<u64, &'static str> {
    if amount == 0 || asset_decimals > 18 || fee_bps == 0 || fee_bps > 10_000 {
        return Err("invalid asset transfer fee input");
    }
    let numerator = (amount as u128)
        .checked_mul(10u128.pow(TNB_DECIMALS as u32))
        .ok_or("asset transfer fee overflow")?;
    let denominator = 10_000u128
        .checked_mul(10u128.pow(asset_decimals as u32))
        .ok_or("asset transfer fee overflow")?;
    let numerator = numerator.checked_mul(fee_bps as u128).ok_or("asset transfer fee overflow")?;
    let fee = numerator.div_ceil(denominator).max(1);
    u64::try_from(fee).map_err(|_| "asset transfer fee overflow")
}

pub fn global_asset_transfer_fee_nox(amount: u64, asset_decimals: u8) -> Result<u64, &'static str> {
    transfer_fee_nox(amount, asset_decimals, 100)
}

fn validate_issuer_fee(fee_bps: u16, treasury: Option<&crate::Address>) -> Result<(), &'static str> {
    if fee_bps > 10_000 || (fee_bps == 0) != treasury.is_none() {
        return Err("invalid issuer fee policy");
    }
    if let Some(address) = treasury {
        if curve25519_dalek::ristretto::CompressedRistretto(address.view).decompress().is_none()
            || curve25519_dalek::ristretto::CompressedRistretto(address.spend).decompress().is_none()
        {
            return Err("invalid issuer treasury address");
        }
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetDefinition {
    pub id: AssetId,
    pub issuer: [u8; 32],
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub max_supply: u64,
    pub minted: u64,
    pub mintable: bool,
    pub burnable: bool,
    pub issuer_fee_bps: u16,
    pub issuer_treasury: Option<crate::Address>,
    pub kind: AssetKind,
}

impl AssetDefinition {
    pub fn derive_id(issuer: &[u8; 32], nonce: u64) -> AssetId {
        let mut hash = Sha256::new();
        hash.update(b"TENEBRA:asset:v1");
        hash.update(issuer);
        hash.update(nonce.to_le_bytes());
        hash.finalize().into()
    }

    pub fn new(
        issuer: [u8; 32],
        nonce: u64,
        name: String,
        symbol: String,
        decimals: u8,
        max_supply: u64,
        initial_supply: u64,
    ) -> Result<Self, &'static str> {
        Self::new_with_options(issuer, nonce, name, symbol, decimals, max_supply, initial_supply, true, false)
    }

    pub fn new_with_options(
        issuer: [u8; 32],
        nonce: u64,
        name: String,
        symbol: String,
        decimals: u8,
        max_supply: u64,
        initial_supply: u64,
        mintable: bool,
        burnable: bool,
    ) -> Result<Self, &'static str> {
        if name.is_empty() || name.len() > 64 || symbol.is_empty() || symbol.len() > 16 {
            return Err("invalid asset metadata");
        }
        if !name.is_ascii() || !symbol.is_ascii() || decimals > 18 || max_supply == 0 {
            return Err("invalid asset metadata");
        }
        if initial_supply > max_supply {
            return Err("initial supply exceeds max supply");
        }
        Ok(Self {
            id: Self::derive_id(&issuer, nonce),
            issuer,
            name,
            symbol,
            decimals,
            max_supply,
            minted: initial_supply,
            mintable,
            burnable,
            issuer_fee_bps: 0,
            issuer_treasury: None,
            kind: AssetKind::Fungible,
        })
    }

    pub fn new_with_issuer_fee(
        issuer: [u8; 32], nonce: u64, name: String, symbol: String, decimals: u8,
        max_supply: u64, initial_supply: u64, mintable: bool, burnable: bool,
        issuer_fee_bps: u16, issuer_treasury: Option<crate::Address>, kind: AssetKind,
    ) -> Result<Self, &'static str> {
        validate_issuer_fee(issuer_fee_bps, issuer_treasury.as_ref())?;
        let mut asset = Self::new_with_options(issuer, nonce, name, symbol, decimals, max_supply, initial_supply, mintable, burnable)?;
        asset.issuer_fee_bps = issuer_fee_bps;
        asset.issuer_treasury = issuer_treasury;
        asset.kind = kind;
        Ok(asset)
    }

    pub fn remaining_supply(&self) -> u64 {
        self.max_supply - self.minted
    }

    pub fn mint(&mut self, amount: u64) -> Result<(), &'static str> {
        if !self.mintable {
            return Err("asset minting disabled");
        }
        let next_minted = self.minted.checked_add(amount).ok_or("supply overflow")?;
        if next_minted > self.max_supply {
            return Err("asset max supply exceeded");
        }
        self.minted = next_minted;
        Ok(())
    }

    pub fn burn(&mut self, amount: u64) -> Result<(), &'static str> {
        if !self.burnable {
            return Err("asset burning disabled");
        }
        if amount == 0 {
            return Err("invalid asset burn");
        }
        self.minted = self.minted.checked_sub(amount).ok_or("asset supply underflow")?;
        Ok(())
    }

    pub fn increase_max_supply(&mut self, new_max_supply: u64) -> Result<(), &'static str> {
        if !self.mintable {
            return Err("asset minting disabled");
        }
        if new_max_supply <= self.max_supply || new_max_supply < self.minted {
            return Err("new max supply must exceed current max supply");
        }
        self.max_supply = new_max_supply;
        Ok(())
    }

    pub fn update_options(&mut self, mintable: bool, burnable: bool, issuer_fee_bps: u16, issuer_treasury: Option<crate::Address>) -> Result<(), &'static str> {
        validate_issuer_fee(issuer_fee_bps, issuer_treasury.as_ref())?;
        self.mintable = mintable;
        self.burnable = burnable;
        self.issuer_fee_bps = issuer_fee_bps;
        self.issuer_treasury = issuer_treasury;
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AssetRegistry {
    assets: BTreeMap<AssetId, AssetDefinition>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AssetTransaction {
    Create {
        issuer: [u8; 32],
        nonce: u64,
        name: String,
        symbol: String,
        decimals: u8,
        max_supply: u64,
        initial_supply: u64,
    },
    CreateWithOptions {
        issuer: [u8; 32],
        nonce: u64,
        name: String,
        symbol: String,
        decimals: u8,
        max_supply: u64,
        initial_supply: u64,
        mintable: bool,
        burnable: bool,
        issuer_fee_bps: u16,
        issuer_treasury: Option<crate::Address>,
        kind: AssetKind,
    },
    Mint {
        asset_id: AssetId,
        issuer: [u8; 32],
        amount: u64,
    },
    Transfer {
        asset_id: AssetId,
        from: [u8; 32],
        to: [u8; 32],
        amount: u64,
    },
    Burn {
        asset_id: AssetId,
        from: [u8; 32],
        amount: u64,
    },
    IncreaseMaxSupply {
        asset_id: AssetId,
        issuer: [u8; 32],
        new_max_supply: u64,
    },
    UpdateOptions {
        asset_id: AssetId,
        issuer: [u8; 32],
        mintable: bool,
        burnable: bool,
        issuer_fee_bps: u16,
        issuer_treasury: Option<crate::Address>,
    },
}

fn encode_treasury(bytes: &mut Vec<u8>, treasury: Option<&crate::Address>) {
    match treasury {
        Some(address) => {
            bytes.push(1);
            bytes.extend_from_slice(&address.view);
            bytes.extend_from_slice(&address.spend);
        }
        None => bytes.push(0),
    }
}

impl AssetTransaction {
    pub fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        const PREFIX: &[u8] = b"TSC-1:asset-tx:v2";
        if bytes.len() <= PREFIX.len() || &bytes[..PREFIX.len()] != PREFIX { return Err("wrong asset transaction format"); }
        let kind = bytes[PREFIX.len()];
        let mut cursor = PREFIX.len() + 1;
        let take = |cursor: &mut usize, count: usize| -> Result<&[u8], &'static str> {
            if *cursor + count > bytes.len() { return Err("truncated asset transaction"); }
            let slice = &bytes[*cursor..*cursor + count]; *cursor += count; Ok(slice)
        };
        let array = |cursor: &mut usize| -> Result<[u8; 32], &'static str> { take(cursor, 32)?.try_into().map_err(|_| "invalid asset field") };
        let u64_at = |cursor: &mut usize| -> Result<u64, &'static str> { Ok(u64::from_le_bytes(take(cursor, 8)?.try_into().map_err(|_| "invalid asset integer")?)) };
        let tx = match kind {
            0 => {
                let issuer = array(&mut cursor)?; let nonce = u64_at(&mut cursor)?;
                let name_len = take(&mut cursor, 1)?[0] as usize; let name = String::from_utf8(take(&mut cursor, name_len)?.to_vec()).map_err(|_| "invalid asset name")?;
                let symbol_len = take(&mut cursor, 1)?[0] as usize; let symbol = String::from_utf8(take(&mut cursor, symbol_len)?.to_vec()).map_err(|_| "invalid asset symbol")?;
                let decimals = take(&mut cursor, 1)?[0]; let max_supply = u64_at(&mut cursor)?; let initial_supply = u64_at(&mut cursor)?;
                Self::Create { issuer, nonce, name, symbol, decimals, max_supply, initial_supply }
            }
            1 => Self::Mint { asset_id: array(&mut cursor)?, issuer: array(&mut cursor)?, amount: u64_at(&mut cursor)? },
            2 => Self::Transfer { asset_id: array(&mut cursor)?, from: array(&mut cursor)?, to: array(&mut cursor)?, amount: u64_at(&mut cursor)? },
            3 | 7 => {
                let issuer = array(&mut cursor)?; let nonce = u64_at(&mut cursor)?;
                let name_len = take(&mut cursor, 1)?[0] as usize; let name = String::from_utf8(take(&mut cursor, name_len)?.to_vec()).map_err(|_| "invalid asset name")?;
                let symbol_len = take(&mut cursor, 1)?[0] as usize; let symbol = String::from_utf8(take(&mut cursor, symbol_len)?.to_vec()).map_err(|_| "invalid asset symbol")?;
                let decimals = take(&mut cursor, 1)?[0]; let max_supply = u64_at(&mut cursor)?; let initial_supply = u64_at(&mut cursor)?;
                let mintable = match take(&mut cursor, 1)?[0] { 0 => false, 1 => true, _ => return Err("invalid mintable flag") };
                let burnable = match take(&mut cursor, 1)?[0] { 0 => false, 1 => true, _ => return Err("invalid burnable flag") };
                let issuer_fee_bps = u16::from_le_bytes(take(&mut cursor, 2)?.try_into().map_err(|_| "invalid issuer fee")?);
                let issuer_treasury = match take(&mut cursor, 1)?[0] {
                    0 => None,
                    1 => Some(crate::Address { view: array(&mut cursor)?, spend: array(&mut cursor)? }),
                    _ => return Err("invalid issuer treasury flag"),
                };
                validate_issuer_fee(issuer_fee_bps, issuer_treasury.as_ref())?;
                let kind = if kind == 7 { AssetKind::Nft } else { AssetKind::Fungible };
                Self::CreateWithOptions { issuer, nonce, name, symbol, decimals, max_supply, initial_supply, mintable, burnable, issuer_fee_bps, issuer_treasury, kind }
            }
            4 => Self::Burn { asset_id: array(&mut cursor)?, from: array(&mut cursor)?, amount: u64_at(&mut cursor)? },
            5 => Self::IncreaseMaxSupply { asset_id: array(&mut cursor)?, issuer: array(&mut cursor)?, new_max_supply: u64_at(&mut cursor)? },
            6 => {
                let asset_id = array(&mut cursor)?;
                let issuer = array(&mut cursor)?;
                let mintable = match take(&mut cursor, 1)?[0] { 0 => false, 1 => true, _ => return Err("invalid mintable flag") };
                let burnable = match take(&mut cursor, 1)?[0] { 0 => false, 1 => true, _ => return Err("invalid burnable flag") };
                let issuer_fee_bps = u16::from_le_bytes(take(&mut cursor, 2)?.try_into().map_err(|_| "invalid issuer fee")?);
                let issuer_treasury = match take(&mut cursor, 1)?[0] {
                    0 => None,
                    1 => Some(crate::Address { view: array(&mut cursor)?, spend: array(&mut cursor)? }),
                    _ => return Err("invalid issuer treasury flag"),
                };
                validate_issuer_fee(issuer_fee_bps, issuer_treasury.as_ref())?;
                Self::UpdateOptions { asset_id, issuer, mintable, burnable, issuer_fee_bps, issuer_treasury }
            }
            _ => return Err("unknown asset transaction kind"),
        };
        if cursor != bytes.len() { return Err("trailing asset transaction bytes"); }
        Ok(tx)
    }

    pub fn encode(&self) -> Result<Vec<u8>, &'static str> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"TSC-1:asset-tx:v2");
        match self {
            Self::Create { issuer, nonce, name, symbol, decimals, max_supply, initial_supply } => {
                if name.len() > 64 || symbol.len() > 16 || !name.is_ascii() || !symbol.is_ascii() { return Err("invalid asset metadata"); }
                bytes.push(0);
                bytes.extend_from_slice(issuer);
                bytes.extend_from_slice(&nonce.to_le_bytes());
                bytes.push(name.len() as u8); bytes.extend_from_slice(name.as_bytes());
                bytes.push(symbol.len() as u8); bytes.extend_from_slice(symbol.as_bytes());
                bytes.push(*decimals);
                bytes.extend_from_slice(&max_supply.to_le_bytes());
                bytes.extend_from_slice(&initial_supply.to_le_bytes());
            }
            Self::CreateWithOptions { issuer, nonce, name, symbol, decimals, max_supply, initial_supply, mintable, burnable, issuer_fee_bps, issuer_treasury, kind } => {
                if name.is_empty() || name.len() > 64 || symbol.is_empty() || symbol.len() > 16 || !name.is_ascii() || !symbol.is_ascii() || *decimals > 18 || *max_supply == 0 || initial_supply > max_supply {
                    return Err("invalid asset metadata or supply");
                }
                validate_issuer_fee(*issuer_fee_bps, issuer_treasury.as_ref())?;
                bytes.push(if *kind == AssetKind::Nft { 7 } else { 3 });
                bytes.extend_from_slice(issuer);
                bytes.extend_from_slice(&nonce.to_le_bytes());
                bytes.push(name.len() as u8); bytes.extend_from_slice(name.as_bytes());
                bytes.push(symbol.len() as u8); bytes.extend_from_slice(symbol.as_bytes());
                bytes.push(*decimals);
                bytes.extend_from_slice(&max_supply.to_le_bytes());
                bytes.extend_from_slice(&initial_supply.to_le_bytes());
                bytes.push(u8::from(*mintable));
                bytes.push(u8::from(*burnable));
                bytes.extend_from_slice(&issuer_fee_bps.to_le_bytes());
                encode_treasury(&mut bytes, issuer_treasury.as_ref());
            }
            Self::Mint { asset_id, issuer, amount } => {
                bytes.push(1); bytes.extend_from_slice(asset_id); bytes.extend_from_slice(issuer); bytes.extend_from_slice(&amount.to_le_bytes());
            }
            Self::Transfer { asset_id, from, to, amount } => {
                bytes.push(2); bytes.extend_from_slice(asset_id); bytes.extend_from_slice(from); bytes.extend_from_slice(to); bytes.extend_from_slice(&amount.to_le_bytes());
            }
            Self::Burn { asset_id, from, amount } => {
                if *amount == 0 { return Err("invalid asset burn"); }
                bytes.push(4); bytes.extend_from_slice(asset_id); bytes.extend_from_slice(from); bytes.extend_from_slice(&amount.to_le_bytes());
            }
            Self::IncreaseMaxSupply { asset_id, issuer, new_max_supply } => {
                bytes.push(5); bytes.extend_from_slice(asset_id); bytes.extend_from_slice(issuer); bytes.extend_from_slice(&new_max_supply.to_le_bytes());
            }
            Self::UpdateOptions { asset_id, issuer, mintable, burnable, issuer_fee_bps, issuer_treasury } => {
                validate_issuer_fee(*issuer_fee_bps, issuer_treasury.as_ref())?;
                bytes.push(6); bytes.extend_from_slice(asset_id); bytes.extend_from_slice(issuer);
                bytes.push(u8::from(*mintable)); bytes.push(u8::from(*burnable));
                bytes.extend_from_slice(&issuer_fee_bps.to_le_bytes());
                encode_treasury(&mut bytes, issuer_treasury.as_ref());
            }
        }
        Ok(bytes)
    }

    pub fn txid(&self) -> Result<AssetId, &'static str> {
        Ok(Sha256::digest(self.encode()?).into())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedAssetTransaction {
    pub transaction: AssetTransaction,
    pub issuer_public: [u8; 32],
    pub signature: [u8; 64],
    pub creation_fee: Option<crate::tsc1_tx_v2::Transaction>,
}

fn challenge(public: &[u8; 32], message: &[u8], commitment: &[u8; 32]) -> Scalar {
    let mut hash = Sha512::new();
    hash.update(b"TENEBRA:asset-issuer:v1");
    hash.update(public); hash.update(message); hash.update(commitment);
    Scalar::from_hash(hash)
}

pub fn sign_issuer(transaction: &AssetTransaction, secret: Scalar, nonce_wide: &[u8; 64]) -> Result<SignedAssetTransaction, &'static str> {
    let public = (secret * RISTRETTO_BASEPOINT_POINT).compress().to_bytes();
    let message = transaction.encode()?;
    let nonce = Scalar::from_bytes_mod_order_wide(nonce_wide);
    let commitment = (nonce * RISTRETTO_BASEPOINT_POINT).compress().to_bytes();
    let response = nonce + challenge(&public, &message, &commitment) * secret;
    Ok(SignedAssetTransaction { transaction: transaction.clone(), issuer_public: public, signature: [commitment, response.to_bytes()].concat().try_into().map_err(|_| "signature encoding failed")?, creation_fee: None })
}

impl SignedAssetTransaction {
    pub fn encode(&self) -> Result<Vec<u8>, &'static str> {
        let mut bytes = self.transaction.encode()?;
        bytes.extend_from_slice(&self.issuer_public);
        bytes.extend_from_slice(&self.signature);
        if let Some(fee) = &self.creation_fee {
            let encoded = fee.encode()?;
            if encoded.len() > 512 * 1024 { return Err("oversized creation fee transaction"); }
            bytes.extend_from_slice(b"FEE1");
            bytes.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&encoded);
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 96 { return Err("truncated signed asset transaction"); }
        let prefix_len = b"TSC-1:asset-tx:v2".len() + 1;
        for operation_end in prefix_len..=bytes.len() - 96 {
            let Ok(transaction) = AssetTransaction::decode(&bytes[..operation_end]) else { continue };
            let signed_end = operation_end + 96;
            if signed_end > bytes.len() { continue; }
            let remainder = &bytes[signed_end..];
            let fee_bytes = if remainder.is_empty() {
                None
            } else if remainder.len() >= 8 && &remainder[..4] == b"FEE1" {
                let length = u32::from_le_bytes(remainder[4..8].try_into().map_err(|_| "invalid fee length")?) as usize;
                if length == 0 || remainder.len() != 8 + length { continue; }
                Some(&remainder[8..])
            } else {
                continue;
            };
            let issuer_public = bytes[operation_end..signed_end - 64].try_into().map_err(|_| "invalid issuer key")?;
            let signature = bytes[signed_end - 64..signed_end].try_into().map_err(|_| "invalid issuer signature")?;
            let creation_fee = fee_bytes.map(crate::tsc1_tx_v2::Transaction::decode).transpose()?;
            let signed = Self { transaction, issuer_public, signature, creation_fee };
            if signed.encode()? == bytes { return Ok(signed); }
        }
        Err("invalid signed asset transaction")
    }

    pub fn verify(&self) -> Result<(), &'static str> {
        let message = self.transaction.encode()?;
        let commitment = CompressedRistretto(self.signature[..32].try_into().map_err(|_| "invalid signature")?).decompress().ok_or("invalid issuer commitment")?;
        let response = Scalar::from_canonical_bytes(self.signature[32..].try_into().map_err(|_| "invalid signature")?).into_option().ok_or("invalid issuer response")?;
        let public = CompressedRistretto(self.issuer_public).decompress().ok_or("invalid issuer key")?;
        if response * RISTRETTO_BASEPOINT_POINT != commitment + challenge(&self.issuer_public, &message, &self.signature[..32].try_into().map_err(|_| "invalid signature")?) * public { return Err("invalid issuer signature"); }
        match &self.transaction {
            AssetTransaction::Create { issuer, .. } | AssetTransaction::CreateWithOptions { issuer, .. } | AssetTransaction::Mint { issuer, .. } | AssetTransaction::IncreaseMaxSupply { issuer, .. } | AssetTransaction::UpdateOptions { issuer, .. } if issuer != &self.issuer_public => Err("issuer key mismatch"),
            AssetTransaction::Transfer { from, .. } | AssetTransaction::Burn { from, .. } if from != &self.issuer_public => Err("asset owner key mismatch"),
            _ => Ok(()),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AssetLedger {
    pub registry: AssetRegistry,
    balances: BTreeMap<(AssetId, [u8; 32]), u64>,
}

impl AssetLedger {
    pub fn balance(&self, asset_id: &AssetId, owner: &[u8; 32]) -> u64 {
        self.balances.get(&(*asset_id, *owner)).copied().unwrap_or(0)
    }

    pub fn apply(&mut self, transaction: AssetTransaction) -> Result<AssetId, &'static str> {
        match transaction {
            AssetTransaction::Create { issuer, nonce, name, symbol, decimals, max_supply, initial_supply } => {
                let asset = AssetDefinition::new(issuer, nonce, name, symbol, decimals, max_supply, initial_supply)?;
                let id = self.registry.register(asset)?;
                if initial_supply > 0 {
                    self.credit(id, &issuer, initial_supply)?;
                }
                Ok(id)
            }
            AssetTransaction::CreateWithOptions { issuer, nonce, name, symbol, decimals, max_supply, initial_supply, mintable, burnable, issuer_fee_bps, issuer_treasury, kind } => {
                let asset = AssetDefinition::new_with_issuer_fee(issuer, nonce, name, symbol, decimals, max_supply, initial_supply, mintable, burnable, issuer_fee_bps, issuer_treasury, kind)?;
                let id = self.registry.register(asset)?;
                if initial_supply > 0 {
                    self.credit(id, &issuer, initial_supply)?;
                }
                Ok(id)
            }
            AssetTransaction::Mint { asset_id, issuer, amount } => {
                let asset = self.registry.get(&asset_id).ok_or("unknown asset")?;
                if asset.issuer != issuer {
                    return Err("mint issuer mismatch");
                }
                self.registry.mint(&asset_id, amount)?;
                self.credit(asset_id, &issuer, amount)?;
                Ok(asset_id)
            }
            AssetTransaction::Transfer { asset_id, from, to, amount } => {
                if amount == 0 || from == to {
                    return Err("invalid asset transfer");
                }
                let current = self.balance(&asset_id, &from);
                if current < amount {
                    return Err("insufficient asset balance");
                }
                self.debit(asset_id, &from, amount)?;
                self.credit(asset_id, &to, amount)?;
                Ok(asset_id)
            }
            AssetTransaction::Burn { asset_id, from, amount } => {
                if amount == 0 { return Err("invalid asset burn"); }
                if self.balance(&asset_id, &from) < amount { return Err("insufficient asset balance"); }
                self.registry.burn(&asset_id, amount)?;
                self.debit(asset_id, &from, amount)?;
                Ok(asset_id)
            }
            AssetTransaction::IncreaseMaxSupply { asset_id, issuer, new_max_supply } => {
                let asset = self.registry.get(&asset_id).ok_or("unknown asset")?;
                if asset.issuer != issuer { return Err("mint issuer mismatch"); }
                self.registry.increase_max_supply(&asset_id, new_max_supply)?;
                Ok(asset_id)
            }
            AssetTransaction::UpdateOptions { asset_id, issuer, mintable, burnable, issuer_fee_bps, issuer_treasury } => {
                let asset = self.registry.get(&asset_id).ok_or("unknown asset")?;
                if asset.issuer != issuer { return Err("asset issuer mismatch"); }
                self.registry.update_options(&asset_id, mintable, burnable, issuer_fee_bps, issuer_treasury)?;
                Ok(asset_id)
            }
        }
    }

    pub fn transfer(&mut self, asset_id: AssetId, from: &[u8; 32], to: &[u8; 32], amount: u128) -> Result<(), &'static str> {
        let amount = u64::try_from(amount).map_err(|_| "asset amount exceeds u64")?;
        self.apply(AssetTransaction::Transfer { asset_id, from: *from, to: *to, amount })?;
        Ok(())
    }

    fn credit(&mut self, asset_id: AssetId, owner: &[u8; 32], amount: u64) -> Result<(), &'static str> {
        let entry = self.balances.entry((asset_id, *owner)).or_default();
        *entry = entry.checked_add(amount).ok_or("balance overflow")?;
        Ok(())
    }

    fn debit(&mut self, asset_id: AssetId, owner: &[u8; 32], amount: u64) -> Result<(), &'static str> {
        let entry = self.balances.get_mut(&(asset_id, *owner)).ok_or("insufficient asset balance")?;
        *entry = entry.checked_sub(amount).ok_or("insufficient asset balance")?;
        Ok(())
    }
}

impl AssetRegistry {
    pub fn register(&mut self, asset: AssetDefinition) -> Result<AssetId, &'static str> {
        if asset.id == TNB_ASSET_ID || self.assets.contains_key(&asset.id) {
            return Err("asset already registered");
        }
        self.assets.insert(asset.id, asset.clone());
        Ok(asset.id)
    }

    pub fn get(&self, id: &AssetId) -> Option<&AssetDefinition> {
        if *id == TNB_ASSET_ID {
            return None;
        }
        self.assets.get(id)
    }

    pub fn mint(&mut self, id: &AssetId, amount: u64) -> Result<(), &'static str> {
        self.assets.get_mut(id).ok_or("unknown asset")?.mint(amount)
    }

    pub fn burn(&mut self, id: &AssetId, amount: u64) -> Result<(), &'static str> {
        self.assets.get_mut(id).ok_or("unknown asset")?.burn(amount)
    }

    pub fn increase_max_supply(&mut self, id: &AssetId, new_max_supply: u64) -> Result<(), &'static str> {
        self.assets.get_mut(id).ok_or("unknown asset")?.increase_max_supply(new_max_supply)
    }

    pub fn update_options(&mut self, id: &AssetId, mintable: bool, burnable: bool, issuer_fee_bps: u16, issuer_treasury: Option<crate::Address>) -> Result<(), &'static str> {
        self.assets.get_mut(id).ok_or("unknown asset")?.update_options(mintable, burnable, issuer_fee_bps, issuer_treasury)
    }

    pub fn iter(&self) -> impl Iterator<Item = &AssetDefinition> {
        self.assets.values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_transfer_fee_is_one_percent_of_nominal_token_amount_in_tnb() {
        assert_eq!(global_asset_transfer_fee_nox(100_000_000_000, 9), Ok(1_000_000_000));
        assert_eq!(transfer_fee_nox(100_000_000_000, 9, 500), Ok(5_000_000_000));
        assert_eq!(transfer_fee_nox(100_000_000_000, 9, 1_000), Ok(10_000_000_000));
        assert_eq!(global_asset_transfer_fee_nox(100, 0), Ok(1_000_000_000));
        assert_eq!(global_asset_transfer_fee_nox(1, 18), Ok(1));
        assert_eq!(global_asset_transfer_fee_nox(0, 9), Err("invalid asset transfer fee input"));
    }

    #[test]
    fn asset_id_is_deterministic_and_supply_is_bounded() {
        let issuer = [7u8; 32];
        let mut asset = AssetDefinition::new(
            issuer,
            1,
            "Project Coin".into(),
            "PRJ".into(),
            6,
            1_000,
            250,
        )
        .unwrap();
        assert_eq!(asset.id, AssetDefinition::derive_id(&issuer, 1));
        assert_eq!(asset.remaining_supply(), 750);
        assert!(asset.mint(750).is_ok());
        assert_eq!(asset.remaining_supply(), 0);
        assert_eq!(asset.mint(1), Err("asset max supply exceeded"));
    }

    #[test]
    fn registry_rejects_duplicate_ids() {
        let asset = AssetDefinition::new([1u8; 32], 4, "Coin".into(), "COIN".into(), 8, 10, 0).unwrap();
        let mut registry = AssetRegistry::default();
        assert!(registry.register(asset.clone()).is_ok());
        assert_eq!(registry.register(asset), Err("asset already registered"));
    }

    #[test]
    fn ledger_creates_mints_and_transfers_assets_without_unbounded_issuance() {
        let issuer = [1u8; 32];
        let receiver = [2u8; 32];
        let mut ledger = AssetLedger::default();
        let id = ledger.apply(AssetTransaction::Create {
            issuer,
            nonce: 9,
            name: "Project Coin".into(),
            symbol: "PRJ".into(),
            decimals: 6,
            max_supply: 1_000,
            initial_supply: 100,
        }).unwrap();
        assert_eq!(ledger.balance(&id, &issuer), 100);
        ledger.apply(AssetTransaction::Mint { asset_id: id, issuer, amount: 400 }).unwrap();
        assert_eq!(ledger.balance(&id, &issuer), 500);
        ledger.apply(AssetTransaction::Transfer { asset_id: id, from: issuer, to: receiver, amount: 125 }).unwrap();
        assert_eq!(ledger.balance(&id, &issuer), 375);
        assert_eq!(ledger.balance(&id, &receiver), 125);
        assert_eq!(ledger.apply(AssetTransaction::Mint { asset_id: id, issuer, amount: 501 }), Err("asset max supply exceeded"));
        assert_eq!(ledger.apply(AssetTransaction::Mint { asset_id: id, issuer: [3u8; 32], amount: 1 }), Err("mint issuer mismatch"));
    }

    #[test]
    fn asset_options_control_burn_and_issuer_can_raise_supply_cap() {
        let issuer = [1u8; 32];
        let mut ledger = AssetLedger::default();
        let id = ledger.apply(AssetTransaction::CreateWithOptions {
            issuer,
            nonce: 12,
            name: "Managed Coin".into(),
            symbol: "MNG".into(),
            decimals: 9,
            max_supply: 100,
            initial_supply: 50,
            mintable: true,
            burnable: true,
            issuer_fee_bps: 0,
            issuer_treasury: None,
            kind: AssetKind::Fungible,
        }).unwrap();
        assert_eq!(ledger.apply(AssetTransaction::Mint { asset_id: id, issuer, amount: 51 }), Err("asset max supply exceeded"));
        assert_eq!(ledger.registry.get(&id).unwrap().minted, 50);
        ledger.apply(AssetTransaction::Burn { asset_id: id, from: issuer, amount: 20 }).unwrap();
        assert_eq!(ledger.balance(&id, &issuer), 30);
        assert_eq!(ledger.registry.get(&id).unwrap().minted, 30);
        ledger.apply(AssetTransaction::IncreaseMaxSupply { asset_id: id, issuer, new_max_supply: 200 }).unwrap();
        ledger.apply(AssetTransaction::Mint { asset_id: id, issuer, amount: 150 }).unwrap();
        assert_eq!(ledger.registry.get(&id).unwrap().minted, 180);
        assert_eq!(ledger.registry.get(&id).unwrap().max_supply, 200);
    }

    #[test]
    fn disabled_mint_and_burn_are_enforced_by_asset_state() {
        let issuer = [1u8; 32];
        let mut ledger = AssetLedger::default();
        let id = ledger.apply(AssetTransaction::CreateWithOptions {
            issuer,
            nonce: 13,
            name: "Fixed Coin".into(),
            symbol: "FIX".into(),
            decimals: 0,
            max_supply: 10,
            initial_supply: 10,
            mintable: false,
            burnable: false,
            issuer_fee_bps: 0,
            issuer_treasury: None,
            kind: AssetKind::Fungible,
        }).unwrap();
        assert_eq!(ledger.apply(AssetTransaction::Mint { asset_id: id, issuer, amount: 1 }), Err("asset minting disabled"));
        assert_eq!(ledger.apply(AssetTransaction::IncreaseMaxSupply { asset_id: id, issuer, new_max_supply: 20 }), Err("asset minting disabled"));
        assert_eq!(ledger.apply(AssetTransaction::Burn { asset_id: id, from: issuer, amount: 1 }), Err("asset burning disabled"));
        assert_eq!(ledger.registry.get(&id).unwrap().minted, 10);
    }

    #[test]
    fn issuer_fee_policy_roundtrips_and_requires_a_treasury() {
        let issuer_secret = Scalar::from(17u64);
        let issuer = (issuer_secret * RISTRETTO_BASEPOINT_POINT).compress().to_bytes();
        let treasury = crate::Address {
            view: (Scalar::from(21u64) * RISTRETTO_BASEPOINT_POINT).compress().to_bytes(),
            spend: (Scalar::from(22u64) * RISTRETTO_BASEPOINT_POINT).compress().to_bytes(),
        };
        let transaction = AssetTransaction::CreateWithOptions {
            issuer,
            nonce: 22,
            name: "Taxed Coin".into(),
            symbol: "TAX".into(),
            decimals: 9,
            max_supply: 1_000_000,
            initial_supply: 1_000_000,
            mintable: true,
            burnable: true,
            issuer_fee_bps: 800,
            issuer_treasury: Some(treasury),
            kind: AssetKind::Fungible,
        };
        let encoded = transaction.encode().unwrap();
        assert_eq!(AssetTransaction::decode(&encoded), Ok(transaction.clone()));
        let signed = sign_issuer(&transaction, issuer_secret, &[6u8; 64]).unwrap();
        assert!(signed.verify().is_ok());
        let mut over_limit = transaction.clone();
        if let AssetTransaction::CreateWithOptions { issuer_fee_bps, .. } = &mut over_limit {
            *issuer_fee_bps = 10_001;
        }
        assert_eq!(over_limit.encode(), Err("invalid issuer fee policy"));
        assert_eq!(AssetDefinition::new_with_issuer_fee(issuer, 23, "Invalid".into(), "INV".into(), 9, 10, 10, true, true, 500, None, AssetKind::Fungible), Err("invalid issuer fee policy"));
    }

    #[test]
    fn asset_transactions_have_domain_separated_ids() {
        let tx = AssetTransaction::Mint { asset_id: [4u8; 32], issuer: [5u8; 32], amount: 7 };
        let encoded = tx.encode().unwrap();
        assert!(encoded.starts_with(b"TSC-1:asset-tx:v2"));
        let expected: [u8; 32] = Sha256::digest(encoded).into();
        assert_eq!(tx.txid().unwrap(), expected);
    }

    #[test]
    fn issuer_signature_is_required_and_binds_operation() {
        let secret = Scalar::from(11u64);
        let transaction = AssetTransaction::Create { issuer: (secret * RISTRETTO_BASEPOINT_POINT).compress().to_bytes(), nonce: 1, name: "Coin".into(), symbol: "COIN".into(), decimals: 8, max_supply: 100, initial_supply: 1 };
        let signed = sign_issuer(&transaction, secret, &[8u8; 64]).unwrap();
        assert!(signed.verify().is_ok());
        let mut changed = signed.clone();
        if let AssetTransaction::Create { ref mut max_supply, .. } = changed.transaction { *max_supply = 101; }
        assert_eq!(changed.verify(), Err("invalid issuer signature"));
    }
}
