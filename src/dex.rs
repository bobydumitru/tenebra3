use crate::assets::{AssetId, AssetLedger};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::CompressedRistretto, scalar::Scalar,
};
use sha2::{Digest, Sha256, Sha512};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read};
pub const MAX_DEX_OPERATIONS: usize = 256;
pub const MAX_DEX_OPERATION_BYTES: usize = 512;

pub const DEX_LEGACY_FEE_BPS: u128 = 30;
pub const DEX_FEE_BPS: u128 = 100;
pub const DEX_FEE_ACTIVATION_HEIGHT: u64 = crate::tsc1_fee::FEE_POLICY_ACTIVATION_HEIGHT;
pub const DEX_OWNER_FEE_SHARE_BPS: u128 = 10_000;
pub const BPS_DENOMINATOR: u128 = 10_000;
pub const DEX_OWNER_SPEND: [u8; 32] = [
    0x6c, 0xe1, 0x65, 0xc2, 0x8e, 0x9f, 0x9b, 0xac,
    0xff, 0x59, 0x27, 0x49, 0x0e, 0xbf, 0x5e, 0x32,
    0xa4, 0xee, 0xa3, 0x20, 0x72, 0xd2, 0x07, 0xee,
    0x95, 0xd8, 0x79, 0x09, 0xf4, 0xe7, 0xc8, 0x54,
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pool {
    pub id: [u8; 32],
    pub asset_a: AssetId,
    pub asset_b: AssetId,
    pub reserve_a: u128,
    pub reserve_b: u128,
    pub provider: [u8; 32],
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SwapQuote {
    pub input_asset: AssetId,
    pub output_asset: AssetId,
    pub input_amount: u128,
    pub output_amount: u128,
    pub fee_amount: u128,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DexOperation {
    CreatePool {
        asset_a: AssetId,
        asset_b: AssetId,
        amount_a: u128,
        amount_b: u128,
        provider: [u8; 32],
    },
    Swap {
        pool_id: [u8; 32],
        input_asset: AssetId,
        input_amount: u128,
        min_output: u128,
        trader: [u8; 32],
    },
    RemoveLiquidity {
        pool_id: [u8; 32],
        share_bps: u16,
        provider: [u8; 32],
    },
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedDexOperation {
    pub sequence: u64,
    pub operation: DexOperation,
    pub public: [u8; 32],
    pub signature: [u8; 64],
}

fn encode(op: &DexOperation) -> Vec<u8> {
    let mut b = Vec::from(&b"TSC-1:dex-op:v1"[..]);
    match op {
        DexOperation::CreatePool {
            asset_a,
            asset_b,
            amount_a,
            amount_b,
            provider,
        } => {
            b.push(0);
            b.extend_from_slice(asset_a);
            b.extend_from_slice(asset_b);
            b.extend_from_slice(&amount_a.to_le_bytes());
            b.extend_from_slice(&amount_b.to_le_bytes());
            b.extend_from_slice(provider)
        }
        DexOperation::Swap {
            pool_id,
            input_asset,
            input_amount,
            min_output,
            trader,
        } => {
            b.push(1);
            b.extend_from_slice(pool_id);
            b.extend_from_slice(input_asset);
            b.extend_from_slice(&input_amount.to_le_bytes());
            b.extend_from_slice(&min_output.to_le_bytes());
            b.extend_from_slice(trader)
        }
        DexOperation::RemoveLiquidity { pool_id, share_bps, provider } => {
            b.push(2);
            b.extend_from_slice(pool_id);
            b.extend_from_slice(&share_bps.to_le_bytes());
            b.extend_from_slice(provider);
        }
    }
    b
}
fn challenge(public: &[u8; 32], msg: &[u8], commitment: &[u8; 32]) -> Scalar {
    let mut h = Sha512::new();
    h.update(b"TENEBRA:dex-signature:v2");
    h.update(crate::tsc1_tx_v2::NETWORK_ID);
    h.update(public);
    h.update(msg);
    h.update(commitment);
    Scalar::from_hash(h)
}
pub fn sign(op: &DexOperation, secret: Scalar, nonce: &[u8; 64]) -> SignedDexOperation {
    sign_with_sequence(op, 0, secret, nonce)
}

pub fn sign_with_sequence(
    op: &DexOperation,
    sequence: u64,
    secret: Scalar,
    nonce: &[u8; 64],
) -> SignedDexOperation {
    let public = (secret * RISTRETTO_BASEPOINT_POINT).compress().to_bytes();
    let mut signed = SignedDexOperation {
        sequence,
        operation: op.clone(),
        public,
        signature: [0; 64],
    };
    let r = Scalar::from_bytes_mod_order_wide(nonce);
    let c = (r * RISTRETTO_BASEPOINT_POINT).compress().to_bytes();
    let response = r + challenge(&public, &signed.message(), &c) * secret;
    signed.signature[..32].copy_from_slice(&c);
    signed.signature[32..].copy_from_slice(&response.to_bytes());
    signed
}

impl SignedDexOperation {
    fn message(&self) -> Vec<u8> {
        let mut bytes = encode(&self.operation);
        bytes.extend_from_slice(&self.sequence.to_le_bytes());
        bytes
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = self.message();
        bytes.extend_from_slice(&self.public);
        bytes.extend_from_slice(&self.signature);
        bytes
    }
    pub fn id(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"TENEBRA:dex-id:v2");
        hash.update(crate::tsc1_tx_v2::NETWORK_ID);
        hash.update(self.public);
        hash.update(self.message());
        hash.finalize().into()
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        fn take<const N: usize>(c: &mut Cursor<&[u8]>) -> Result<[u8; N], &'static str> {
            let mut b = [0; N];
            c.read_exact(&mut b)
                .map_err(|_| "truncated dex operation")?;
            Ok(b)
        }
        if bytes.len() > MAX_DEX_OPERATION_BYTES {
            return Err("oversized dex operation");
        }
        let mut c = Cursor::new(bytes);
        if &take::<15>(&mut c)? != b"TSC-1:dex-op:v1" {
            return Err("wrong dex format");
        }
        let operation = match take::<1>(&mut c)?[0] {
            0 => DexOperation::CreatePool {
                asset_a: take(&mut c)?,
                asset_b: take(&mut c)?,
                amount_a: u128::from_le_bytes(take(&mut c)?),
                amount_b: u128::from_le_bytes(take(&mut c)?),
                provider: take(&mut c)?,
            },
            1 => DexOperation::Swap {
                pool_id: take(&mut c)?,
                input_asset: take(&mut c)?,
                input_amount: u128::from_le_bytes(take(&mut c)?),
                min_output: u128::from_le_bytes(take(&mut c)?),
                trader: take(&mut c)?,
            },
            2 => DexOperation::RemoveLiquidity {
                pool_id: take(&mut c)?,
                share_bps: u16::from_le_bytes(take(&mut c)?),
                provider: take(&mut c)?,
            },
            _ => return Err("unknown dex operation"),
        };
        let signed = Self {
            operation,
            sequence: u64::from_le_bytes(take(&mut c)?),
            public: take(&mut c)?,
            signature: take(&mut c)?,
        };
        if c.position() != bytes.len() as u64 {
            return Err("trailing dex bytes");
        }
        Ok(signed)
    }
    pub fn verify(&self) -> Result<(), &'static str> {
        let commitment: [u8; 32] = self.signature[..32].try_into().unwrap();
        let c = CompressedRistretto(commitment)
            .decompress()
            .ok_or("invalid dex commitment")?;
        let response = Scalar::from_canonical_bytes(self.signature[32..].try_into().unwrap())
            .into_option()
            .ok_or("invalid dex response")?;
        let public = CompressedRistretto(self.public)
            .decompress()
            .ok_or("invalid dex public key")?;
        if public == Default::default() || c == Default::default() {
            return Err("identity dex key or commitment");
        }
        if response * RISTRETTO_BASEPOINT_POINT
            != c + challenge(&self.public, &self.message(), &commitment) * public
        {
            return Err("invalid dex signature");
        }
        let owner = match &self.operation {
            DexOperation::CreatePool { provider, .. } => provider,
            DexOperation::Swap { trader, .. } => trader,
            DexOperation::RemoveLiquidity { provider, .. } => provider,
        };
        if owner != &self.public {
            return Err("dex owner key mismatch");
        }
        Ok(())
    }
}

impl Pool {
    pub fn new(a: AssetId, b: AssetId, aa: u128, bb: u128, provider: [u8; 32]) -> Result<Self, &'static str> {
        if a == b || aa == 0 || bb == 0 || aa > u64::MAX as u128 || bb > u64::MAX as u128 {
            return Err("invalid pool liquidity");
        }
        let (a, b, aa, bb) = if a < b {
            (a, b, aa, bb)
        } else {
            (b, a, bb, aa)
        };
        let mut hash = Sha256::new();
        hash.update(b"TENEBRA:dex-pool:v1");
        hash.update(a);
        hash.update(b);
        Ok(Self {
            id: hash.finalize().into(),
            asset_a: a,
            asset_b: b,
            reserve_a: aa,
            reserve_b: bb,
            provider,
        })
    }
    pub fn quote(&self, input: AssetId, amount: u128) -> Result<SwapQuote, &'static str> {
        self.quote_with_fee_bps(input, amount, DEX_FEE_BPS)
    }

    fn quote_with_fee_bps(
        &self,
        input: AssetId,
        amount: u128,
        fee_bps: u128,
    ) -> Result<SwapQuote, &'static str> {
        let (ri, ro, out) = if input == self.asset_a {
            (self.reserve_a, self.reserve_b, self.asset_b)
        } else if input == self.asset_b {
            (self.reserve_b, self.reserve_a, self.asset_a)
        } else {
            return Err("asset not in pool");
        };
        if amount == 0 || amount > u64::MAX as u128 {
            return Err("invalid swap amount");
        }
        let fee = amount.checked_mul(fee_bps).ok_or("swap overflow")? / BPS_DENOMINATOR;
        let effective = amount - fee;
        let denominator = ri.checked_add(effective).ok_or("swap overflow")?;
        let output = ro.checked_mul(effective).ok_or("swap overflow")? / denominator;
        if output == 0 || output >= ro {
            return Err("insufficient liquidity");
        }
        Ok(SwapQuote {
            input_asset: input,
            output_asset: out,
            input_amount: amount,
            output_amount: output,
            fee_amount: fee,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DexState {
    pub pools: Vec<Pool>,
    sequences: BTreeMap<[u8; 32], u64>,
    applied_operations: BTreeSet<[u8; 32]>,
}
impl DexState {
    pub fn next_sequence(&self, public: &[u8; 32]) -> u64 {
        self.sequences.get(public).copied().unwrap_or(0)
    }
    pub fn has_applied_operation(&self, id: &[u8; 32]) -> bool {
        self.applied_operations.contains(id)
    }
    pub fn apply(
        &mut self,
        signed: &SignedDexOperation,
        ledger: &mut AssetLedger,
    ) -> Result<(), &'static str> {
        self.apply_at_height(signed, ledger, 0)
    }

    pub fn apply_at_height(
        &mut self,
        signed: &SignedDexOperation,
        ledger: &mut AssetLedger,
        height: u64,
    ) -> Result<(), &'static str> {
        signed.verify()?;
        let id = signed.id();
        if self.applied_operations.contains(&id) {
            return Err("dex operation already applied");
        }
        if signed.sequence != self.next_sequence(&signed.public) {
            return Err("invalid dex sequence");
        }
        let next = signed
            .sequence
            .checked_add(1)
            .ok_or("dex sequence overflow")?;
        let mut staged_ledger = ledger.clone();
        let mut staged = self.clone();
        let fee_bps = if crate::network::IS_MAINNET && height >= DEX_FEE_ACTIVATION_HEIGHT {
            DEX_FEE_BPS
        } else {
            DEX_LEGACY_FEE_BPS
        };
        staged.apply_operation(&signed.operation, &mut staged_ledger, fee_bps)?;
        staged.sequences.insert(signed.public, next);
        staged.applied_operations.insert(id);
        *ledger = staged_ledger;
        *self = staged;
        Ok(())
    }
    fn apply_operation(
        &mut self,
        operation: &DexOperation,
        ledger: &mut AssetLedger,
        fee_bps: u128,
    ) -> Result<(), &'static str> {
        match operation {
            DexOperation::CreatePool {
                asset_a,
                asset_b,
                amount_a,
                amount_b,
                provider,
            } => {
                if (*asset_a != crate::assets::TNB_ASSET_ID && ledger.registry.get(asset_a).is_none())
                    || (*asset_b != crate::assets::TNB_ASSET_ID && ledger.registry.get(asset_b).is_none())
                {
                    return Err("unfunded or unknown pool asset");
                }
                let pool = Pool::new(*asset_a, *asset_b, *amount_a, *amount_b, *provider)?;
                if self.pools.iter().any(|p| p.id == pool.id) {
                    return Err("pool already exists");
                }
                ledger.transfer(*asset_a, provider, &pool.id, *amount_a)?;
                ledger.transfer(*asset_b, provider, &pool.id, *amount_b)?;
                self.pools.push(pool);
            }
            DexOperation::Swap {
                pool_id,
                input_asset,
                input_amount,
                min_output,
                trader,
            } => {
                let pool = self
                    .pools
                    .iter_mut()
                    .find(|p| p.id == *pool_id)
                    .ok_or("unknown pool")?;
                let q = pool.quote_with_fee_bps(*input_asset, *input_amount, fee_bps)?;
                if q.output_amount < *min_output {
                    return Err("slippage exceeded");
                }
                let owner_fee = q
                    .fee_amount
                    .checked_mul(DEX_OWNER_FEE_SHARE_BPS)
                    .ok_or("fee overflow")?
                    / BPS_DENOMINATOR;
                ledger.transfer(*input_asset, trader, &pool.id, *input_amount)?;
                if owner_fee > 0 {
                    ledger.transfer(*input_asset, &pool.id, &DEX_OWNER_SPEND, owner_fee)?;
                }
                ledger.transfer(q.output_asset, &pool.id, trader, q.output_amount)?;
                if q.input_asset == pool.asset_a {
                    pool.reserve_a = pool
                        .reserve_a
                        .checked_add(q.input_amount - owner_fee)
                        .ok_or("pool overflow")?;
                    pool.reserve_b -= q.output_amount;
                } else {
                    pool.reserve_b = pool
                        .reserve_b
                        .checked_add(q.input_amount - owner_fee)
                        .ok_or("pool overflow")?;
                    pool.reserve_a -= q.output_amount;
                }
            }
            DexOperation::RemoveLiquidity { pool_id, share_bps, provider } => {
                if *share_bps == 0 || *share_bps > 10_000 {
                    return Err("invalid liquidity share");
                }
                let index = self.pools.iter().position(|p| p.id == *pool_id).ok_or("unknown pool")?;
                let pool = &mut self.pools[index];
                if pool.provider != *provider {
                    return Err("liquidity provider mismatch");
                }
                let amount_a = pool.reserve_a.checked_mul(*share_bps as u128).ok_or("liquidity overflow")? / 10_000;
                let amount_b = pool.reserve_b.checked_mul(*share_bps as u128).ok_or("liquidity overflow")? / 10_000;
                if amount_a == 0 || amount_b == 0 {
                    return Err("liquidity share is too small");
                }
                ledger.transfer(pool.asset_a, &pool.id, provider, amount_a)?;
                ledger.transfer(pool.asset_b, &pool.id, provider, amount_b)?;
                pool.reserve_a -= amount_a;
                pool.reserve_b -= amount_b;
                if *share_bps == 10_000 {
                    self.pools.remove(index);
                }
            }
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::assets::TNB_ASSET_ID;
    #[test]
    fn signature_binds_dex_operation() {
        let s = Scalar::from(11u64);
        let p = (s * RISTRETTO_BASEPOINT_POINT).compress().to_bytes();
        let op = DexOperation::CreatePool {
            asset_a: TNB_ASSET_ID,
            asset_b: [7; 32],
            amount_a: 10,
            amount_b: 10,
            provider: p,
        };
        assert!(sign(&op, s, &[1; 64]).verify().is_ok())
    }

    #[test]
    fn dex_charges_one_percent_and_routes_all_of_it_to_treasury() {
        let treasury = crate::Address::parse(include_str!("../config/treasury-address.txt")).unwrap();
        assert_eq!(DEX_OWNER_SPEND, treasury.spend);
        let pool = Pool {
            id: [3; 32],
            asset_a: TNB_ASSET_ID,
            asset_b: [7; 32],
            reserve_a: 1_000_000,
            reserve_b: 1_000_000,
            provider: [9; 32],
        };
        assert_eq!(
            pool.quote_with_fee_bps(TNB_ASSET_ID, 10_000, DEX_LEGACY_FEE_BPS)
                .unwrap()
                .fee_amount,
            30
        );
        let quote = pool.quote(TNB_ASSET_ID, 10_000).unwrap();
        assert_eq!(quote.fee_amount, 100);
        assert_eq!(
            quote.fee_amount * DEX_OWNER_FEE_SHARE_BPS / BPS_DENOMINATOR,
            quote.fee_amount
        );
    }

    #[test]
    fn identical_dex_operations_are_not_reapplied() {
        let issuer = [11u8; 32];
        let provider_secret = Scalar::from(13u64);
        let provider = (provider_secret * RISTRETTO_BASEPOINT_POINT).compress().to_bytes();
        let mut ledger = AssetLedger::default();
        let asset_a = ledger
            .apply(crate::assets::AssetTransaction::Create {
                issuer,
                nonce: 1,
                name: "Alpha".into(),
                symbol: "ALP".into(),
                decimals: 6,
                max_supply: 1_000,
                initial_supply: 100,
            })
            .unwrap();
        let asset_b = ledger
            .apply(crate::assets::AssetTransaction::Create {
                issuer,
                nonce: 2,
                name: "Beta".into(),
                symbol: "BET".into(),
                decimals: 6,
                max_supply: 1_000,
                initial_supply: 100,
            })
            .unwrap();
        ledger
            .apply(crate::assets::AssetTransaction::Transfer {
                asset_id: asset_a,
                from: issuer,
                to: provider,
                amount: 100,
            })
            .unwrap();
        ledger
            .apply(crate::assets::AssetTransaction::Transfer {
                asset_id: asset_b,
                from: issuer,
                to: provider,
                amount: 100,
            })
            .unwrap();
        let op = DexOperation::CreatePool {
            asset_a,
            asset_b,
            amount_a: 50,
            amount_b: 50,
            provider,
        };
        let signed = sign(&op, provider_secret, &[2; 64]);
        let mut state = DexState::default();
        assert!(state.apply(&signed, &mut ledger).is_ok());
        assert_eq!(state.apply(&signed, &mut ledger), Err("dex operation already applied"));
    }
}
