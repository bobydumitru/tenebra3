//! TSC-1 confidential amounts, range proofs, and the mainnet TNB transfer-fee proof.
//! Every output needs a valid range proof AND a balanced transaction.

use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
pub type AssetId = [u8; 32];
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use std::sync::LazyLock;

pub const TNB_ASSET_ID: [u8; 32] = [0; 32];
const PROOF_BITS: usize = 64;
const TRANSFER_FEE_PROOF_BITS: usize = 8;
const TRANSFER_FEE_BPS: u64 = 100;
const TRANSFER_FEE_PROOF_MAGIC: &[u8; 8] = b"TSC1FEE2";
// Public deterministic generators are immutable. Each proof still gets a fresh transcript.
static RANGE_GENERATORS: LazyLock<BulletproofGens> =
    LazyLock::new(|| BulletproofGens::new(PROOF_BITS, 1));
static VALUE_GENERATORS: LazyLock<PedersenGens> = LazyLock::new(PedersenGens::default);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvenAmount {
    pub asset_id: AssetId,
    pub commitment: [u8; 32],
    pub range_proof: Vec<u8>,
}

fn transcript(asset_id: &[u8; 32]) -> Transcript {
    let mut transcript = Transcript::new(b"TSC-1:amount-range:v1");
    transcript.append_message(b"asset-id", asset_id);
    transcript
}

fn transfer_fee_transcript(asset_id: &[u8; 32], fee_nox: u64, side: u8) -> Transcript {
    let mut transcript = Transcript::new(b"TSC-1:transfer-fee-proof:v1");
    transcript.append_message(b"asset-id", asset_id);
    transcript.append_message(b"fee-nox", &fee_nox.to_le_bytes());
    transcript.append_message(b"side", &[side]);
    transcript
}

fn decode_fee_proof(encoded: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
    if encoded.len() < TRANSFER_FEE_PROOF_MAGIC.len() + 6
        || &encoded[..TRANSFER_FEE_PROOF_MAGIC.len()] != TRANSFER_FEE_PROOF_MAGIC
    {
        return None;
    }
    let mut cursor = TRANSFER_FEE_PROOF_MAGIC.len();
    let primary_len = u16::from_le_bytes(encoded.get(cursor..cursor + 2)?.try_into().ok()?) as usize;
    cursor += 2;
    let primary_end = cursor.checked_add(primary_len)?;
    let primary = encoded.get(cursor..primary_end)?;
    cursor = primary_end;
    let lower_len = u16::from_le_bytes(encoded.get(cursor..cursor + 2)?.try_into().ok()?) as usize;
    cursor += 2;
    let lower_end = cursor.checked_add(lower_len)?;
    let lower = encoded.get(cursor..lower_end)?;
    cursor = lower_end;
    let upper_len = u16::from_le_bytes(encoded.get(cursor..cursor + 2)?.try_into().ok()?) as usize;
    cursor += 2;
    let upper_end = cursor.checked_add(upper_len)?;
    if upper_end != encoded.len() {
        return None;
    }
    Some((primary, lower, encoded.get(cursor..upper_end)?))
}

pub fn attach_tnb_transfer_fee_proof(
    output: &mut ProvenAmount,
    amount_nox: u64,
    fee_nox: u64,
    blinding: &Scalar,
) -> Result<(), String> {
    let required_fee = amount_nox.div_ceil(TRANSFER_FEE_BPS).max(1);
    if fee_nox != required_fee {
        return Err("TNB transfer fee must be exactly 1 percent".into());
    }
    let offset = (fee_nox as u128 - 1) * TRANSFER_FEE_BPS as u128 + 1;
    if offset > u64::MAX as u128 {
        return Err("TNB transfer fee proof amount overflow".into());
    }
    let remainder = amount_nox
        .checked_sub(offset as u64)
        .filter(|value| *value < TRANSFER_FEE_BPS)
        .ok_or_else(|| "TNB transfer fee proof amount is out of range".to_string())?;
    let commitment = CompressedRistretto(output.commitment)
        .decompress()
        .ok_or_else(|| "invalid TNB transfer output commitment".to_string())?
        - VALUE_GENERATORS.B * Scalar::from(offset as u64);
    let complement = TRANSFER_FEE_BPS - 1 - remainder;
    let mut lower_transcript = transfer_fee_transcript(&output.asset_id, fee_nox, 0);
    let (lower_proof, proven_commitment) = RangeProof::prove_single(
        &RANGE_GENERATORS,
        &VALUE_GENERATORS,
        &mut lower_transcript,
        remainder,
        blinding,
        TRANSFER_FEE_PROOF_BITS,
    )
    .map_err(|error| format!("TNB transfer fee lower-bound proof creation failed: {error}"))?;
    if proven_commitment != commitment.compress() {
        return Err("TNB transfer fee lower-bound commitment mismatch".into());
    }
    let upper_commitment = VALUE_GENERATORS.B * Scalar::from(TRANSFER_FEE_BPS - 1) - commitment;
    let mut upper_transcript = transfer_fee_transcript(&output.asset_id, fee_nox, 1);
    let (upper_proof, proven_upper_commitment) = RangeProof::prove_single(
        &RANGE_GENERATORS,
        &VALUE_GENERATORS,
        &mut upper_transcript,
        complement,
        &-*blinding,
        TRANSFER_FEE_PROOF_BITS,
    )
    .map_err(|error| format!("TNB transfer fee upper-bound proof creation failed: {error}"))?;
    if proven_upper_commitment != upper_commitment.compress() {
        return Err("TNB transfer fee upper-bound commitment mismatch".into());
    }
    let primary = std::mem::take(&mut output.range_proof);
    let primary_len = u16::try_from(primary.len())
        .map_err(|_| "TNB transfer range proof too large".to_string())?;
    let lower_proof = lower_proof.to_bytes();
    let lower_len = u16::try_from(lower_proof.len())
        .map_err(|_| "TNB fee lower-bound proof too large".to_string())?;
    let upper_proof = upper_proof.to_bytes();
    let upper_len = u16::try_from(upper_proof.len())
        .map_err(|_| "TNB fee upper-bound proof too large".to_string())?;
    let mut encoded = Vec::with_capacity(14 + primary.len() + lower_proof.len() + upper_proof.len());
    encoded.extend_from_slice(TRANSFER_FEE_PROOF_MAGIC);
    encoded.extend_from_slice(&primary_len.to_le_bytes());
    encoded.extend_from_slice(&primary);
    encoded.extend_from_slice(&lower_len.to_le_bytes());
    encoded.extend_from_slice(&lower_proof);
    encoded.extend_from_slice(&upper_len.to_le_bytes());
    encoded.extend_from_slice(&upper_proof);
    output.range_proof = encoded;
    Ok(())
}

pub fn verify_tnb_transfer_fee_proof(output: &ProvenAmount, fee_nox: u64) -> bool {
    let Some((_, lower_proof, upper_proof)) = decode_fee_proof(&output.range_proof) else {
        return false;
    };
    let Some(offset) = (fee_nox as u128)
        .checked_sub(1)
        .and_then(|value| value.checked_mul(TRANSFER_FEE_BPS as u128))
        .and_then(|value| value.checked_add(1))
        .filter(|value| *value <= u64::MAX as u128)
    else {
        return false;
    };
    let Some(commitment) = CompressedRistretto(output.commitment).decompress() else {
        return false;
    };
    let lower_commitment = commitment - VALUE_GENERATORS.B * Scalar::from(offset as u64);
    let upper_commitment = VALUE_GENERATORS.B * Scalar::from(TRANSFER_FEE_BPS - 1) - lower_commitment;
    let Ok(lower_proof) = RangeProof::from_bytes(lower_proof) else {
        return false;
    };
    let Ok(upper_proof) = RangeProof::from_bytes(upper_proof) else {
        return false;
    };
    lower_proof
        .verify_single(
            &RANGE_GENERATORS,
            &VALUE_GENERATORS,
            &mut transfer_fee_transcript(&output.asset_id, fee_nox, 0),
            &lower_commitment.compress(),
            TRANSFER_FEE_PROOF_BITS,
        )
        .is_ok()
        && upper_proof
            .verify_single(
                &RANGE_GENERATORS,
                &VALUE_GENERATORS,
                &mut transfer_fee_transcript(&output.asset_id, fee_nox, 1),
                &upper_commitment.compress(),
                TRANSFER_FEE_PROOF_BITS,
            )
            .is_ok()
}

pub fn random_blinding() -> Result<Scalar, getrandom::Error> {
    let mut wide = [0u8; 64];
    getrandom::getrandom(&mut wide)?;
    Ok(Scalar::from_bytes_mod_order_wide(&wide))
}

pub fn prove_amount(
    amount: u64,
    blinding: &Scalar,
    asset_id: &[u8; 32],
) -> Result<ProvenAmount, String> {
    let mut transcript = transcript(asset_id);
    let (proof, commitment) = RangeProof::prove_single(
        &RANGE_GENERATORS,
        &VALUE_GENERATORS,
        &mut transcript,
        amount,
        blinding,
        PROOF_BITS,
    )
    .map_err(|error| format!("range proof creation failed: {error}"))?;
    Ok(ProvenAmount {
        asset_id: *asset_id,
        commitment: commitment.to_bytes(),
        range_proof: proof.to_bytes(),
    })
}

pub fn verify_amount(output: &ProvenAmount, asset_id: &[u8; 32]) -> bool {
    if &output.asset_id != asset_id {
        return false;
    }
    let primary = decode_fee_proof(&output.range_proof)
        .map(|(primary, _, _)| primary)
        .unwrap_or(&output.range_proof);
    let Ok(proof) = RangeProof::from_bytes(primary) else {
        return false;
    };
    proof
        .verify_single(
            &RANGE_GENERATORS,
            &VALUE_GENERATORS,
            &mut transcript(asset_id),
            &CompressedRistretto(output.commitment),
            PROOF_BITS,
        )
        .is_ok()
}

/// Verify amount conservation. Only call after verifying every output proof.
/// Inputs and outputs must all belong to the same asset.
pub fn balances(inputs: &[[u8; 32]], outputs: &[[u8; 32]], fee: u64) -> bool {
    let mut input_sum = RistrettoPoint::default();
    let mut output_sum = VALUE_GENERATORS.B * Scalar::from(fee);
    for encoded in inputs {
        let Some(point) = CompressedRistretto(*encoded).decompress() else {
            return false;
        };
        input_sum += point;
    }
    for encoded in outputs {
        let Some(point) = CompressedRistretto(*encoded).decompress() else {
            return false;
        };
        output_sum += point;
    }
    input_sum == output_sum
}

/// Conserves confidential commitments independently for every asset.
/// Fees are charged only in the native TNB asset.
pub fn balances_by_asset(
    inputs: &[(AssetId, [u8; 32])],
    outputs: &[(AssetId, [u8; 32])],
    fee_asset: &AssetId,
    fee: u64,
) -> bool {
    if fee_asset != &TNB_ASSET_ID {
        return false;
    }
    if inputs
        .iter()
        .chain(outputs.iter())
        .all(|(asset, _)| asset == &TNB_ASSET_ID)
    {
        let input_commitments: Vec<_> = inputs.iter().map(|(_, commitment)| *commitment).collect();
        let output_commitments: Vec<_> =
            outputs.iter().map(|(_, commitment)| *commitment).collect();
        return balances(&input_commitments, &output_commitments, fee);
    }
    let mut asset_ids = vec![*fee_asset];
    for (asset, _) in inputs.iter().chain(outputs.iter()) {
        if !asset_ids.contains(asset) {
            asset_ids.push(*asset);
        }
    }
    for asset_id in asset_ids {
        let mut input_sum = RistrettoPoint::default();
        let mut output_sum = if &asset_id == fee_asset {
            VALUE_GENERATORS.B * Scalar::from(fee)
        } else {
            RistrettoPoint::default()
        };
        for (asset, encoded) in inputs {
            if *asset != asset_id {
                continue;
            }
            let Some(point) = CompressedRistretto(*encoded).decompress() else {
                return false;
            };
            input_sum += point;
        }
        for (asset, encoded) in outputs {
            if *asset != asset_id {
                continue;
            }
            let Some(point) = CompressedRistretto(*encoded).decompress() else {
                return false;
            };
            output_sum += point;
        }
        if input_sum != output_sum {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asset_balances_require_native_fees_and_separate_conservation() {
        let commit = |value| {
            VALUE_GENERATORS
                .commit(Scalar::from(value), Scalar::ONE)
                .compress()
                .to_bytes()
        };
        let token = [7; 32];
        let inputs = [(TNB_ASSET_ID, commit(10u64)), (token, commit(100u64))];
        let outputs = [(TNB_ASSET_ID, commit(9u64)), (token, commit(100u64))];
        assert!(balances_by_asset(&inputs, &outputs, &TNB_ASSET_ID, 1));
        assert!(!balances_by_asset(
            &inputs,
            &[(TNB_ASSET_ID, commit(8u64)), (token, commit(101u64))],
            &TNB_ASSET_ID,
            1
        ));
        assert!(!balances_by_asset(
            &inputs[1..],
            &outputs[1..],
            &TNB_ASSET_ID,
            1
        ));
        for fee in [0, 1, 2] {
            assert_eq!(
                balances_by_asset(&inputs[..1], &outputs[..1], &TNB_ASSET_ID, fee),
                balances(&[inputs[0].1], &[outputs[0].1], fee)
            );
        }
        assert!(!balances_by_asset(
            &[(TNB_ASSET_ID, [255; 32])],
            &outputs[..1],
            &TNB_ASSET_ID,
            1
        ));
    }

    #[test]
    fn valid_proof_passes_and_wrong_asset_fails() {
        let proof = prove_amount(42, &random_blinding().unwrap(), &TNB_ASSET_ID).unwrap();
        assert!(verify_amount(&proof, &TNB_ASSET_ID));
        assert!(!verify_amount(&proof, &[1; 32]));
    }

    #[test]
    fn confidential_tnb_fee_proves_exact_rounded_up_one_percent() {
        let blind = random_blinding().unwrap();
        let mut output = prove_amount(1_234, &blind, &TNB_ASSET_ID).unwrap();
        attach_tnb_transfer_fee_proof(&mut output, 1_234, 13, &blind).unwrap();
        assert!(verify_amount(&output, &TNB_ASSET_ID));
        assert!(verify_tnb_transfer_fee_proof(&output, 13));
        assert!(!verify_tnb_transfer_fee_proof(&output, 12));
        assert!(output.range_proof.len() <= 2_048);

        let mut corrupted = output.clone();
        *corrupted.range_proof.last_mut().unwrap() ^= 1;
        assert!(!verify_tnb_transfer_fee_proof(&corrupted, 13));

    }

    #[test]
    fn changed_commitment_fails() {
        let blind = random_blinding().unwrap();
        let mut proof = prove_amount(42, &blind, &TNB_ASSET_ID).unwrap();
        proof.commitment = prove_amount(43, &blind, &TNB_ASSET_ID).unwrap().commitment;
        assert!(!verify_amount(&proof, &TNB_ASSET_ID));
    }

    #[test]
    fn balanced_transaction_passes_wrong_fee_fails() {
        let input_blind = random_blinding().unwrap();
        let output_blind = random_blinding().unwrap();
        let change_blind = input_blind - output_blind;
        let input = prove_amount(100, &input_blind, &TNB_ASSET_ID).unwrap();
        let output = prove_amount(60, &output_blind, &TNB_ASSET_ID).unwrap();
        let change = prove_amount(39, &change_blind, &TNB_ASSET_ID).unwrap();
        assert!(verify_amount(&output, &TNB_ASSET_ID));
        assert!(verify_amount(&change, &TNB_ASSET_ID));
        assert!(balances(
            &[input.commitment],
            &[output.commitment, change.commitment],
            1
        ));
        assert!(!balances(
            &[input.commitment],
            &[output.commitment, change.commitment],
            2
        ));
    }

    #[test]
    fn balances_by_asset_rejects_cross_asset_value_creation() {
        let token = [9u8; 32];
        let input_blind = random_blinding().unwrap();
        let output_blind = random_blinding().unwrap();
        let input = prove_amount(100, &input_blind, &TNB_ASSET_ID).unwrap();
        let output = prove_amount(100, &output_blind, &token).unwrap();
        assert!(!balances_by_asset(
            &[(TNB_ASSET_ID, input.commitment)],
            &[(token, output.commitment)],
            &TNB_ASSET_ID,
            0,
        ));
    }
}
