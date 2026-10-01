//! Fail-closed TNB transaction validator prototype.
//! Public validity rules are checked, but spending remains disabled until a
//! reviewed private spend-authorization scheme is implemented.

#[path = "../tsc1_private_amounts.rs"]
mod private_amounts;

use std::collections::{HashMap, HashSet};

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use private_amounts::{ProvenAmount, TNB_ASSET_ID, balances, verify_amount};
use tenebra::OneTimeOutput;

const MAX_INPUTS: usize = 16;
const MAX_OUTPUTS: usize = 16;
const MAX_PROOF_BYTES: usize = 8192;

#[derive(Clone)]
struct TxOutput {
    destination: OneTimeOutput,
    amount: ProvenAmount,
    asset_id: [u8; 32],
}

struct Transaction {
    inputs: Vec<[u8; 32]>,
    outputs: Vec<TxOutput>,
    fee_nox: u64,
}

struct StoredOutput {
    commitment: [u8; 32],
    asset_id: [u8; 32],
}

#[derive(Default)]
struct LedgerView {
    unspent: HashMap<[u8; 32], StoredOutput>,
    spent: HashSet<[u8; 32]>,
    seen_destinations: HashSet<[u8; 32]>,
}

fn valid_point(encoded: [u8; 32]) -> bool {
    matches!(CompressedRistretto(encoded).decompress(), Some(point) if point != RistrettoPoint::default())
}

impl LedgerView {
    /// Checks public rules only. This does not authorize or apply a spend.
    fn validate_public_rules(&self, tx: &Transaction) -> Result<(), &'static str> {
        if tx.inputs.is_empty() || tx.inputs.len() > MAX_INPUTS {
            return Err("invalid input count");
        }
        if tx.outputs.is_empty() || tx.outputs.len() > MAX_OUTPUTS {
            return Err("invalid output count");
        }
        if tx.fee_nox == 0 || tx.fee_nox > tenebra::MAX_SUPPLY_NOX {
            return Err("invalid fee");
        }

        let mut input_ids = HashSet::new();
        let mut input_commitments = Vec::with_capacity(tx.inputs.len());
        for id in &tx.inputs {
            if !input_ids.insert(*id) {
                return Err("duplicate input");
            }
            if self.spent.contains(id) {
                return Err("already spent input");
            }
            let known = self.unspent.get(id).ok_or("unknown input")?;
            if known.asset_id != TNB_ASSET_ID || !valid_point(known.commitment) {
                return Err("invalid TNB input");
            }
            input_commitments.push(known.commitment);
        }

        let mut output_destinations = HashSet::new();
        let mut output_commitments = Vec::with_capacity(tx.outputs.len());
        for output in &tx.outputs {
            if output.asset_id != TNB_ASSET_ID {
                return Err("wrong asset");
            }
            if !valid_point(output.destination.ephemeral)
                || !valid_point(output.destination.destination)
            {
                return Err("invalid one-time destination");
            }
            if self
                .seen_destinations
                .contains(&output.destination.destination)
                || !output_destinations.insert(output.destination.destination)
            {
                return Err("reused one-time destination");
            }
            if output.amount.range_proof.is_empty()
                || output.amount.range_proof.len() > MAX_PROOF_BYTES
                || !verify_amount(&output.amount, &TNB_ASSET_ID)
            {
                return Err("invalid amount range proof");
            }
            output_commitments.push(output.amount.commitment);
        }

        if !balances(&input_commitments, &output_commitments, tx.fee_nox) {
            return Err("unbalanced TNB transaction");
        }
        Ok(())
    }

    /// No transaction can enter consensus without cryptographic spend authorization.
    fn validate_for_consensus(&self, tx: &Transaction) -> Result<(), &'static str> {
        self.validate_public_rules(tx)?;
        Err("private spend authorization is not implemented")
    }
}

fn main() {
    println!("TSC-1 TNB transaction validator prototype");
    println!(
        "Range proofs, amount balance, fees, input references and duplicate spends are checked."
    );
    println!("All real transfers remain disabled until private spend authorization is reviewed.");
    // Keep the production entry point explicitly fail-closed.
    let ledger = LedgerView::default();
    let tx = Transaction {
        inputs: vec![],
        outputs: vec![],
        fee_nox: 0,
    };
    assert!(ledger.validate_for_consensus(&tx).is_err());
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::scalar::Scalar;
    use private_amounts::{prove_amount, random_blinding};
    use tenebra::{WalletSecrets, create_output};

    fn fixture() -> (LedgerView, Transaction) {
        let input_blind = random_blinding().unwrap();
        let output_blind = random_blinding().unwrap();
        let change_blind = input_blind - output_blind;
        let input = prove_amount(100, &input_blind, &TNB_ASSET_ID).unwrap();
        let payment = prove_amount(60, &output_blind, &TNB_ASSET_ID).unwrap();
        let change = prove_amount(39, &change_blind, &TNB_ASSET_ID).unwrap();
        let recipient = WalletSecrets::generate().unwrap();
        let id = [7u8; 32];
        let mut ledger = LedgerView::default();
        ledger.unspent.insert(
            id,
            StoredOutput {
                commitment: input.commitment,
                asset_id: TNB_ASSET_ID,
            },
        );
        let tx = Transaction {
            inputs: vec![id],
            outputs: vec![
                TxOutput {
                    destination: create_output(&recipient.address(), 0).unwrap(),
                    amount: payment,
                    asset_id: TNB_ASSET_ID,
                },
                TxOutput {
                    destination: create_output(&recipient.address(), 1).unwrap(),
                    amount: change,
                    asset_id: TNB_ASSET_ID,
                },
            ],
            fee_nox: 1,
        };
        (ledger, tx)
    }

    #[test]
    fn balanced_private_transfer_passes_public_rules_but_not_consensus() {
        let (ledger, tx) = fixture();
        assert_eq!(ledger.validate_public_rules(&tx), Ok(()));
        assert_eq!(
            ledger.validate_for_consensus(&tx),
            Err("private spend authorization is not implemented")
        );
    }

    #[test]
    fn wrong_fee_and_tampered_proof_are_rejected() {
        let (ledger, mut tx) = fixture();
        tx.fee_nox = 2;
        assert_eq!(
            ledger.validate_public_rules(&tx),
            Err("unbalanced TNB transaction")
        );
        tx.fee_nox = 1;
        tx.outputs[0].amount.range_proof[0] ^= 1;
        assert_eq!(
            ledger.validate_public_rules(&tx),
            Err("invalid amount range proof")
        );
    }

    #[test]
    fn duplicate_spent_and_unknown_inputs_are_rejected() {
        let (mut ledger, mut tx) = fixture();
        tx.inputs.push(tx.inputs[0]);
        assert_eq!(ledger.validate_public_rules(&tx), Err("duplicate input"));
        tx.inputs.pop();
        ledger.spent.insert(tx.inputs[0]);
        assert_eq!(
            ledger.validate_public_rules(&tx),
            Err("already spent input")
        );
        ledger.spent.clear();
        tx.inputs[0] = [8u8; 32];
        assert_eq!(ledger.validate_public_rules(&tx), Err("unknown input"));
    }

    #[test]
    fn wrong_asset_and_reused_destination_are_rejected() {
        let (mut ledger, mut tx) = fixture();
        tx.outputs[0].asset_id = [1u8; 32];
        assert_eq!(ledger.validate_public_rules(&tx), Err("wrong asset"));
        tx.outputs[0].asset_id = TNB_ASSET_ID;
        ledger
            .seen_destinations
            .insert(tx.outputs[0].destination.destination);
        assert_eq!(
            ledger.validate_public_rules(&tx),
            Err("reused one-time destination")
        );
    }

    #[test]
    fn empty_and_zero_fee_transactions_are_rejected() {
        let ledger = LedgerView::default();
        let empty = Transaction {
            inputs: vec![],
            outputs: vec![],
            fee_nox: 0,
        };
        assert_eq!(
            ledger.validate_public_rules(&empty),
            Err("invalid input count")
        );
        let (ledger, mut tx) = fixture();
        tx.fee_nox = 0;
        assert_eq!(ledger.validate_public_rules(&tx), Err("invalid fee"));
        let _ = Scalar::ZERO;
    }
}
