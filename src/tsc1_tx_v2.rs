//! Candidate private transaction envelope. Consensus spending stays disabled.

use crate::MAX_SUPPLY_NOX;
use crate::assets::TNB_ASSET_ID;
use crate::tsc1_chain_v2::{Chain, Hash};
use crate::tsc1_funded_output::FundedOutput;
use crate::tsc1_private_amounts::balances_by_asset;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rayon::prelude::*;
use sha2::{Digest, Sha256, Sha512};
use std::collections::HashSet;
use std::io::{Cursor, Read};

/// Isolated v3f devnet transaction domain; not a mainnet network ID.
#[cfg(not(feature = "mainnet-candidate"))]
pub const NETWORK_ID: Hash = [
    0x1f, 0xd8, 0x3b, 0xc5, 0xbe, 0x9d, 0x95, 0x28, 0xbd, 0x98, 0xd3, 0x1e, 0xb6, 0xfa, 0xb0, 0x9c,
    0x7e, 0xf9, 0x55, 0xe5, 0x28, 0xad, 0x0f, 0x37, 0x09, 0x29, 0x81, 0x10, 0xb0, 0x36, 0x66, 0xd4,
];
#[cfg(feature = "mainnet-candidate")]
pub const NETWORK_ID: Hash = [
    0x0c, 0xa9, 0x82, 0x3a, 0xd6, 0xb5, 0x35, 0x5b, 0x0d, 0x57, 0x86, 0xa3, 0x75, 0x55, 0x83, 0xfe,
    0x00, 0xcd, 0x77, 0xfc, 0xfa, 0x16, 0x27, 0x6d, 0x37, 0xc8, 0x00, 0x6c, 0x7d, 0x1b, 0x98, 0x68,
];
pub const RING_SIZE: usize = 2;
pub const MAX_INPUTS: usize = 16;
const MAX_OUTPUTS: usize = 16;
const MAX_AUTH_BYTES: usize = 16 * 1024;
pub const AUTHORIZATION_BYTES: usize = 32 * (1 + 2 * RING_SIZE);

/// Experimental two-row linkable ring proof; not independently audited.
#[derive(Debug, PartialEq, Eq)]
pub struct AuthorizationProof {
    pub challenge: Scalar,
    pub key_responses: [Scalar; RING_SIZE],
    pub amount_responses: [Scalar; RING_SIZE],
}

impl AuthorizationProof {
    pub fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != AUTHORIZATION_BYTES {
            return Err("wrong authorization length");
        }
        let scalar_at = |offset: usize| -> Result<Scalar, &'static str> {
            let encoded: [u8; 32] = bytes[offset..offset + 32].try_into().unwrap();
            Option::from(Scalar::from_canonical_bytes(encoded))
                .ok_or("noncanonical authorization scalar")
        };
        let challenge = scalar_at(0)?;
        let mut key_responses = [Scalar::ZERO; RING_SIZE];
        let mut amount_responses = [Scalar::ZERO; RING_SIZE];
        for (index, response) in key_responses.iter_mut().enumerate() {
            *response = scalar_at(32 * (index + 1))?;
        }
        for (index, response) in amount_responses.iter_mut().enumerate() {
            *response = scalar_at(32 * (RING_SIZE + index + 1))?;
        }
        Ok(Self {
            challenge,
            key_responses,
            amount_responses,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(AUTHORIZATION_BYTES);
        bytes.extend_from_slice(&self.challenge.to_bytes());
        for response in &self.key_responses {
            bytes.extend_from_slice(&response.to_bytes());
        }
        for response in &self.amount_responses {
            bytes.extend_from_slice(&response.to_bytes());
        }
        bytes
    }
}

pub struct RingMemberStatement {
    pub destination: RistrettoPoint,
    pub hashed_destination: RistrettoPoint,
    pub commitment_difference: RistrettoPoint,
}

fn ring_member_statement(
    output: &FundedOutput,
    pseudo_output: RistrettoPoint,
) -> Result<RingMemberStatement, &'static str> {
    let destination = CompressedRistretto(output.destination.destination)
        .decompress()
        .ok_or("invalid ring destination")?;
    let commitment = CompressedRistretto(output.amount.commitment)
        .decompress()
        .ok_or("invalid ring commitment")?;
    Ok(RingMemberStatement {
        destination,
        hashed_destination: hash_point(&destination),
        commitment_difference: commitment - pseudo_output,
    })
}

fn hash_point(destination: &RistrettoPoint) -> RistrettoPoint {
    let mut hash = Sha512::new();
    hash.update(b"TSC-1:mlsag:hash-point:v1");
    hash.update(destination.compress().as_bytes());
    let uniform: [u8; 64] = hash.finalize().into();
    RistrettoPoint::from_uniform_bytes(&uniform)
}

pub fn key_image_for_secret(secret: Scalar) -> [u8; 32] {
    let destination = secret * bulletproofs::PedersenGens::default().B;
    (secret * hash_point(&destination)).compress().to_bytes()
}

fn ring_challenge(
    message: &Hash,
    key_image: &[u8; 32],
    index: usize,
    key_commitment: &RistrettoPoint,
    image_commitment: &RistrettoPoint,
    amount_commitment: &RistrettoPoint,
) -> Scalar {
    let mut hash = Sha512::new();
    hash.update(b"TSC-1:mlsag:challenge:v1");
    hash.update(message);
    hash.update(key_image);
    hash.update((index as u32).to_le_bytes());
    hash.update(key_commitment.compress().as_bytes());
    hash.update(image_commitment.compress().as_bytes());
    hash.update(amount_commitment.compress().as_bytes());
    let wide: [u8; 64] = hash.finalize().into();
    Scalar::from_bytes_mod_order_wide(&wide)
}

impl AuthorizationProof {
    pub fn sign(
        message: &Hash,
        key_image: [u8; 32],
        ring: &[RingMemberStatement],
        signer: usize,
        destination_secret: Scalar,
        amount_blinding_difference: Scalar,
    ) -> Result<Self, &'static str> {
        if ring.len() != RING_SIZE || signer >= RING_SIZE || destination_secret == Scalar::ZERO {
            return Err("invalid ring signer");
        }
        let generators = bulletproofs::PedersenGens::default();
        if ring[signer].destination != destination_secret * generators.B
            || ring[signer].commitment_difference
                != amount_blinding_difference * generators.B_blinding
            || key_image != key_image_for_secret(destination_secret)
        {
            return Err("ring witness does not match statement");
        }
        let alpha_key = crate::random_scalar().map_err(|_| "OS randomness unavailable")?;
        let alpha_amount = crate::random_scalar().map_err(|_| "OS randomness unavailable")?;
        let mut key_responses = [Scalar::ZERO; RING_SIZE];
        let mut amount_responses = [Scalar::ZERO; RING_SIZE];
        let mut challenges = [Scalar::ZERO; RING_SIZE];
        let next = (signer + 1) % RING_SIZE;
        challenges[next] = ring_challenge(
            message,
            &key_image,
            signer,
            &(alpha_key * generators.B),
            &(alpha_key * ring[signer].hashed_destination),
            &(alpha_amount * generators.B_blinding),
        );
        let image = CompressedRistretto(key_image)
            .decompress()
            .ok_or("invalid key image")?;
        for step in 1..RING_SIZE {
            let index = (signer + step) % RING_SIZE;
            key_responses[index] =
                crate::random_scalar().map_err(|_| "OS randomness unavailable")?;
            amount_responses[index] =
                crate::random_scalar().map_err(|_| "OS randomness unavailable")?;
            let member = &ring[index];
            let l = key_responses[index] * generators.B + challenges[index] * member.destination;
            let r = key_responses[index] * member.hashed_destination + challenges[index] * image;
            let t = amount_responses[index] * generators.B_blinding
                + challenges[index] * member.commitment_difference;
            challenges[(index + 1) % RING_SIZE] =
                ring_challenge(message, &key_image, index, &l, &r, &t);
        }
        key_responses[signer] = alpha_key - challenges[signer] * destination_secret;
        amount_responses[signer] = alpha_amount - challenges[signer] * amount_blinding_difference;
        Ok(Self {
            challenge: challenges[0],
            key_responses,
            amount_responses,
        })
    }

    pub fn verify(
        &self,
        message: &Hash,
        key_image: [u8; 32],
        ring: &[RingMemberStatement],
    ) -> bool {
        if ring.len() != RING_SIZE {
            return false;
        }
        let Some(image) = CompressedRistretto(key_image).decompress() else {
            return false;
        };
        if image == RistrettoPoint::default() {
            return false;
        }
        let generators = bulletproofs::PedersenGens::default();
        let mut challenge = self.challenge;
        for (index, member) in ring.iter().enumerate() {
            let l = self.key_responses[index] * generators.B + challenge * member.destination;
            let r = self.key_responses[index] * member.hashed_destination + challenge * image;
            let t = self.amount_responses[index] * generators.B_blinding
                + challenge * member.commitment_difference;
            challenge = ring_challenge(message, &key_image, index, &l, &r, &t);
        }
        challenge == self.challenge
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingInput {
    pub asset_id: [u8; 32],
    pub members: [Hash; RING_SIZE],
    pub key_image: [u8; 32],
    pub pseudo_output: [u8; 32],
    pub authorization: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    pub network_id: Hash,
    pub version: u8,
    pub expires_at_height: u64,
    pub inputs: Vec<RingInput>,
    pub outputs: Vec<FundedOutput>,
    pub fee_nox: u64,
}

fn valid_point(encoded: [u8; 32]) -> bool {
    matches!(CompressedRistretto(encoded).decompress(), Some(point) if point != RistrettoPoint::default())
}

impl Transaction {
    pub fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        fn take<const N: usize>(cursor: &mut Cursor<&[u8]>) -> Result<[u8; N], &'static str> {
            let mut field = [0u8; N];
            cursor
                .read_exact(&mut field)
                .map_err(|_| "truncated transaction")?;
            Ok(field)
        }
        let mut cursor = Cursor::new(bytes);
        let tag: [u8; 20] = take(&mut cursor)?;
        let v2 = &tag == b"TSC-1:tx:unsigned:v2";
        if !v2 && &tag != b"TSC-1:tx:unsigned:v1" {
            return Err("wrong transaction format");
        }
        let network_id = take(&mut cursor)?;
        let version = take::<1>(&mut cursor)?[0];
        if version != if v2 { 2 } else { 1 } {
            return Err("wrong transaction network or version");
        }
        let expires_at_height = u64::from_le_bytes(take(&mut cursor)?);
        let input_count = take::<1>(&mut cursor)?[0] as usize;
        if input_count == 0 || input_count > MAX_INPUTS {
            return Err("invalid input count");
        }
        let mut inputs = Vec::with_capacity(input_count);
        for _ in 0..input_count {
            let asset_id = if v2 { take(&mut cursor)? } else { TNB_ASSET_ID };
            let mut members = [[0u8; 32]; RING_SIZE];
            for member in &mut members {
                *member = take(&mut cursor)?;
            }
            inputs.push(RingInput {
                asset_id,
                members,
                key_image: take(&mut cursor)?,
                pseudo_output: take(&mut cursor)?,
                authorization: Vec::new(),
            });
        }
        let output_count = take::<1>(&mut cursor)?[0] as usize;
        if output_count == 0 || output_count > MAX_OUTPUTS {
            return Err("invalid output count");
        }
        let mut outputs = Vec::with_capacity(output_count);
        for _ in 0..output_count {
            let len = u32::from_le_bytes(take(&mut cursor)?) as usize;
            if len > 2048 {
                return Err("oversized output");
            }
            let mut encoded = vec![0u8; len];
            cursor
                .read_exact(&mut encoded)
                .map_err(|_| "truncated transaction")?;
            outputs.push(FundedOutput::decode_canonical(&encoded)?);
        }
        let fee_nox = u64::from_le_bytes(take(&mut cursor)?);
        for input in &mut inputs {
            let len = u32::from_le_bytes(take(&mut cursor)?) as usize;
            if len > MAX_AUTH_BYTES {
                return Err("oversized authorization");
            }
            input.authorization.resize(len, 0);
            cursor
                .read_exact(&mut input.authorization)
                .map_err(|_| "truncated transaction")?;
        }
        if cursor.position() != bytes.len() as u64 {
            return Err("trailing transaction bytes");
        }
        Ok(Self {
            network_id,
            version,
            expires_at_height,
            inputs,
            outputs,
            fee_nox,
        })
    }

    fn check_sizes(&self) -> Result<(), &'static str> {
        if self.inputs.is_empty() || self.inputs.len() > MAX_INPUTS {
            return Err("invalid input count");
        }
        if self.outputs.is_empty() || self.outputs.len() > MAX_OUTPUTS {
            return Err("invalid output count");
        }
        if self
            .inputs
            .iter()
            .any(|input| input.authorization.len() > MAX_AUTH_BYTES)
        {
            return Err("invalid authorization size");
        }
        if self.outputs.iter().any(|output| {
            output.amount.range_proof.len() > 2_048 || output.encrypted_note.len() != 56
        }) {
            return Err("invalid output size");
        }
        Ok(())
    }

    pub fn encode_unsigned(&self) -> Result<Vec<u8>, &'static str> {
        self.check_sizes()?;
        let mut bytes = Vec::new();
        if self.version == 1 {
            if self
                .inputs
                .iter()
                .any(|input| input.asset_id != TNB_ASSET_ID)
                || self
                    .outputs
                    .iter()
                    .any(|output| output.amount.asset_id != TNB_ASSET_ID)
            {
                return Err("legacy transaction contains non-TNB asset");
            }
            bytes.extend_from_slice(b"TSC-1:tx:unsigned:v1");
        } else if self.version == 2 {
            bytes.extend_from_slice(b"TSC-1:tx:unsigned:v2");
        } else {
            return Err("wrong transaction network or version");
        }
        bytes.extend_from_slice(&self.network_id);
        bytes.push(self.version);
        bytes.extend_from_slice(&self.expires_at_height.to_le_bytes());
        bytes.push(self.inputs.len() as u8);
        for input in &self.inputs {
            if self.version == 2 {
                bytes.extend_from_slice(&input.asset_id);
            }
            for member in &input.members {
                bytes.extend_from_slice(member);
            }
            bytes.extend_from_slice(&input.key_image);
            bytes.extend_from_slice(&input.pseudo_output);
        }
        bytes.push(self.outputs.len() as u8);
        for output in &self.outputs {
            let encoded = output.encode_canonical();
            bytes.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&encoded);
        }
        bytes.extend_from_slice(&self.fee_nox.to_le_bytes());
        Ok(bytes)
    }

    pub fn signing_hash(&self) -> Result<Hash, &'static str> {
        Ok(Sha256::digest(self.encode_unsigned()?).into())
    }

    pub fn encode(&self) -> Result<Vec<u8>, &'static str> {
        let mut bytes = self.encode_unsigned()?;
        for input in &self.inputs {
            bytes.extend_from_slice(&(input.authorization.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&input.authorization);
        }
        Ok(bytes)
    }

    pub fn txid(&self) -> Result<Hash, &'static str> {
        let mut hash = Sha256::new();
        hash.update(b"TSC-1:txid:v1");
        hash.update(self.encode()?);
        Ok(hash.finalize().into())
    }

    /// Public checks only. Ring membership and authorization are not verified here.
    pub fn validate_public(&self, height: u64) -> Result<(), &'static str> {
        self.check_sizes()?;
        for input in &self.inputs {
            if input.authorization.is_empty() {
                return Err("missing authorization");
            }
            AuthorizationProof::decode(&input.authorization)?;
        }
        if self.network_id != NETWORK_ID || !matches!(self.version, 1 | 2) {
            return Err("wrong transaction network or version");
        }
        if self.expires_at_height < height || self.expires_at_height == 0 {
            return Err("expired transaction");
        }
        if self.fee_nox == 0 || self.fee_nox > MAX_SUPPLY_NOX {
            return Err("invalid fee");
        }
        if self.version == 1
            && (self
                .inputs
                .iter()
                .any(|input| input.asset_id != TNB_ASSET_ID)
                || self
                    .outputs
                    .iter()
                    .any(|output| output.amount.asset_id != TNB_ASSET_ID))
        {
            return Err("legacy transaction contains non-TNB asset");
        }
        let mut images = HashSet::new();
        let mut input_assets = Vec::with_capacity(self.inputs.len());
        for input in &self.inputs {
            if !input.members.windows(2).all(|pair| pair[0] < pair[1]) {
                return Err("ring members not strictly ordered");
            }
            if !images.insert(input.key_image) || !valid_point(input.key_image) {
                return Err("invalid or duplicate key image");
            }
            if !valid_point(input.pseudo_output) {
                return Err("invalid pseudo output");
            }
            input_assets.push((input.asset_id, input.pseudo_output));
        }
        let mut destinations = HashSet::new();
        let mut output_assets = Vec::with_capacity(self.outputs.len());
        for output in &self.outputs {
            if !output.verify_public() || !destinations.insert(output.destination.destination) {
                return Err("invalid or duplicate output");
            }
            output_assets.push((output.amount.asset_id, output.amount.commitment));
        }
        if !balances_by_asset(&input_assets, &output_assets, &TNB_ASSET_ID, self.fee_nox) {
            return Err("unbalanced transaction");
        }
        Ok(())
    }

    pub fn validate_ring_membership(
        &self,
        chain: &Chain,
        inclusion_height: u64,
    ) -> Result<(), &'static str> {
        self.ring_statements(chain, inclusion_height).map(|_| ())
    }

    pub fn ring_statements(
        &self,
        chain: &Chain,
        inclusion_height: u64,
    ) -> Result<Vec<Vec<RingMemberStatement>>, &'static str> {
        self.ring_statements_with(inclusion_height, |id| chain.lookup_reward_output(id))
    }

    pub fn ring_statements_with<'a>(
        &self,
        inclusion_height: u64,
        mut lookup: impl FnMut(&Hash) -> Option<&'a FundedOutput>,
    ) -> Result<Vec<Vec<RingMemberStatement>>, &'static str> {
        self.validate_public(inclusion_height)?;
        let mut statements = Vec::with_capacity(self.inputs.len());
        for input in &self.inputs {
            let pseudo_output = CompressedRistretto(input.pseudo_output)
                .decompress()
                .ok_or("invalid pseudo output")?;
            let mut ring = Vec::with_capacity(RING_SIZE);
            for member in &input.members {
                let output = lookup(member).ok_or("unknown ring member")?;
                if output.amount.asset_id != input.asset_id {
                    return Err("ring member asset mismatch");
                }
                ring.push(ring_member_statement(output, pseudo_output)?);
            }
            statements.push(ring);
        }
        Ok(statements)
    }

    /// Cryptographic spend check for the research devnet; block consensus is separate.
    pub fn verify_anonymous_authorization(
        &self,
        chain: &Chain,
        inclusion_height: u64,
    ) -> Result<(), &'static str> {
        self.verify_anonymous_authorization_with(inclusion_height, |id| {
            chain.lookup_reward_output(id)
        })
    }

    pub fn verify_anonymous_authorization_with<'a>(
        &self,
        inclusion_height: u64,
        lookup: impl FnMut(&Hash) -> Option<&'a FundedOutput>,
    ) -> Result<(), &'static str> {
        let rings = self.ring_statements_with(inclusion_height, lookup)?;
        let message = self.signing_hash()?;
        let verify = |input: &RingInput, ring: &Vec<RingMemberStatement>| {
            AuthorizationProof::decode(&input.authorization)
                .map(|proof| proof.verify(&message, input.key_image, ring))
                .unwrap_or(false)
        };
        let valid = if cfg!(target_arch = "wasm32") || self.inputs.len() == 1 {
            self.inputs.iter().zip(rings.iter()).all(|(input, ring)| verify(input, ring))
        } else {
            self.inputs
                .par_iter()
                .zip(rings.par_iter())
                .all(|(input, ring)| verify(input, ring))
        };
        if !valid {
            return Err("invalid anonymous authorization");
        }
        Ok(())
    }

    pub fn validate_for_consensus(&self, height: u64) -> Result<(), &'static str> {
        self.validate_public(height)?;
        Err("transaction block consensus is not implemented")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::WalletSecrets;
    use crate::tsc1_funded_output::create_funded_output;
    use bulletproofs::PedersenGens;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use curve25519_dalek::scalar::Scalar;

    fn candidate_auth() -> Vec<u8> {
        let mut bytes = vec![0; AUTHORIZATION_BYTES];
        for chunk in bytes.as_chunks_mut::<32>().0 {
            chunk.copy_from_slice(&Scalar::ONE.to_bytes());
        }
        bytes
    }

    #[test]
    fn foreign_network_transaction_is_rejected() {
        let mut tx = sample();
        tx.network_id[0] ^= 1;
        assert_eq!(
            tx.validate_public(1),
            Err("wrong transaction network or version")
        );
    }

    #[test]
    fn v3f_network_domain_and_input_budget_are_enforced() {
        let mut domain = crate::network::TX_DOMAIN.to_vec();
        domain.extend_from_slice(&crate::network::pinned_genesis().unwrap().genesis_hash());
        let expected: Hash = Sha256::digest(&domain).into();
        assert_eq!(NETWORK_ID, expected);
        let mut tx = sample();
        tx.inputs = vec![tx.inputs[0].clone(); MAX_INPUTS + 1];
        assert_eq!(tx.validate_public(1), Err("invalid input count"));
    }

    fn sample() -> Transaction {
        let wallet = WalletSecrets::generate().unwrap();
        let output = create_funded_output(&wallet.address(), 0, 9).unwrap();
        let recovered = wallet.scan_funded_output(&output, 0).unwrap();
        let pseudo_output = PedersenGens::default()
            .commit(Scalar::from(10u64), recovered.blinding)
            .compress()
            .to_bytes();
        Transaction {
            network_id: NETWORK_ID,
            version: 2,
            expires_at_height: 100,
            inputs: vec![RingInput {
                asset_id: TNB_ASSET_ID,
                members: std::array::from_fn(|index| [(index + 1) as u8; 32]),
                key_image: RISTRETTO_BASEPOINT_POINT.compress().to_bytes(),
                pseudo_output,
                authorization: candidate_auth(),
            }],
            outputs: vec![output],
            fee_nox: 1,
        }
    }

    #[test]
    fn public_rules_pass_but_consensus_rejects() {
        let tx = sample();
        assert_eq!(tx.validate_public(1), Ok(()));
        assert_eq!(
            tx.validate_for_consensus(1),
            Err("transaction block consensus is not implemented")
        );
    }

    #[test]
    fn signing_message_binds_fee_and_output_but_not_authorization() {
        let tx = sample();
        let signed = tx.signing_hash().unwrap();
        let txid = tx.txid().unwrap();
        let mut changed = tx.clone();
        changed.inputs[0].authorization.clear();
        assert_eq!(changed.signing_hash().unwrap(), signed);
        assert_eq!(changed.validate_public(1), Err("missing authorization"));
        changed = tx.clone();
        changed.inputs[0].authorization[0] ^= 1;
        assert_eq!(changed.signing_hash().unwrap(), signed);
        assert_ne!(changed.txid().unwrap(), txid);
        changed = tx.clone();
        changed.fee_nox += 1;
        assert_ne!(changed.signing_hash().unwrap(), signed);
        changed = tx.clone();
        changed.network_id = [0; 32];
        assert_ne!(changed.signing_hash().unwrap(), signed);
        changed = tx.clone();
        changed.outputs[0].encrypted_note[0] ^= 1;
        assert_ne!(changed.signing_hash().unwrap(), signed);
    }

    #[test]
    fn rejects_wrong_network_expiry_fee_and_ring_order() {
        let tx = sample();
        let mut changed = tx.clone();
        changed.network_id = [0; 32];
        assert_eq!(
            changed.validate_public(1),
            Err("wrong transaction network or version")
        );
        changed = tx.clone();
        assert_eq!(changed.validate_public(101), Err("expired transaction"));
        changed.fee_nox = 2;
        assert_eq!(changed.validate_public(1), Err("unbalanced transaction"));
        changed = tx.clone();
        changed.inputs[0].members[1] = changed.inputs[0].members[0];
        assert_eq!(
            changed.validate_public(1),
            Err("ring members not strictly ordered")
        );
    }

    #[test]
    fn rejects_tampered_proof_and_duplicate_key_image() {
        let tx = sample();
        let mut changed = tx.clone();
        changed.outputs[0].amount.range_proof[0] ^= 1;
        assert_eq!(
            changed.validate_public(1),
            Err("invalid or duplicate output")
        );
        changed = tx.clone();
        changed.inputs.push(changed.inputs[0].clone());
        assert_eq!(
            changed.validate_public(1),
            Err("invalid or duplicate key image")
        );
    }

    #[test]
    fn canonical_decode_rejects_truncation_trailing_and_oversized_auth() {
        let tx = sample();
        let encoded = tx.encode().unwrap();
        let decoded = Transaction::decode(&encoded).unwrap();
        assert_eq!(decoded.encode().unwrap(), encoded);
        assert_eq!(decoded.txid().unwrap(), tx.txid().unwrap());
        assert!(Transaction::decode(&encoded[..encoded.len() - 1]).is_err());
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            Transaction::decode(&trailing).err(),
            Some("trailing transaction bytes")
        );
        let mut oversized = encoded;
        let offset = oversized.len() - AUTHORIZATION_BYTES - 4;
        oversized[offset..offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            Transaction::decode(&oversized).err(),
            Some("oversized authorization")
        );
    }

    #[test]
    fn token_transaction_roundtrip_and_ring_asset_binding() {
        let mut tx = sample();
        let wallet = WalletSecrets::from_seed(&[27; 32]);
        let mut token_output = create_funded_output(&wallet.address(), 1, 50).unwrap();
        token_output.amount =
            crate::tsc1_private_amounts::prove_amount(50, &Scalar::ONE, &[7; 32]).unwrap();
        let mut token_input = tx.inputs[0].clone();
        token_input.asset_id = [7; 32];
        token_input.key_image = (Scalar::from(2u64) * RISTRETTO_BASEPOINT_POINT)
            .compress()
            .to_bytes();
        token_input.pseudo_output = token_output.amount.commitment;
        tx.inputs.push(token_input);
        tx.outputs.push(token_output);
        assert_eq!(tx.validate_public(1), Ok(()));
        let encoded = tx.encode().unwrap();
        let decoded = Transaction::decode(&encoded).unwrap();
        assert_eq!(decoded.encode().unwrap(), encoded);
        assert_eq!(decoded.validate_public(1), Ok(()));
        let native = &tx.outputs[0];
        assert_eq!(
            tx.ring_statements_with(1, |_| Some(native)).err(),
            Some("ring member asset mismatch")
        );
        tx.inputs[1].asset_id = TNB_ASSET_ID;
        assert_eq!(tx.validate_public(1), Err("unbalanced transaction"));
    }

    #[test]
    fn legacy_encoding_preserves_bytes_and_rejects_assets() {
        let mut tx = sample();
        let v2 = tx.encode().unwrap();
        // Reconstruct the original v1 wire layout independently of the encoder.
        let mut legacy = v2.clone();
        legacy[..20].copy_from_slice(b"TSC-1:tx:unsigned:v1");
        legacy[52] = 1;
        legacy.drain(62..94);
        tx.version = 1;
        assert_eq!(tx.encode().unwrap(), legacy);
        let decoded = Transaction::decode(&legacy).unwrap();
        assert_eq!(decoded.encode().unwrap(), legacy);
        assert_eq!(decoded.validate_public(1), Ok(()));
        assert_eq!(decoded.signing_hash().unwrap(), tx.signing_hash().unwrap());
        tx.inputs[0].asset_id = [7; 32];
        assert!(tx.encode().is_err());
        assert!(tx.validate_public(1).is_err());
        let mut mismatched = v2;
        mismatched[52] = 1;
        assert!(Transaction::decode(&mismatched).is_err());
    }

    #[test]
    fn authorization_encoding_rejects_noncanonical_fields() {
        let mut tx = sample();
        assert!(AuthorizationProof::decode(&tx.inputs[0].authorization).is_ok());
        tx.inputs[0].authorization[0..32].fill(0xff);
        assert_eq!(
            tx.validate_public(1),
            Err("noncanonical authorization scalar")
        );
        tx = sample();
        tx.inputs[0].authorization[32 * (RING_SIZE + 1)..][..32].fill(0xff);
        assert_eq!(
            tx.validate_public(1),
            Err("noncanonical authorization scalar")
        );
        tx = sample();
        tx.inputs[0].authorization.pop();
        assert_eq!(tx.validate_public(1), Err("wrong authorization length"));
    }

    #[test]
    fn member_statement_binds_destination_and_commitment_difference() {
        let chain = crate::tsc1_devnet_v2::pinned_genesis().unwrap();
        let output = &chain.genesis_block().reward_output;
        let commitment = CompressedRistretto(output.amount.commitment)
            .decompress()
            .unwrap();
        let statement = ring_member_statement(output, commitment).unwrap();
        assert_eq!(
            statement.destination.compress().to_bytes(),
            output.destination.destination
        );
        assert_eq!(statement.commitment_difference, RistrettoPoint::default());
        let changed =
            ring_member_statement(output, commitment + RISTRETTO_BASEPOINT_POINT).unwrap();
        assert_ne!(
            changed.commitment_difference,
            statement.commitment_difference
        );
    }

    #[test]
    fn two_row_ring_proof_binds_key_amount_message_and_image() {
        let generators = PedersenGens::default();
        let mut ring: Vec<RingMemberStatement> = (0..RING_SIZE)
            .map(|index| {
                let destination = Scalar::from(index as u64 + 1) * generators.B;
                RingMemberStatement {
                    destination,
                    hashed_destination: hash_point(&destination),
                    commitment_difference: Scalar::from(index as u64 + 2) * generators.B_blinding,
                }
            })
            .collect();
        let signer = RING_SIZE - 1;
        let key = Scalar::from(signer as u64 + 1);
        let amount = Scalar::from(signer as u64 + 2);
        let image = key_image_for_secret(key);
        let message = [42; 32];
        let proof = AuthorizationProof::sign(&message, image, &ring, signer, key, amount).unwrap();
        assert!(proof.verify(&message, image, &ring));
        assert!(
            AuthorizationProof::decode(&proof.encode())
                .unwrap()
                .verify(&message, image, &ring)
        );
        assert!(!proof.verify(&[43; 32], image, &ring));
        assert!(!proof.verify(&key_image_for_secret(Scalar::from(99u64)), image, &ring));
        let mut forged = AuthorizationProof::decode(&proof.encode()).unwrap();
        forged.amount_responses[0] += Scalar::ONE;
        assert!(!forged.verify(&message, image, &ring));
        let mutated_index = (signer + 1) % RING_SIZE;
        ring[mutated_index].destination += generators.B;
        assert!(!proof.verify(&message, image, &ring));
        ring[mutated_index].destination -= generators.B;
        ring[mutated_index].commitment_difference += generators.B_blinding;
        assert!(!proof.verify(&message, image, &ring));
        assert!(
            AuthorizationProof::sign(&message, image, &ring, signer, Scalar::from(99u64), amount)
                .is_err()
        );
        assert!(
            AuthorizationProof::sign(&message, image, &ring, signer, key, amount + Scalar::ONE)
                .is_err()
        );
    }

    #[test]
    fn every_ring_position_is_linkable_and_rejects_mutations() {
        let generators = PedersenGens::default();
        let ring: Vec<RingMemberStatement> = (0..RING_SIZE)
            .map(|index| {
                let destination = Scalar::from(index as u64 + 1) * generators.B;
                RingMemberStatement {
                    destination,
                    hashed_destination: hash_point(&destination),
                    commitment_difference: Scalar::from(index as u64 + 17) * generators.B_blinding,
                }
            })
            .collect();
        let message = [61; 32];
        for signer in 0..RING_SIZE {
            let key = Scalar::from(signer as u64 + 1);
            let amount = Scalar::from(signer as u64 + 17);
            let image = key_image_for_secret(key);
            let proof =
                AuthorizationProof::sign(&message, image, &ring, signer, key, amount).unwrap();
            assert!(proof.verify(&message, image, &ring));
            assert_eq!(image, key_image_for_secret(key));
            assert!(!proof.verify(&[62; 32], image, &ring));
            let mut changed = AuthorizationProof::decode(&proof.encode()).unwrap();
            changed.key_responses[signer] += Scalar::ONE;
            assert!(!changed.verify(&message, image, &ring));
            let mut changed = AuthorizationProof::decode(&proof.encode()).unwrap();
            changed.amount_responses[signer] += Scalar::ONE;
            assert!(!changed.verify(&message, image, &ring));
        }
    }

    #[test]
    #[ignore = "manual signature timing; run with --ignored --nocapture"]
    fn measure_ring_signature_cost() {
        use std::time::Instant;

        let generators = PedersenGens::default();
        let ring: Vec<RingMemberStatement> = (0..RING_SIZE)
            .map(|index| {
                let destination = Scalar::from(index as u64 + 1) * generators.B;
                RingMemberStatement {
                    destination,
                    hashed_destination: hash_point(&destination),
                    commitment_difference: Scalar::from(index as u64 + 17) * generators.B_blinding,
                }
            })
            .collect();
        let signer = RING_SIZE - 1;
        let key = Scalar::from(signer as u64 + 1);
        let amount = Scalar::from(signer as u64 + 17);
        let image = key_image_for_secret(key);
        let message = [71; 32];
        let mut signing = Vec::with_capacity(10);
        let mut verification = Vec::with_capacity(10);
        for _ in 0..10 {
            let start = Instant::now();
            let proof =
                AuthorizationProof::sign(&message, image, &ring, signer, key, amount).unwrap();
            signing.push(start.elapsed());
            let start = Instant::now();
            assert!(proof.verify(&message, image, &ring));
            verification.push(start.elapsed());
        }
        signing.sort();
        verification.sort();
        eprintln!("ring_signature_samples=10");
        eprintln!(
            "ring_signature_sign_median_ms={:.2}",
            signing[5].as_secs_f64() * 1000.0
        );
        eprintln!(
            "ring_signature_verify_median_ms={:.2}",
            verification[5].as_secs_f64() * 1000.0
        );
        eprintln!(
            "ring_signature_verify_max_ms={:.2}",
            verification[9].as_secs_f64() * 1000.0
        );
    }

    #[test]
    #[ignore = "500-proof throughput benchmark; run with --release --ignored --nocapture"]
    fn benchmark_500_anonymous_proofs_parallel() {
        use std::time::Instant;

        let generators = PedersenGens::default();
        let ring: Vec<RingMemberStatement> = (0..RING_SIZE)
            .map(|index| {
                let destination = Scalar::from(index as u64 + 1) * generators.B;
                RingMemberStatement {
                    destination,
                    hashed_destination: hash_point(&destination),
                    commitment_difference: Scalar::from(index as u64 + 17) * generators.B_blinding,
                }
            })
            .collect();
        let signer = RING_SIZE - 1;
        let key = Scalar::from(signer as u64 + 1);
        let amount = Scalar::from(signer as u64 + 17);
        let image = key_image_for_secret(key);
        let message = [73; 32];
        let proofs: Vec<_> = (0..500)
            .map(|_| AuthorizationProof::sign(&message, image, &ring, signer, key, amount).unwrap())
            .collect();
        let start = Instant::now();
        let verified = proofs
            .par_iter()
            .filter(|proof| proof.verify(&message, image, &ring))
            .count();
        let elapsed = start.elapsed();
        assert_eq!(verified, 500);
        eprintln!("anonymous_proofs_verified={verified}");
        eprintln!(
            "anonymous_proof_batch_ms={:.2}",
            elapsed.as_secs_f64() * 1000.0
        );
        eprintln!(
            "anonymous_proof_batch_tps={:.2}",
            500.0 / elapsed.as_secs_f64()
        );
    }

    #[test]
    fn wallet_signs_founder_output_against_mined_ring() {
        use crate::FOUNDER_ALLOCATION_NOX;
        use crate::tsc1_chain_v2::{Chain, reward_at_height};
        use crate::tsc1_funded_output::create_reward_output;

        let founder = WalletSecrets::from_seed(&[61; 32]);
        let founder_output =
            create_reward_output(&founder.address(), 0, FOUNDER_ALLOCATION_NOX).unwrap();
        let recovered = founder.scan_funded_output(&founder_output, 0).unwrap();
        let mut chain = Chain::new(founder_output, 1).unwrap();
        for index in 1..(RING_SIZE + 10) {
            let recipient = WalletSecrets::from_seed(&[index as u8; 32]);
            let amount = reward_at_height(index as u64);
            let output = create_reward_output(&recipient.address(), 0, amount).unwrap();
            let mut block = chain.next_block(output, chain.tip_timestamp() + 1);
            block.mine().unwrap();
            chain.append(block).unwrap();
        }
        let founder_id = chain.genesis_block().reward_output_id();
        let mut ids: Vec<Hash> = chain
            .blocks()
            .iter()
            .take(RING_SIZE)
            .map(|block| block.reward_output_id())
            .collect();
        ids.sort();
        let signer = ids.iter().position(|id| *id == founder_id).unwrap();
        let receiver = WalletSecrets::from_seed(&[71; 32]);
        let output =
            create_funded_output(&receiver.address(), 0, FOUNDER_ALLOCATION_NOX - 10).unwrap();
        let output_blinding = receiver.scan_funded_output(&output, 0).unwrap().blinding;
        let pseudo =
            PedersenGens::default().commit(Scalar::from(FOUNDER_ALLOCATION_NOX), output_blinding);
        let secret =
            Option::<Scalar>::from(Scalar::from_canonical_bytes(recovered.one_time_spend)).unwrap();
        let mut tx = Transaction {
            network_id: NETWORK_ID,
            version: 1,
            expires_at_height: chain.height() + 10,
            inputs: vec![RingInput {
                asset_id: TNB_ASSET_ID,
                members: ids.clone().try_into().unwrap(),
                key_image: key_image_for_secret(secret),
                pseudo_output: pseudo.compress().to_bytes(),
                authorization: candidate_auth(),
            }],
            outputs: vec![output],
            fee_nox: 10,
        };
        let ring = tx.ring_statements(&chain, chain.height() + 1).unwrap();
        let proof = AuthorizationProof::sign(
            &tx.signing_hash().unwrap(),
            tx.inputs[0].key_image,
            &ring[0],
            signer,
            secret,
            -output_blinding,
        )
        .unwrap();
        tx.inputs[0].authorization = proof.encode();
        assert_eq!(
            tx.verify_anonymous_authorization(&chain, chain.height() + 1),
            Ok(())
        );
        let mut state = crate::tsc1_spend_state_v2::SpendState::from_reward_chain(&chain);
        let original_count = state.output_count();
        assert!(
            state
                .apply_batch(&[tx.clone(), tx.clone()], chain.height() + 1)
                .is_err()
        );
        assert_eq!(state.output_count(), original_count);
        assert!(!state.has_spent_image(&tx.inputs[0].key_image));
        assert_eq!(state.apply_batch(&[tx.clone()], chain.height() + 1), Ok(()));
        let received_id = crate::tsc1_spend_state_v2::transaction_output_id(tx.txid().unwrap(), 0);
        assert!(state.output(&received_id).is_some());
        assert!(state.has_spent_image(&tx.inputs[0].key_image));
        assert!(
            state
                .apply_batch(&[tx.clone()], chain.height() + 1)
                .is_err()
        );
        let received = receiver
            .scan_funded_output(state.output(&received_id).unwrap(), 0)
            .unwrap();
        let received_secret =
            Option::<Scalar>::from(Scalar::from_canonical_bytes(received.one_time_spend)).unwrap();
        let final_receiver = WalletSecrets::from_seed(&[72; 32]);
        let final_output =
            create_funded_output(&final_receiver.address(), 0, FOUNDER_ALLOCATION_NOX - 11)
                .unwrap();
        let final_blinding = final_receiver
            .scan_funded_output(&final_output, 0)
            .unwrap()
            .blinding;
        let second_pseudo = PedersenGens::default()
            .commit(Scalar::from(FOUNDER_ALLOCATION_NOX - 10), final_blinding);
        let mut second_ids = ids.clone();
        second_ids.retain(|id| *id != founder_id);
        second_ids.push(received_id);
        second_ids.sort();
        let second_signer = second_ids.iter().position(|id| *id == received_id).unwrap();
        let mut second = Transaction {
            network_id: NETWORK_ID,
            version: 2,
            expires_at_height: chain.height() + 10,
            inputs: vec![RingInput {
                asset_id: TNB_ASSET_ID,
                members: second_ids.try_into().unwrap(),
                key_image: key_image_for_secret(received_secret),
                pseudo_output: second_pseudo.compress().to_bytes(),
                authorization: candidate_auth(),
            }],
            outputs: vec![final_output],
            fee_nox: 1,
        };
        let second_ring = second
            .ring_statements_with(chain.height() + 1, |id| state.output(id))
            .unwrap();
        second.inputs[0].authorization = AuthorizationProof::sign(
            &second.signing_hash().unwrap(),
            second.inputs[0].key_image,
            &second_ring[0],
            second_signer,
            received_secret,
            received.blinding - final_blinding,
        )
        .unwrap()
        .encode();
        assert_eq!(
            state.apply_batch(&[second.clone()], chain.height() + 1),
            Ok(())
        );
        assert!(state.has_spent_image(&second.inputs[0].key_image));
        assert!(
            state
                .output(&crate::tsc1_spend_state_v2::transaction_output_id(
                    second.txid().unwrap(),
                    0
                ))
                .is_some()
        );
        let mut nonce = [0u8; 8];
        getrandom::getrandom(&mut nonce).unwrap();
        let journal_dir =
            std::env::temp_dir().join(format!("tsc1-spend-journal-{}", hex::encode(nonce)));
        let journal =
            crate::tsc1_spend_journal_v2::append(&chain, &journal_dir, &[tx.clone()]).unwrap();
        assert_eq!(journal.record_count, 1);
        let journal =
            crate::tsc1_spend_journal_v2::append(&chain, &journal_dir, &[second.clone()]).unwrap();
        assert_eq!(journal.record_count, 2);
        let restored = crate::tsc1_spend_journal_v2::load(&chain, &journal_dir).unwrap();
        assert_eq!(restored.spends.output_count(), state.output_count());
        assert!(restored.spends.has_spent_image(&second.inputs[0].key_image));
        let first_file = journal_dir.join("00000000000000000001.bin");
        let mut damaged = std::fs::read(&first_file).unwrap();
        damaged[0] ^= 1;
        std::fs::write(&first_file, damaged).unwrap();
        assert!(crate::tsc1_spend_journal_v2::load(&chain, &journal_dir).is_err());
        std::fs::remove_file(first_file).unwrap();
        std::fs::remove_file(journal_dir.join("00000000000000000002.bin")).unwrap();
        std::fs::remove_dir(journal_dir).unwrap();
        let genesis_only = Chain::from_genesis(chain.genesis_block().clone()).unwrap();
        let mut v3 = crate::tsc1_chain_v3::ChainV3::from_genesis(genesis_only.clone()).unwrap();
        assert_eq!(v3.wallet_balance_nox(&founder), Ok(FOUNDER_ALLOCATION_NOX));
        for reward_block in chain.blocks().iter().skip(1) {
            let mut block = crate::tsc1_chain_v3::BlockV3 {
                previous_hash: v3.tip_hash(),
                reward: reward_block.clone(),
                transactions: Vec::new(),
                miner_fee_output: None,
                treasury_fee_output: None,
                asset_transactions: Vec::new(),
                dex_operations: Vec::new(),
                difficulty_bits: v3.next_difficulty_bits(),
                nonce: 0,
            };
            block.mine().unwrap();
            v3.append(block).unwrap();
        }
        let mut immature_tx = tx.clone();
        immature_tx.inputs[0].members[0] = chain.blocks().last().unwrap().reward_output_id();
        immature_tx.inputs[0].members.sort();
        let immature_miner = WalletSecrets::from_seed(&[93; 32]);
        let immature_reward = create_reward_output(
            &immature_miner.address(),
            0,
            reward_at_height(v3.height() + 1),
        )
        .unwrap();
        let mut immature_block = v3
            .next_block_with_fees(
                immature_reward,
                &immature_miner.address(),
                v3.rewards().tip_timestamp() + 1,
                vec![immature_tx],
            )
            .unwrap();
        immature_block.mine().unwrap();
        assert_eq!(
            v3.append(immature_block),
            Err("invalid anonymous authorization")
        );
        let miner = WalletSecrets::from_seed(&[90; 32]);
        let reward =
            create_reward_output(&miner.address(), 0, reward_at_height(v3.height() + 1)).unwrap();
        let mut first_block = v3
            .next_block_with_fees(
                reward,
                &miner.address(),
                v3.rewards().tip_timestamp() + 1,
                vec![tx.clone()],
            )
            .unwrap();
        first_block.mine().unwrap();
        assert!(first_block.miner_fee_output.is_some());
        assert!(first_block.treasury_fee_output.is_some());
        let mut missing_treasury = first_block.clone();
        missing_treasury.treasury_fee_output = None;
        missing_treasury.mine().unwrap();
        assert!(v3.append(missing_treasury).is_err());
        let original_hash = first_block.hash().unwrap();
        let mut forged_block = first_block.clone();
        forged_block.transactions[0].inputs[0].authorization[32] ^= 1;
        assert_ne!(forged_block.hash().unwrap(), original_hash);
        forged_block.mine().unwrap();
        assert!(v3.append(forged_block).is_err());
        assert_eq!(v3.height(), chain.height());
        v3.append(first_block).unwrap();
        assert!(v3.spends().has_spent_image(&tx.inputs[0].key_image));
        assert_eq!(v3.wallet_balance_nox(&founder), Ok(0));
        assert_eq!(
            v3.wallet_balance_nox(&receiver),
            Ok(FOUNDER_ALLOCATION_NOX - 10)
        );
        let next_miner = WalletSecrets::from_seed(&[91; 32]);
        let reward =
            create_reward_output(&next_miner.address(), 0, reward_at_height(v3.height() + 1))
                .unwrap();
        let mut second_block = v3
            .next_block_with_fees(
                reward,
                &next_miner.address(),
                v3.rewards().tip_timestamp() + 1,
                vec![second.clone()],
            )
            .unwrap();
        second_block.mine().unwrap();
        v3.append(second_block).unwrap();
        assert!(v3.spends().has_spent_image(&second.inputs[0].key_image));
        assert_eq!(v3.wallet_balance_nox(&receiver), Ok(0));
        assert_eq!(
            v3.wallet_balance_nox(&final_receiver),
            Ok(FOUNDER_ALLOCATION_NOX - 11)
        );
        let restored_v3 =
            crate::tsc1_chain_v3::ChainV3::decode(&v3.encode().unwrap(), genesis_only).unwrap();
        assert_eq!(restored_v3.tip_hash(), v3.tip_hash());
        assert_eq!(
            restored_v3.wallet_balance_nox(&final_receiver),
            Ok(FOUNDER_ALLOCATION_NOX - 11)
        );
        assert!(
            restored_v3
                .spends()
                .has_spent_image(&second.inputs[0].key_image)
        );
        let before_replay = v3.tip_hash();
        let replay_miner = WalletSecrets::from_seed(&[92; 32]);
        let reward = create_reward_output(
            &replay_miner.address(),
            0,
            reward_at_height(v3.height() + 1),
        )
        .unwrap();
        let mut replay_block = v3
            .next_block_with_fees(
                reward,
                &replay_miner.address(),
                v3.rewards().tip_timestamp() + 1,
                vec![tx.clone()],
            )
            .unwrap();
        replay_block.mine().unwrap();
        assert!(v3.append(replay_block).is_err());
        assert_eq!(v3.tip_hash(), before_replay);
        tx.inputs[0].authorization[32] ^= 1;
        assert!(
            tx.verify_anonymous_authorization(&chain, chain.height() + 1)
                .is_err()
        );
    }

    #[test]
    fn unknown_ring_members_cannot_enter_a_validated_chain() {
        let tx = sample();
        let chain = crate::tsc1_devnet_v2::pinned_genesis().unwrap();
        assert_eq!(
            tx.validate_ring_membership(&chain, 1),
            Err("unknown ring member")
        );
    }
}
