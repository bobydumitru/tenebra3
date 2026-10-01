// Generates synthetic public-chain fixtures only; never contacts the live network.
use tenebra::{
    WalletSecrets,
    assets::AssetTransaction,
    tsc1_chain_v3::ChainV3,
    tsc1_chain_v2::{reward_at_height, TARGET_BLOCK_SECONDS},
    tsc1_funded_output::create_reward_output,
    tsc1_tx_v2::Transaction,
    tsc1_wallet_tx_v3::{create_signed_asset_creation_fee, create_signed_transfer},
};
use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, scalar::Scalar};
use chacha20poly1305::{aead::{Aead, KeyInit, Payload}, XChaCha20Poly1305, XNonce};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = std::path::Path::new("target/wallet-regression");
    std::fs::create_dir_all(root)?;
    let sender = WalletSecrets::from_seed(&[203;32]);
    let recipient = WalletSecrets::from_seed(&[204;32]);
    let miner = WalletSecrets::from_seed(&[205;32]);
    let mut chain = ChainV3::from_pinned_genesis()?;
    let mut bytes = Vec::new();
    if std::env::args().any(|arg| arg == "confirm") {
        let prior = std::fs::read(root.join("before.bin"))?;
        let mut cursor = 0;
        while cursor < prior.len() {
            let length=u32::from_le_bytes(prior[cursor..cursor+4].try_into()?) as usize;cursor+=4;
            chain.append(tenebra::tsc1_chain_v3::BlockV3::decode(&prior[cursor..cursor+length])?)?;cursor+=length;
        }
        bytes=prior;
        let tx=Transaction::decode(&std::fs::read(root.join("signed.bin"))?)?;
        let reward=create_reward_output(&miner.address(),0,reward_at_height(chain.height()+1))?;
        let mut block=chain.next_block_with_fees(reward,&miner.address(),chain.rewards().tip_timestamp()+TARGET_BLOCK_SECONDS,vec![tx])?;
        block.mine()?;let encoded=block.encode()?;chain.append(block)?;
        bytes.extend_from_slice(&(encoded.len() as u32).to_le_bytes());bytes.extend(encoded);
        std::fs::write(root.join("after.bin"),bytes)?;
        std::fs::write(root.join("expected.json"),serde_json::to_vec(&serde_json::json!({"sender":chain.wallet_balance_nox(&sender)?.to_string(),"recipient":chain.wallet_balance_nox(&recipient)?.to_string()}))?)?;
    } else if std::env::args().any(|arg| arg == "asset-fee-history") {
        for height in 1..=16 {
            let reward=create_reward_output(&miner.address(),0,reward_at_height(height))?;
            let mut block=chain.next_block(reward,chain.rewards().tip_timestamp()+TARGET_BLOCK_SECONDS,vec![]);
            block.mine()?;
            chain.append(block.clone())?;
            let encoded=block.encode()?;
            bytes.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
            bytes.extend(encoded);
        }
        let funding=create_signed_transfer(&chain,&miner,&sender.address(),10_000_000_002,1)?;
        let reward=create_reward_output(&miner.address(),0,reward_at_height(chain.height()+1))?;
        let mut block=chain.next_block_with_fees(reward,&miner.address(),chain.rewards().tip_timestamp()+TARGET_BLOCK_SECONDS,vec![funding])?;
        block.mine()?;
        let encoded=block.encode()?;
        chain.append(block)?;
        bytes.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
        bytes.extend(encoded);
        let issuer_secret=Scalar::from(9u64);
        let issuer=(issuer_secret*RISTRETTO_BASEPOINT_POINT).compress().to_bytes();
        let asset=AssetTransaction::Create {
            issuer, nonce: 1, name: "History fixture".into(), symbol: "HST".into(),
            decimals: 9, max_supply: 1000, initial_supply: 1000,
        };
        let mut signed=tenebra::assets::sign_issuer(&asset,issuer_secret,&[6u8;64])?;
        signed.creation_fee=Some(create_signed_asset_creation_fee(&chain,&sender,asset.txid()?)?);
        let reward=create_reward_output(&miner.address(),0,reward_at_height(chain.height()+1))?;
        let mut block=chain.next_block(reward,chain.rewards().tip_timestamp()+TARGET_BLOCK_SECONDS,vec![]);
        block.asset_transactions.push(signed);
        block.mine()?;
        let encoded=block.encode()?;
        chain.append_wallet_state(block)?;
        bytes.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
        bytes.extend(encoded);
        std::fs::write(root.join("asset-fee-history.bin"),bytes)?;
        std::fs::write(root.join("asset-fee-history.json"),serde_json::to_vec(&serde_json::json!({"sender":chain.wallet_balance_nox(&sender)?.to_string(),"recipient":chain.wallet_balance_nox(&recipient)?.to_string()}))?)?;
    } else {
        for height in 1..=12 {
            let reward=create_reward_output(&sender.address(),0,reward_at_height(height))?;
            let mut block=chain.next_block(reward,chain.rewards().tip_timestamp()+TARGET_BLOCK_SECONDS,vec![]);
            block.mine()?;let encoded=block.encode()?;chain.append(block)?;
            bytes.extend_from_slice(&(encoded.len() as u32).to_le_bytes());bytes.extend(encoded);
        }
        std::fs::write(root.join("before.bin"),bytes)?;
        let mut key=[0u8;32];argon2::Argon2::default().hash_password_into(b"test-password-only",&[7;16],&mut key).unwrap();
        let cipher=XChaCha20Poly1305::new_from_slice(&key).unwrap();
        let encrypted=cipher.encrypt(XNonce::from_slice(&[8;24]),Payload{msg:&[203;32],aad:b"TSC1WLT1"}).unwrap();
        let mut file=b"TSC1WLT1".to_vec();file.extend([7;16]);file.extend([8;24]);file.extend(encrypted);
        std::fs::write(root.join("synthetic.tsc1"),file)?;
    }
    Ok(())
}
