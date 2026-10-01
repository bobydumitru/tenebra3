use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, scalar::Scalar};
use argon2::Argon2;
use bip39::{Language, Mnemonic};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use sha2::{Digest, Sha256, Sha512};
use tenebra::{
    Address, WalletSecrets,
    assets::{AssetKind, AssetTransaction, sign_issuer},
    dex::{DexOperation, sign_with_sequence},
    tsc1_chain_v3::{BlockV3, ChainV3},
    tsc1_wallet_tx_v3::{create_signed_asset_creation_fee_for_asset, create_signed_asset_transfer_fee, create_signed_transfer},
};

#[link(wasm_import_module = "./env.js")]
unsafe extern "C" {
    fn random_fill(pointer: *mut u8, length: usize);
}

fn scalar(seed: &[u8; 32], role: &[u8]) -> Scalar {
    let mut hash = Sha512::new();
    hash.update(b"TSC-1:wallet-key:v1");
    hash.update(role);
    hash.update(seed);
    let digest: [u8; 64] = hash.finalize().into();
    Scalar::from_bytes_mod_order_wide(&digest)
}

fn address(seed: &[u8; 32]) -> String {
    let mut public = [0u8; 64];
    public[..32].copy_from_slice(&(scalar(seed, b"view") * RISTRETTO_BASEPOINT_POINT).compress().to_bytes());
    public[32..].copy_from_slice(&(scalar(seed, b"spend") * RISTRETTO_BASEPOINT_POINT).compress().to_bytes());
    let checksum = Sha256::digest([b"TSC1-address-v1".as_slice(), &public].concat());
    format!("tsc1_{}{}", hex::encode(public), hex::encode(&checksum[..4]))
}

fn decrypt_native_seed(file: &[u8], password: &[u8]) -> Option<[u8; 32]> {
    if file.len() != 96 || &file[..8] != b"TSC1WLT1" {
        return None;
    }
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(password, &file[8..24], &mut key)
        .ok()?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    let seed = cipher
        .decrypt(
            XNonce::from_slice(&file[24..48]),
            Payload { msg: &file[48..], aad: b"TSC1WLT1" },
        )
        .ok()?;
    seed.as_slice().try_into().ok()
}

fn write_signed_dex(
    file: &[u8],
    password: &[u8],
    operation: DexOperation,
    sequence: u64,
    output: *mut u8,
) -> u32 {
    let Some(seed) = decrypt_native_seed(file, password) else { return 0 };
    let secret = scalar(&seed, b"spend");
    let mut nonce = [0u8; 64];
    unsafe { random_fill(nonce.as_mut_ptr(), nonce.len()) };
    let signed = sign_with_sequence(&operation, sequence, secret, &nonce);
    let encoded = signed.encode();
    if encoded.len() > 512 { return 0; }
    unsafe { std::ptr::copy_nonoverlapping(encoded.as_ptr(), output, encoded.len()); }
    encoded.len() as u32
}

#[unsafe(no_mangle)]
pub extern "C" fn wallet_native_file_sign_message(
    file: *const u8,
    password: *const u8,
    password_length: usize,
    message: *const u8,
    message_length: usize,
    output: *mut u8,
) -> u32 {
    let file = unsafe { std::slice::from_raw_parts(file, 96) };
    let password = unsafe { std::slice::from_raw_parts(password, password_length) };
    let message = unsafe { std::slice::from_raw_parts(message, message_length) };
    let Some(seed) = decrypt_native_seed(file, password) else { return 0 };
    let secret = scalar(&seed, b"spend");
    let public = (secret * RISTRETTO_BASEPOINT_POINT).compress().to_bytes();
    let mut nonce = [0u8; 64];
    unsafe { random_fill(nonce.as_mut_ptr(), nonce.len()) };
    let r = Scalar::from_bytes_mod_order_wide(&nonce);
    let commitment = (r * RISTRETTO_BASEPOINT_POINT).compress().to_bytes();
    let mut hash = Sha512::new();
    hash.update(b"TENEBRA:wallet-message:v1");
    hash.update(tenebra::tsc1_tx_v2::NETWORK_ID);
    hash.update(public);
    hash.update(message);
    hash.update(commitment);
    let challenge = Scalar::from_hash(hash);
    let response = r + challenge * secret;
    let mut signature = [0u8; 64];
    signature[..32].copy_from_slice(&commitment);
    signature[32..].copy_from_slice(&response.to_bytes());
    unsafe { std::ptr::copy_nonoverlapping(signature.as_ptr(), output, signature.len()); }
    signature.len() as u32
}

#[unsafe(no_mangle)]
pub extern "C" fn wallet_alloc(size: usize) -> *mut u8 {
    let mut buffer = Vec::with_capacity(size);
    let pointer = buffer.as_mut_ptr();
    std::mem::forget(buffer);
    pointer
}

#[unsafe(no_mangle)]
pub extern "C" fn wallet_generate_seed(output: *mut u8) -> u32 {
    let mut seed = [0u8; 32];
    unsafe { random_fill(seed.as_mut_ptr(), seed.len()) };
    unsafe { std::ptr::copy_nonoverlapping(seed.as_ptr(), output, seed.len()) };
    seed.len() as u32
}

#[unsafe(no_mangle)]
pub extern "C" fn wallet_address(seed: *const u8, output: *mut u8) -> u32 {
    let mut bytes = [0u8; 32];
    unsafe { std::ptr::copy_nonoverlapping(seed, bytes.as_mut_ptr(), bytes.len()) };
    let text = address(&bytes);
    unsafe { std::ptr::copy_nonoverlapping(text.as_ptr(), output, text.len()) };
    text.len() as u32
}

#[unsafe(no_mangle)]
pub extern "C" fn wallet_seed_to_mnemonic(seed: *const u8, output: *mut u8) -> u32 {
    let seed = unsafe { std::slice::from_raw_parts(seed, 32) };
    let Ok(mnemonic) = Mnemonic::from_entropy_in(Language::English, seed) else {
        return 0;
    };
    let phrase = mnemonic.to_string();
    unsafe { std::ptr::copy_nonoverlapping(phrase.as_ptr(), output, phrase.len()) };
    phrase.len() as u32
}

#[unsafe(no_mangle)]
pub extern "C" fn wallet_mnemonic_to_seed(
    phrase: *const u8,
    phrase_length: usize,
    output: *mut u8,
) -> u32 {
    if phrase_length == 0 || phrase_length > 512 {
        return 0;
    }
    let phrase = unsafe { std::slice::from_raw_parts(phrase, phrase_length) };
    let Ok(phrase) = std::str::from_utf8(phrase) else {
        return 0;
    };
    let Ok(mnemonic) = Mnemonic::parse_in(Language::English, phrase) else {
        return 0;
    };
    let entropy = mnemonic.to_entropy();
    if entropy.len() != 32 {
        return 0;
    }
    unsafe { std::ptr::copy_nonoverlapping(entropy.as_ptr(), output, entropy.len()) };
    entropy.len() as u32
}

#[unsafe(no_mangle)]
pub extern "C" fn wallet_native_file_address(
    file: *const u8,
    password: *const u8,
    password_length: usize,
    output: *mut u8,
) -> u32 {
    let file = unsafe { std::slice::from_raw_parts(file, 96) };
    let password = unsafe { std::slice::from_raw_parts(password, password_length) };
    if &file[..8] != b"TSC1WLT1" {
        return 0;
    }
    let mut key = [0u8; 32];
    if Argon2::default().hash_password_into(password, &file[8..24], &mut key).is_err() {
        return 0;
    }
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    let seed = match cipher.decrypt(XNonce::from_slice(&file[24..48]), Payload { msg: &file[48..], aad: b"TSC1WLT1" }) {
        Ok(seed) if seed.len() == 32 => seed,
        _ => return 0,
    };
    let text = address(seed.as_slice().try_into().expect("seed length checked"));
    unsafe { std::ptr::copy_nonoverlapping(text.as_ptr(), output, text.len()) };
    text.len() as u32
}

#[unsafe(no_mangle)]
pub extern "C" fn wallet_native_file_sign_mining_challenge(
    file: *const u8,
    password: *const u8,
    password_length: usize,
    challenge: *const u8,
    challenge_length: usize,
    output: *mut u8,
) -> u32 {
    let file = unsafe { std::slice::from_raw_parts(file, 96) };
    let password = unsafe { std::slice::from_raw_parts(password, password_length) };
    let Some(seed) = decrypt_native_seed(file, password) else { return 0 };
    wallet_seed_sign_mining_challenge(seed.as_ptr(), challenge, challenge_length, output)
}

#[unsafe(no_mangle)]
pub extern "C" fn wallet_seed_sign_mining_challenge(seed: *const u8, challenge: *const u8, challenge_length: usize, output: *mut u8) -> u32 {
    if challenge_length == 0 || challenge_length > 128 { return 0; }
    let seed: [u8; 32] = unsafe { std::slice::from_raw_parts(seed, 32) }.try_into().unwrap();
    let challenge = unsafe { std::slice::from_raw_parts(challenge, challenge_length) };
    let mut nonce = [0u8; 64];
    unsafe { random_fill(nonce.as_mut_ptr(), nonce.len()) };
    let signature = tenebra::miner_auth::sign(scalar(&seed, b"spend"), challenge, &nonce);
    unsafe { std::ptr::copy_nonoverlapping(signature.as_ptr(), output, signature.len()); }
    signature.len() as u32
}

#[unsafe(no_mangle)]
pub extern "C" fn wallet_native_file_balance(
    file: *const u8,
    password: *const u8,
    password_length: usize,
    blocks: *const u8,
    blocks_length: usize,
    output: *mut u8,
) -> u32 {
    let file = unsafe { std::slice::from_raw_parts(file, 96) };
    let password = unsafe { std::slice::from_raw_parts(password, password_length) };
    let Some(seed) = decrypt_native_seed(file, password) else { return 0 };
    wallet_seed_balance(seed.as_ptr(), blocks, blocks_length, output)
}

#[unsafe(no_mangle)]
pub extern "C" fn wallet_seed_balance(seed: *const u8, blocks: *const u8, blocks_length: usize, output: *mut u8) -> u32 {
    let seed: [u8; 32] = unsafe { std::slice::from_raw_parts(seed, 32) }.try_into().unwrap();
    let Some(chain) = decode_wallet_chain(blocks, blocks_length) else { return 0 };
    let Ok(balance) = chain.wallet_balance_nox(&WalletSecrets::from_seed(&seed)) else { return 0 };
    unsafe { std::ptr::copy_nonoverlapping(balance.to_le_bytes().as_ptr(), output, 8) };
    1
}

fn decode_wallet_chain(blocks: *const u8, blocks_length: usize) -> Option<ChainV3> {
    let mut chain = ChainV3::from_pinned_genesis().ok()?;
    let bytes = unsafe { std::slice::from_raw_parts(blocks, blocks_length) };
    let mut cursor = 0;
    while cursor < bytes.len() {
        let length = u32::from_le_bytes(bytes.get(cursor..cursor + 4)?.try_into().ok()?) as usize;
        cursor += 4;
        if length == 0 || length > 64 * 1024 * 1024 { return None; }
        let block = BlockV3::decode(bytes.get(cursor..cursor + length)?).ok()?;
        chain.append_wallet_state(block).ok()?;
        cursor += length;
    }
    Some(chain)
}

fn decode_wallet_blocks(blocks: *const u8, blocks_length: usize) -> Option<Vec<BlockV3>> {
    let bytes = unsafe { std::slice::from_raw_parts(blocks, blocks_length) };
    let mut cursor = 0;
    let mut decoded = Vec::new();
    while cursor < bytes.len() {
        let length = u32::from_le_bytes(bytes.get(cursor..cursor + 4)?.try_into().ok()?) as usize;
        cursor += 4;
        if length == 0 || length > 64 * 1024 * 1024 { return None; }
        decoded.push(BlockV3::decode(bytes.get(cursor..cursor + length)?).ok()?);
        cursor += length;
    }
    Some(decoded)
}

fn append_wallet_history_record(
    wallet: &WalletSecrets,
    owned: &std::collections::HashMap<[u8; 32], u64>,
    transaction: &tenebra::tsc1_tx_v2::Transaction,
    height: u64,
    timestamp: u64,
    output: *mut u8,
    count: &mut u32,
) -> bool {
    if *count >= 4096 {
        return false;
    }
    let spent: u64 = transaction.inputs.iter().filter_map(|input| owned.get(&input.key_image)).sum();
    let received: u64 = transaction.outputs.iter().enumerate()
        .filter(|(_, funded)| funded.amount.asset_id == tenebra::assets::TNB_ASSET_ID)
        .filter_map(|(index, funded)| wallet.scan_funded_output(funded, index as u64))
        .map(|recovered| recovered.amount_nox).sum();
    if spent == 0 && received == 0 {
        return false;
    }
    let Ok(txid) = transaction.txid() else { return true };
    let amount = if spent > 0 { spent.saturating_sub(received).saturating_sub(transaction.fee_nox) } else { received };
    let mut record = [0u8; 64];
    record[..8].copy_from_slice(&height.to_le_bytes());
    record[8..16].copy_from_slice(&timestamp.to_le_bytes());
    record[16..24].copy_from_slice(&amount.to_le_bytes());
    record[24..56].copy_from_slice(&txid);
    record[56..64].copy_from_slice(&u64::from(spent > 0).to_le_bytes());
    unsafe { std::ptr::copy_nonoverlapping(record.as_ptr(), output.add(4 + *count as usize * 64), 64); }
    *count += 1;
    false
}

#[unsafe(no_mangle)]
pub extern "C" fn wallet_free(pointer: *mut u8, size: usize) {
    if size > 0 { unsafe { drop(Vec::from_raw_parts(pointer, 0, size)); } }
}

#[unsafe(no_mangle)]
pub extern "C" fn wallet_native_file_seed(file: *const u8, password: *const u8, password_length: usize, output: *mut u8) -> u32 {
    let file = unsafe { std::slice::from_raw_parts(file, 96) };
    let password = unsafe { std::slice::from_raw_parts(password, password_length) };
    let Some(mut seed) = decrypt_native_seed(file, password) else { return 0 };
    unsafe { std::ptr::copy_nonoverlapping(seed.as_ptr(), output, 32); }
    seed.fill(0);
    32
}

// V2 history: height, timestamp, amount, txid, direction (0 receive / 1 send).
// Ownership is determined from key images, so change is not an incoming payment.
#[unsafe(no_mangle)]
pub extern "C" fn wallet_seed_history_v2(seed: *const u8, blocks: *const u8, blocks_length: usize, output: *mut u8) -> u32 {
    let seed: [u8; 32] = unsafe { std::slice::from_raw_parts(seed, 32) }.try_into().unwrap();
    let Some(blocks) = decode_wallet_blocks(blocks, blocks_length) else { return u32::MAX };
    let Ok(genesis) = ChainV3::from_pinned_genesis() else { return u32::MAX };
    let wallet = WalletSecrets::from_seed(&seed);
    let mut owned = std::collections::HashMap::new();
    let mut remember = |funded: &tenebra::tsc1_funded_output::FundedOutput, index| {
        if funded.amount.asset_id != tenebra::assets::TNB_ASSET_ID { return; }
        if let Some(recovered) = wallet.scan_funded_output(funded, index) {
            if let Some(secret) = Option::<Scalar>::from(Scalar::from_canonical_bytes(recovered.one_time_spend)) {
                owned.insert(tenebra::tsc1_tx_v2::key_image_for_secret(secret), recovered.amount_nox);
            }
        }
    };
    remember(&genesis.rewards().genesis_block().reward_output, 0);
    for block in &blocks {
        remember(&block.reward.reward_output, 0);
        if let Some(funded) = &block.miner_fee_output { remember(funded, 0); }
        if let Some(funded) = &block.treasury_fee_output { remember(funded, 0); }
        for signed in &block.asset_transactions {
            if let Some(fee) = &signed.creation_fee {
                for (index, funded) in fee.outputs.iter().enumerate() { remember(funded, index as u64); }
            }
        }
        for tx in &block.transactions {
            for (index, funded) in tx.outputs.iter().enumerate() { remember(funded, index as u64); }
        }
    }
    drop(remember);
    let mut count = 0u32;
    for block in blocks.iter().rev() {
        for tx in block.transactions.iter().rev() {
            if append_wallet_history_record(&wallet, &owned, tx, block.reward.height, block.reward.timestamp, output, &mut count) { return u32::MAX; }
            if count == 4096 { break; }
        }
        for signed in block.asset_transactions.iter().rev() {
            if let Some(fee) = &signed.creation_fee {
                if append_wallet_history_record(&wallet, &owned, fee, block.reward.height, block.reward.timestamp, output, &mut count) { return u32::MAX; }
                if count == 4096 { break; }
            }
        }
        if count == 4096 { break; }
    }
    unsafe { std::ptr::copy_nonoverlapping(count.to_le_bytes().as_ptr(), output, 4); }
    count
}

#[unsafe(no_mangle)]
pub extern "C" fn wallet_native_file_rewards(
    file: *const u8,
    password: *const u8,
    password_length: usize,
    blocks: *const u8,
    blocks_length: usize,
    output: *mut u8,
) -> u32 {
    let file = unsafe { std::slice::from_raw_parts(file, 96) };
    let password = unsafe { std::slice::from_raw_parts(password, password_length) };
    let Some(seed) = decrypt_native_seed(file, password) else { return 0 };
    wallet_seed_rewards(seed.as_ptr(), blocks, blocks_length, output)
}

#[unsafe(no_mangle)]
pub extern "C" fn wallet_seed_rewards(seed: *const u8, blocks: *const u8, blocks_length: usize, output: *mut u8) -> u32 {
    let seed: [u8; 32] = unsafe { std::slice::from_raw_parts(seed, 32) }.try_into().unwrap();
    let Some(blocks) = decode_wallet_blocks(blocks, blocks_length) else { return u32::MAX };
    let wallet = WalletSecrets::from_seed(&seed);
    let mut count = 0u32;
    for block in blocks.iter().rev() {
        if let Some(recovered) = wallet.scan_funded_output(&block.reward.reward_output, 0) {
            let record = [block.reward.height.to_le_bytes(), block.reward.timestamp.to_le_bytes(), recovered.amount_nox.to_le_bytes()].concat();
            unsafe { std::ptr::copy_nonoverlapping(record.as_ptr(), output.add(4 + count as usize * 24), 24); }
            count += 1;
            if count == 4096 { break; }
        }
    }
    unsafe { std::ptr::copy_nonoverlapping(count.to_le_bytes().as_ptr(), output, 4); }
    count
}

#[unsafe(no_mangle)]
pub extern "C" fn wallet_native_file_history(
    file: *const u8,
    password: *const u8,
    password_length: usize,
    blocks: *const u8,
    blocks_length: usize,
    output: *mut u8,
) -> u32 {
    let file = unsafe { std::slice::from_raw_parts(file, 96) };
    let password = unsafe { std::slice::from_raw_parts(password, password_length) };
    if &file[..8] != b"TSC1WLT1" { return 0; }
    let mut key = [0u8; 32];
    if Argon2::default().hash_password_into(password, &file[8..24], &mut key).is_err() { return 0; }
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    let seed = match cipher.decrypt(XNonce::from_slice(&file[24..48]), Payload { msg: &file[48..], aad: b"TSC1WLT1" }) {
        Ok(seed) if seed.len() == 32 => seed,
        _ => return 0,
    };
    let seed: [u8; 32] = match seed.as_slice().try_into() { Ok(seed) => seed, Err(_) => return 0 };
    let wallet = WalletSecrets::from_seed(&seed);
    let block_bytes = unsafe { std::slice::from_raw_parts(blocks, blocks_length) };
    let mut cursor = 0usize;
    let mut count = 0u32;
    unsafe { std::ptr::copy_nonoverlapping(count.to_le_bytes().as_ptr(), output, 4); }
    while cursor < block_bytes.len() && count < 4096 {
        if block_bytes.len() - cursor < 4 { return 0; }
        let length = u32::from_le_bytes(match block_bytes[cursor..cursor + 4].try_into() { Ok(value) => value, Err(_) => return 0 }) as usize;
        cursor += 4;
        if length == 0 || length > 64 * 1024 * 1024 || length > block_bytes.len() - cursor { return 0; }
        let block = match BlockV3::decode(&block_bytes[cursor..cursor + length]) { Ok(block) => block, Err(_) => return 0 };
        for transaction in &block.transactions {
            let txid = match transaction.txid() { Ok(txid) => txid, Err(_) => return 0 };
            for (index, funded_output) in transaction.outputs.iter().enumerate() {
                if let Some(recovered) = wallet.scan_funded_output(funded_output, index as u64) {
                    let mut record = [0u8; 56];
                    record[..8].copy_from_slice(&block.reward.height.to_le_bytes());
                    record[8..16].copy_from_slice(&block.reward.timestamp.to_le_bytes());
                    record[16..24].copy_from_slice(&recovered.amount_nox.to_le_bytes());
                    record[24..56].copy_from_slice(&txid);
                    let offset = 4 + count as usize * 56;
                    unsafe { std::ptr::copy_nonoverlapping(record.as_ptr(), output.add(offset), 56); }
                    count += 1;
                    if count == 4096 { break; }
                }
            }
            if count == 4096 { break; }
        }
        cursor += length;
    }
    unsafe { std::ptr::copy_nonoverlapping(count.to_le_bytes().as_ptr(), output, 4); }
    count
}

#[unsafe(no_mangle)]
pub extern "C" fn wallet_native_file_sign_transfer(
    file: *const u8, password: *const u8, password_length: usize,
    blocks: *const u8, blocks_length: usize,
    recipient: *const u8, recipient_length: usize,
    amount_nox: u64, fee_nox: u64, output: *mut u8,
) -> u32 {
    let file = unsafe { std::slice::from_raw_parts(file, 96) };
    let password = unsafe { std::slice::from_raw_parts(password, password_length) };
    let Some(seed) = decrypt_native_seed(file, password) else { return 0 };
    wallet_seed_sign_transfer(seed.as_ptr(), blocks, blocks_length, recipient, recipient_length, amount_nox, fee_nox, output)
}

#[unsafe(no_mangle)]
pub extern "C" fn wallet_seed_sign_transfer(seed: *const u8, blocks: *const u8, blocks_length: usize, recipient: *const u8, recipient_length: usize, amount_nox: u64, fee_nox: u64, output: *mut u8) -> u32 {
    let seed: [u8; 32] = unsafe { std::slice::from_raw_parts(seed, 32) }.try_into().unwrap();
    let recipient_text = match std::str::from_utf8(unsafe { std::slice::from_raw_parts(recipient, recipient_length) }) { Ok(text) => text, Err(_) => return 0 };
    let recipient = match Address::parse(recipient_text) { Ok(address) => address, Err(_) => return 0 };
    let mut chain = match ChainV3::from_pinned_genesis() { Ok(chain) => chain, Err(_) => return 0 };
    let block_bytes = unsafe { std::slice::from_raw_parts(blocks, blocks_length) };
    let mut cursor = 0usize;
    while cursor < block_bytes.len() {
        if block_bytes.len() - cursor < 4 { return 0; }
        let length = u32::from_le_bytes(block_bytes[cursor..cursor + 4].try_into().unwrap()) as usize;
        cursor += 4;
        if length == 0 || length > 64 * 1024 * 1024 || length > block_bytes.len() - cursor { return 0; }
        let block = match BlockV3::decode(&block_bytes[cursor..cursor + length]) { Ok(block) => block, Err(_) => return 0 };
        if chain.append_wallet_state(block).is_err() { return 0; }
        cursor += length;
    }
    let wallet = WalletSecrets::from_seed(&seed);
    let transaction = match create_signed_transfer(&chain, &wallet, &recipient, amount_nox, fee_nox) { Ok(transaction) => transaction, Err(_) => return 0 };
    let encoded = match transaction.encode() { Ok(encoded) if encoded.len() <= 512 * 1024 => encoded, _ => return 0 };
    unsafe { std::ptr::copy_nonoverlapping(encoded.as_ptr(), output, encoded.len()); }
    encoded.len() as u32
}

#[unsafe(no_mangle)]
pub extern "C" fn wallet_seed_sign_asset_create(
    seed: *const u8,
    blocks: *const u8,
    blocks_length: usize,
    name: *const u8,
    name_length: usize,
    symbol: *const u8,
    symbol_length: usize,
    decimals: u8,
    max_supply: u64,
    initial_supply: u64,
    output: *mut u8,
) -> u32 {
    let seed: [u8; 32] = unsafe { std::slice::from_raw_parts(seed, 32) }.try_into().unwrap();
    let name = match std::str::from_utf8(unsafe { std::slice::from_raw_parts(name, name_length) }) { Ok(name) => name, Err(_) => return 0 };
    let symbol = match std::str::from_utf8(unsafe { std::slice::from_raw_parts(symbol, symbol_length) }) { Ok(symbol) => symbol, Err(_) => return 0 };
    let secret = scalar(&seed, b"spend");
    let issuer = (secret * RISTRETTO_BASEPOINT_POINT).compress().to_bytes();
    let mut nonce = [0u8; 64];
    unsafe { random_fill(nonce.as_mut_ptr(), nonce.len()); }
    let transaction = AssetTransaction::Create {
        issuer,
        nonce: u64::from_le_bytes(nonce[..8].try_into().unwrap()),
        name: name.to_string(),
        symbol: symbol.to_string(),
        decimals,
        max_supply,
        initial_supply,
    };
    let mut signed = match sign_issuer(&transaction, secret, &nonce) { Ok(signed) => signed, Err(_) => return 0 };
    let chain = match decode_wallet_chain(blocks, blocks_length) { Some(chain) => chain, None => return 0 };
    let fee = match create_signed_asset_creation_fee_for_asset(&chain, &WalletSecrets::from_seed(&seed), &transaction) { Ok(fee) => fee, Err(_) => return 0 };
    signed.creation_fee = Some(fee);
    let encoded = signed.encode().unwrap_or_default();
    if encoded.len() > 512 * 1024 { return 0; }
    unsafe { std::ptr::copy_nonoverlapping(encoded.as_ptr(), output, encoded.len()); }
    encoded.len() as u32
}

#[unsafe(no_mangle)]
pub extern "C" fn wallet_seed_sign_asset_create_with_options(
    seed: *const u8,
    blocks: *const u8,
    blocks_length: usize,
    name: *const u8,
    name_length: usize,
    symbol: *const u8,
    symbol_length: usize,
    decimals: u8,
    max_supply: u64,
    initial_supply: u64,
    mintable: u8,
    burnable: u8,
    issuer_fee_bps: u16,
    asset_kind: u8,
    issuer_treasury: *const u8,
    issuer_treasury_length: usize,
    output: *mut u8,
) -> u32 {
    let seed: [u8; 32] = unsafe { std::slice::from_raw_parts(seed, 32) }.try_into().unwrap();
    let name = match std::str::from_utf8(unsafe { std::slice::from_raw_parts(name, name_length) }) { Ok(name) => name, Err(_) => return 0 };
    let symbol = match std::str::from_utf8(unsafe { std::slice::from_raw_parts(symbol, symbol_length) }) { Ok(symbol) => symbol, Err(_) => return 0 };
    if mintable > 1 || burnable > 1 || asset_kind > 1 { return 0; }
    let treasury = if issuer_fee_bps == 0 { None } else {
        let text = match std::str::from_utf8(unsafe { std::slice::from_raw_parts(issuer_treasury, issuer_treasury_length) }) { Ok(text) => text, Err(_) => return 0 };
        match Address::parse(text) { Ok(address) => Some(address), Err(_) => return 0 }
    };
    let secret = scalar(&seed, b"spend");
    let issuer = (secret * RISTRETTO_BASEPOINT_POINT).compress().to_bytes();
    let mut nonce = [0u8; 64];
    unsafe { random_fill(nonce.as_mut_ptr(), nonce.len()); }
    let transaction = AssetTransaction::CreateWithOptions {
        issuer,
        nonce: u64::from_le_bytes(nonce[..8].try_into().unwrap()),
        name: name.to_string(),
        symbol: symbol.to_string(),
        decimals,
        max_supply,
        initial_supply,
        mintable: mintable == 1,
        burnable: burnable == 1,
        issuer_fee_bps,
        issuer_treasury: treasury,
        kind: if asset_kind == 1 { AssetKind::Nft } else { AssetKind::Fungible },
    };
    let mut signed = match sign_issuer(&transaction, secret, &nonce) { Ok(signed) => signed, Err(_) => return 0 };
    let chain = match decode_wallet_chain(blocks, blocks_length) { Some(chain) => chain, None => return 0 };
    let fee = match create_signed_asset_creation_fee_for_asset(&chain, &WalletSecrets::from_seed(&seed), &transaction) { Ok(fee) => fee, Err(_) => return 0 };
    signed.creation_fee = Some(fee);
    let encoded = signed.encode().unwrap_or_default();
    if encoded.len() > 512 * 1024 { return 0; }
    unsafe { std::ptr::copy_nonoverlapping(encoded.as_ptr(), output, encoded.len()); }
    encoded.len() as u32
}

#[unsafe(no_mangle)]
pub extern "C" fn wallet_seed_sign_asset_admin(
    seed: *const u8,
    operation: u8,
    asset_id: *const u8,
    amount: u64,
    new_max_supply: u64,
    mintable: u8,
    burnable: u8,
    issuer_fee_bps: u16,
    issuer_treasury: *const u8,
    issuer_treasury_length: usize,
    output: *mut u8,
) -> u32 {
    let seed: [u8; 32] = unsafe { std::slice::from_raw_parts(seed, 32) }.try_into().unwrap();
    let asset_id: [u8; 32] = unsafe { std::slice::from_raw_parts(asset_id, 32) }.try_into().unwrap();
    if mintable > 1 || burnable > 1 { return 0; }
    let treasury = if issuer_fee_bps == 0 { None } else {
        let text = match std::str::from_utf8(unsafe { std::slice::from_raw_parts(issuer_treasury, issuer_treasury_length) }) { Ok(text) => text, Err(_) => return 0 };
        match Address::parse(text) { Ok(address) => Some(address), Err(_) => return 0 }
    };
    let secret = scalar(&seed, b"spend");
    let issuer = (secret * RISTRETTO_BASEPOINT_POINT).compress().to_bytes();
    let transaction = match operation {
        0 => AssetTransaction::Mint { asset_id, issuer, amount },
        1 => AssetTransaction::Burn { asset_id, from: issuer, amount },
        2 => AssetTransaction::IncreaseMaxSupply { asset_id, issuer, new_max_supply },
        3 => AssetTransaction::UpdateOptions { asset_id, issuer, mintable: mintable == 1, burnable: burnable == 1, issuer_fee_bps, issuer_treasury: treasury },
        _ => return 0,
    };
    let mut nonce = [0u8; 64];
    unsafe { random_fill(nonce.as_mut_ptr(), nonce.len()); }
    let signed = match sign_issuer(&transaction, secret, &nonce) { Ok(signed) => signed, Err(_) => return 0 };
    let encoded = signed.encode().unwrap_or_default();
    if encoded.len() > 8192 { return 0; }
    unsafe { std::ptr::copy_nonoverlapping(encoded.as_ptr(), output, encoded.len()); }
    encoded.len() as u32
}

#[unsafe(no_mangle)]
pub extern "C" fn wallet_seed_sign_asset_transfer(
    seed: *const u8,
    blocks: *const u8,
    blocks_length: usize,
    asset_id: *const u8,
    recipient: *const u8,
    recipient_length: usize,
    amount: u64,
    output: *mut u8,
) -> u32 {
    let seed: [u8; 32] = unsafe { std::slice::from_raw_parts(seed, 32) }.try_into().unwrap();
    let chain = match decode_wallet_chain(blocks, blocks_length) { Some(chain) => chain, None => return 0 };
    let asset_id: [u8; 32] = unsafe { std::slice::from_raw_parts(asset_id, 32) }.try_into().unwrap();
    let recipient_text = match std::str::from_utf8(unsafe { std::slice::from_raw_parts(recipient, recipient_length) }) { Ok(text) => text, Err(_) => return 0 };
    let recipient = match Address::parse(recipient_text) { Ok(address) => address, Err(_) => return 0 };
    let secret = scalar(&seed, b"spend");
    let from = (secret * RISTRETTO_BASEPOINT_POINT).compress().to_bytes();
    let mut nonce = [0u8; 64];
    unsafe { random_fill(nonce.as_mut_ptr(), nonce.len()); }
    let transaction = AssetTransaction::Transfer { asset_id, from, to: recipient.spend, amount };
    let asset = match chain.assets().registry.get(&asset_id) { Some(asset) => asset, None => return 0 };
    let fee_nox = match tenebra::assets::global_asset_transfer_fee_nox(amount, asset.decimals) { Ok(fee) => fee, Err(_) => return 0 };
    let issuer_fee_nox = if asset.issuer_fee_bps == 0 { 0 } else { match tenebra::assets::transfer_fee_nox(amount, asset.decimals, asset.issuer_fee_bps) { Ok(fee) => fee, Err(_) => return 0 } };
    let mut signed = match sign_issuer(&transaction, secret, &nonce) { Ok(signed) => signed, Err(_) => return 0 };
    let asset_txid = match transaction.txid() { Ok(txid) => txid, Err(_) => return 0 };
    let fee = match create_signed_asset_transfer_fee(&chain, &WalletSecrets::from_seed(&seed), asset_txid, fee_nox, issuer_fee_nox, asset.issuer_treasury) { Ok(fee) => fee, Err(_) => return 0 };
    signed.creation_fee = Some(fee);
    let encoded = signed.encode().unwrap_or_default();
    if encoded.len() > 512 * 1024 { return 0; }
    unsafe { std::ptr::copy_nonoverlapping(encoded.as_ptr(), output, encoded.len()); }
    encoded.len() as u32
}

#[unsafe(no_mangle)]
pub extern "C" fn wallet_native_file_sign_dex_create_pool(
    file: *const u8,
    password: *const u8,
    password_length: usize,
    asset_a: *const u8,
    asset_b: *const u8,
    amount_a: u64,
    amount_b: u64,
    sequence: u64,
    output: *mut u8,
) -> u32 {
    let file = unsafe { std::slice::from_raw_parts(file, 96) };
    let password = unsafe { std::slice::from_raw_parts(password, password_length) };
    let asset_a: [u8; 32] = unsafe { std::slice::from_raw_parts(asset_a, 32) }.try_into().unwrap();
    let asset_b: [u8; 32] = unsafe { std::slice::from_raw_parts(asset_b, 32) }.try_into().unwrap();
    let Some(seed) = decrypt_native_seed(file, password) else { return 0 };
    let provider = (scalar(&seed, b"spend") * RISTRETTO_BASEPOINT_POINT).compress().to_bytes();
    write_signed_dex(
        file,
        password,
        DexOperation::CreatePool {
            asset_a,
            asset_b,
            amount_a: amount_a as u128,
            amount_b: amount_b as u128,
            provider,
        },
        sequence,
        output,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn wallet_native_file_sign_dex_swap(
    file: *const u8,
    password: *const u8,
    password_length: usize,
    pool_id: *const u8,
    input_asset: *const u8,
    input_amount: u64,
    min_output: u64,
    sequence: u64,
    output: *mut u8,
) -> u32 {
    let file = unsafe { std::slice::from_raw_parts(file, 96) };
    let password = unsafe { std::slice::from_raw_parts(password, password_length) };
    let pool_id: [u8; 32] = unsafe { std::slice::from_raw_parts(pool_id, 32) }.try_into().unwrap();
    let input_asset: [u8; 32] = unsafe { std::slice::from_raw_parts(input_asset, 32) }.try_into().unwrap();
    let Some(seed) = decrypt_native_seed(file, password) else { return 0 };
    let trader = (scalar(&seed, b"spend") * RISTRETTO_BASEPOINT_POINT).compress().to_bytes();
    write_signed_dex(
        file,
        password,
        DexOperation::Swap {
            pool_id,
            input_asset,
            input_amount: input_amount as u128,
            min_output: min_output as u128,
            trader,
        },
        sequence,
        output,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn wallet_native_file_sign_dex_remove_liquidity(
    file: *const u8,
    password: *const u8,
    password_length: usize,
    pool_id: *const u8,
    share_bps: u16,
    sequence: u64,
    output: *mut u8,
) -> u32 {
    let file = unsafe { std::slice::from_raw_parts(file, 96) };
    let password = unsafe { std::slice::from_raw_parts(password, password_length) };
    let pool_id: [u8; 32] = unsafe { std::slice::from_raw_parts(pool_id, 32) }.try_into().unwrap();
    let Some(seed) = decrypt_native_seed(file, password) else { return 0 };
    let provider = (scalar(&seed, b"spend") * RISTRETTO_BASEPOINT_POINT).compress().to_bytes();
    write_signed_dex(
        file,
        password,
        DexOperation::RemoveLiquidity { pool_id, share_bps, provider },
        sequence,
        output,
    )
}
