//! Snapshot exchange and bounded transaction submission for the v3 devnet.

use crate::assets::SignedAssetTransaction;
use crate::network::pinned_genesis;
use crate::tsc1_chain_v2::Chain;
use crate::tsc1_chain_v3::{
    BlockV3, ChainV3, FINALITY_DEPTH, MAX_BLOCK_BYTES, load_blocks, persist_block,
};
use crate::tsc1_pending_v3::{MAX_TX_BYTES, accept_asset, accept_transaction, remove_included};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const MAGIC: &[u8; 8] = crate::network::PEER_MAGIC;
const MAX_SNAPSHOT: usize = 64 * 1024 * 1024;
const MAX_CONNECTIONS: usize = 64;
const MAX_CONNECTIONS_PER_IP: usize = 128;
const MAX_TRACKED_IPS: usize = 1024;
const CONNECTION_WINDOW: Duration = Duration::from_secs(60);
const AUTH_TAG: &[u8; 1] = b"A";
const AUTH_OK: &[u8; 2] = b"OK";

pub(crate) struct ConnectionAdmission {
    attempts: Mutex<HashMap<IpAddr, (Instant, usize)>>,
}

impl ConnectionAdmission {
    pub(crate) fn new() -> Self {
        Self {
            attempts: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn allow(&self, ip: IpAddr) -> bool {
        let Ok(mut attempts) = self.attempts.lock() else {
            return false;
        };
        let now = Instant::now();
        if let Some((started, count)) = attempts.get_mut(&ip) {
            if now.duration_since(*started) >= CONNECTION_WINDOW {
                *started = now;
                *count = 1;
                return true;
            }
            if *count >= MAX_CONNECTIONS_PER_IP {
                return false;
            }
            *count += 1;
            return true;
        }
        if attempts.len() >= MAX_TRACKED_IPS {
            attempts.retain(|_, (started, _)| now.duration_since(*started) < CONNECTION_WINDOW);
        }
        if attempts.len() >= MAX_TRACKED_IPS {
            return false;
        }
        attempts.insert(ip, (now, 1));
        true
    }
}

pub(crate) fn configured_peers() -> Result<Vec<String>, &'static str> {
    let mut peers = Vec::new();
    for variable in [
        crate::network::variable("PEERS"),
        crate::network::variable("SEEDS"),
    ] {
        for peer in env::var(variable)
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|peer| !peer.is_empty())
        {
            if !peers.iter().any(|known| known == peer) {
                peers.push(peer.to_owned());
            }
        }
    }
    if peers.len() > 16 {
        return Err("too many configured v3 peers or seeds");
    }
    Ok(peers)
}

fn peer_signing_key() -> Result<SigningKey, Box<dyn std::error::Error>> {
    let text = env::var("TSC1_DEVNET_V3_PEER_KEY")?;
    let bytes: [u8; 32] = hex::decode(text.trim())?
        .try_into()
        .map_err(|_| "peer key must be 32 bytes")?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn allowed_peer_keys() -> Result<Vec<VerifyingKey>, Box<dyn std::error::Error>> {
    let mut keys = Vec::new();
    for text in env::var("TSC1_DEVNET_V3_PEER_KEYS")?
        .split(',')
        .map(str::trim)
        .filter(|text| !text.is_empty())
    {
        let bytes: [u8; 32] = hex::decode(text)?
            .try_into()
            .map_err(|_| "invalid peer public key")?;
        keys.push(VerifyingKey::from_bytes(&bytes)?);
    }
    if keys.is_empty() {
        return Err("peer allowlist is empty".into());
    }
    Ok(keys)
}

fn authenticate_incoming(mut stream: &TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    let server_key = peer_signing_key()?;
    let allowed = allowed_peer_keys()?;
    let mut tag = [0; 1];
    stream.read_exact(&mut tag)?;
    if &tag != AUTH_TAG {
        return Err("peer authentication required".into());
    }
    let mut client_public = [0; 32];
    let mut client_nonce = [0; 32];
    stream.read_exact(&mut client_public)?;
    stream.read_exact(&mut client_nonce)?;
    let client_key = VerifyingKey::from_bytes(&client_public)?;
    if !allowed.iter().any(|key| key == &client_key) {
        return Err("peer key is not allowlisted".into());
    }
    let mut client_signature = [0; 64];
    stream.read_exact(&mut client_signature)?;
    let mut client_message = b"TSC1P3:client-auth:v1".to_vec();
    client_message.extend_from_slice(&client_public);
    client_message.extend_from_slice(&client_nonce);
    client_key.verify(&client_message, &Signature::from_bytes(&client_signature))?;
    let mut server_nonce = [0; 32];
    getrandom::getrandom(&mut server_nonce)?;
    let mut server_message = b"TSC1P3:server-auth:v1".to_vec();
    server_message.extend_from_slice(&client_public);
    server_message.extend_from_slice(&client_nonce);
    server_message.extend_from_slice(server_key.verifying_key().as_bytes());
    server_message.extend_from_slice(&server_nonce);
    let signature = server_key.sign(&server_message);
    stream.write_all(AUTH_OK)?;
    stream.write_all(server_key.verifying_key().as_bytes())?;
    stream.write_all(&server_nonce)?;
    stream.write_all(&signature.to_bytes())?;
    Ok(())
}

fn authenticate_outgoing(mut stream: TcpStream) -> Result<TcpStream, Box<dyn std::error::Error>> {
    let client_key = peer_signing_key()?;
    let allowed = allowed_peer_keys()?;
    let client_public = client_key.verifying_key().to_bytes();
    let mut client_nonce = [0; 32];
    getrandom::getrandom(&mut client_nonce)?;
    let mut message = b"TSC1P3:client-auth:v1".to_vec();
    message.extend_from_slice(&client_public);
    message.extend_from_slice(&client_nonce);
    stream.write_all(AUTH_TAG)?;
    stream.write_all(&client_public)?;
    stream.write_all(&client_nonce)?;
    stream.write_all(&client_key.sign(&message).to_bytes())?;
    let mut ok = [0; 2];
    stream.read_exact(&mut ok)?;
    if &ok != AUTH_OK {
        return Err("peer authentication rejected".into());
    }
    let mut server_public = [0; 32];
    let mut server_nonce = [0; 32];
    let mut signature = [0; 64];
    stream.read_exact(&mut server_public)?;
    stream.read_exact(&mut server_nonce)?;
    stream.read_exact(&mut signature)?;
    let server_key = VerifyingKey::from_bytes(&server_public)?;
    if !allowed.iter().any(|key| key == &server_key) {
        return Err("server key is not allowlisted".into());
    }
    let mut server_message = b"TSC1P3:server-auth:v1".to_vec();
    server_message.extend_from_slice(&client_public);
    server_message.extend_from_slice(&client_nonce);
    server_message.extend_from_slice(&server_public);
    server_message.extend_from_slice(&server_nonce);
    server_key.verify(&server_message, &Signature::from_bytes(&signature))?;
    Ok(stream)
}

fn serve_connection(
    stream: TcpStream,
    blocks_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    serve_connection_with_peers(stream, blocks_dir, pinned_genesis()?, configured_peers()?)
}

fn serve_authenticated_connection(
    stream: TcpStream,
    blocks_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    if crate::network::IS_MAINNET {
        let mut magic = [0; 8];
        let mut genesis = [0; 32];
        (&stream).read_exact(&mut magic)?;
        (&stream).read_exact(&mut genesis)?;
        if &magic != MAGIC || genesis != pinned_genesis()?.genesis_hash() {
            return Err("wrong mainnet handshake".into());
        }
        (&stream).write_all(MAGIC)?;
    } else {
        authenticate_incoming(&stream)?;
    }
    serve_connection(stream, blocks_dir)
}

#[cfg(test)]
pub(crate) fn serve_connection_with_genesis(
    stream: TcpStream,
    blocks_dir: &Path,
    genesis: Chain,
) -> Result<(), Box<dyn std::error::Error>> {
    serve_connection_with_peers(stream, blocks_dir, genesis, Vec::new())
}

pub(crate) fn serve_connection_with_peers(
    mut stream: TcpStream,
    blocks_dir: &Path,
    genesis: Chain,
    peers: Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let mut request = [0u8; 1];
    stream.read_exact(&mut request)?;
    match request[0] {
        b'H' => {
            let chain = load_blocks(blocks_dir, genesis)?;
            let pending = crate::tsc1_pending_v3::load_pending(blocks_dir, &chain)?.len() as u32;
            stream.write_all(MAGIC)?;
            stream.write_all(&chain.height().to_le_bytes())?;
            stream.write_all(&chain.tip_hash())?;
            stream.write_all(&0u64.to_le_bytes())?;
            stream.write_all(&pending.to_le_bytes())?;
            Ok(())
        }
        b'S' => {
            let snapshot = load_blocks(blocks_dir, genesis)?.encode()?;
            if snapshot.len() > MAX_SNAPSHOT {
                return Err("v3 snapshot exceeds protocol limit".into());
            }
            stream.write_all(MAGIC)?;
            stream.write_all(&(snapshot.len() as u32).to_le_bytes())?;
            stream.write_all(&snapshot)?;
            Ok(())
        }
        b'T' => {
            let mut length = [0u8; 4];
            stream.read_exact(&mut length)?;
            let length = u32::from_le_bytes(length) as usize;
            if length == 0 || length > MAX_TX_BYTES {
                return Err("invalid submitted transaction length".into());
            }
            let mut bytes = vec![0; length];
            stream.read_exact(&mut bytes)?;
            let result = load_blocks(blocks_dir, genesis)
                .and_then(|chain| accept_transaction(blocks_dir, &chain, &bytes));
            stream.write_all(MAGIC)?;
            match result {
                Ok(txid) => {
                    stream.write_all(&[1])?;
                    stream.write_all(&txid)?;
                    if !peers.is_empty() {
                        thread::spawn(move || {
                            for peer in peers {
                                let _ = submit(&peer, &bytes);
                            }
                        });
                    }
                    Ok(())
                }
                Err(error) => {
                    stream.write_all(&[0])?;
                    stream.write_all(&[0; 32])?;
                    Err(error)
                }
            }
        }
        b'A' => {
            let mut length = [0u8; 4];
            stream.read_exact(&mut length)?;
            let length = u32::from_le_bytes(length) as usize;
            if length == 0 || length > 512 * 1024 {
                return Err("invalid submitted asset length".into());
            }
            let mut bytes = vec![0; length];
            stream.read_exact(&mut bytes)?;
            let signed = SignedAssetTransaction::decode(&bytes)?;
            signed.verify()?;
            let txid = signed.transaction.txid()?;
            accept_asset(blocks_dir, &signed)?;
            stream.write_all(MAGIC)?;
            stream.write_all(&[1])?;
            stream.write_all(&txid)?;
            Ok(())
        }
        b'B' => {
            let mut length = [0u8; 4];
            stream.read_exact(&mut length)?;
            let length = u32::from_le_bytes(length) as usize;
            if length == 0 || length > MAX_BLOCK_BYTES {
                return Err("invalid relayed block length".into());
            }
            let mut bytes = vec![0; length];
            stream.read_exact(&mut bytes)?;
            let result = (|| -> Result<_, Box<dyn std::error::Error>> {
                let mut chain = load_blocks(blocks_dir, genesis)?;
                let block = BlockV3::decode(&bytes)?;
                chain.append(block.clone())?;
                persist_block(blocks_dir, &block)?;
                if let Err(error) = remove_included(blocks_dir, &block.transactions) {
                    eprintln!("v3 pending cleanup failed after block import: {error}");
                }
                Ok(chain.tip_hash())
            })();
            stream.write_all(MAGIC)?;
            match result {
                Ok(hash) => {
                    stream.write_all(&[1])?;
                    stream.write_all(&hash)?;
                    Ok(())
                }
                Err(error) => {
                    stream.write_all(&[0])?;
                    stream.write_all(&[0; 32])?;
                    Err(error)
                }
            }
        }
        _ => Err("unknown v3 peer request".into()),
    }
}

pub fn serve(bind: &str, blocks_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(all(feature = "mainnet-candidate", not(target_arch = "wasm32")))]
    {
        return crate::candidate_node::serve(bind, blocks_dir);
    }
    #[allow(unreachable_code)]
    if !crate::network::IS_MAINNET {
        peer_signing_key().map_err(|_| "public v3 server requires TSC1_DEVNET_V3_PEER_KEY")?;
        allowed_peer_keys().map_err(|_| "public v3 server requires TSC1_DEVNET_V3_PEER_KEYS")?;
    }
    load_blocks(blocks_dir, pinned_genesis()?)?;
    let listener = TcpListener::bind(bind)?;
    let active_connections = Arc::new(AtomicUsize::new(0));
    let admission = Arc::new(ConnectionAdmission::new());
    println!("devnet_v3_listening={}", listener.local_addr()?);
    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                let Ok(peer_ip) = stream.peer_addr().map(|address| address.ip()) else {
                    eprintln!("v3 peer address unavailable");
                    continue;
                };
                if !admission.allow(peer_ip) {
                    eprintln!("v3 peer rate limit reached for {peer_ip}");
                    continue;
                }
                let current =
                    active_connections.try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                        (count < MAX_CONNECTIONS).then_some(count + 1)
                    });
                if current.is_err() {
                    eprintln!("v3 peer connection limit reached");
                    continue;
                }
                let blocks_dir = blocks_dir.to_path_buf();
                let active_connections = Arc::clone(&active_connections);
                thread::spawn(move || {
                    if let Err(error) = serve_authenticated_connection(stream, &blocks_dir) {
                        eprintln!("v3 peer request failed: {error}");
                    }
                    active_connections.fetch_sub(1, Ordering::AcqRel);
                });
            }
            Err(error) => eprintln!("v3 peer accept failed: {error}"),
        }
    }
    Ok(())
}

pub(crate) fn connect_peer(peer: &str) -> Result<TcpStream, Box<dyn std::error::Error>> {
    let mut connection = None;
    for address in peer.to_socket_addrs()? {
        if let Ok(stream) = TcpStream::connect_timeout(&address, Duration::from_secs(5)) {
            connection = Some(stream);
            break;
        }
    }
    let mut stream = connection.ok_or("could not connect to peer")?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    if crate::network::IS_MAINNET {
        stream.write_all(MAGIC)?;
        stream.write_all(&pinned_genesis()?.genesis_hash())?;
        let mut magic = [0; 8];
        stream.read_exact(&mut magic)?;
        if &magic != MAGIC {
            return Err("wrong mainnet handshake response".into());
        }
        Ok(stream)
    } else if env::var_os("TSC1_DEVNET_V3_PEER_KEY").is_some() {
        authenticate_outgoing(stream)
    } else {
        Ok(stream)
    }
}

fn receive_chain(mut stream: TcpStream) -> Result<ChainV3, Box<dyn std::error::Error>> {
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    stream.write_all(b"S")?;
    let mut magic = [0; 8];
    stream.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err("wrong v3 peer protocol".into());
    }
    let mut length = [0; 4];
    stream.read_exact(&mut length)?;
    let length = u32::from_le_bytes(length) as usize;
    if length == 0 || length > MAX_SNAPSHOT {
        return Err("invalid v3 snapshot length".into());
    }
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes)?;
    Ok(ChainV3::decode(&bytes, pinned_genesis()?)?)
}

pub fn submit(peer: &str, bytes: &[u8]) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    if bytes.is_empty() || bytes.len() > MAX_TX_BYTES {
        return Err("invalid submitted transaction size".into());
    }
    let mut stream = connect_peer(peer)?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    stream.write_all(b"T")?;
    stream.write_all(&(bytes.len() as u32).to_le_bytes())?;
    stream.write_all(bytes)?;
    let mut magic = [0u8; 8];
    stream.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err("wrong v3 peer protocol".into());
    }
    let mut accepted = [0u8; 1];
    stream.read_exact(&mut accepted)?;
    let mut txid = [0u8; 32];
    stream.read_exact(&mut txid)?;
    if accepted[0] != 1 {
        return Err("peer rejected signed transaction".into());
    }
    Ok(txid)
}

pub fn submit_dex(peer: &str, bytes: &[u8]) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    if bytes.is_empty() || bytes.len() > crate::dex::MAX_DEX_OPERATION_BYTES {
        return Err("invalid submitted dex operation size".into());
    }
    let mut stream = connect_peer(peer)?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    stream.write_all(b"D")?;
    stream.write_all(&(bytes.len() as u32).to_le_bytes())?;
    stream.write_all(bytes)?;
    let mut magic = [0u8; 8];
    stream.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err("wrong v3 peer protocol".into());
    }
    let mut accepted = [0u8; 1];
    stream.read_exact(&mut accepted)?;
    let mut operation_id = [0u8; 32];
    stream.read_exact(&mut operation_id)?;
    if accepted[0] != 1 {
        return Err("peer rejected signed dex operation".into());
    }
    Ok(operation_id)
}

pub fn dex_status(peer: &str, operation_id: &[u8; 32]) -> Result<u8, Box<dyn std::error::Error>> {
    let mut stream = connect_peer(peer)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.write_all(b"J")?;
    stream.write_all(operation_id)?;
    let mut magic = [0u8; 8];
    stream.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err("wrong v3 peer protocol".into());
    }
    let mut status = [0u8; 1];
    stream.read_exact(&mut status)?;
    Ok(status[0])
}

pub fn publish_block(peer: &str, block: &BlockV3) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = block.encode()?;
    let mut stream = connect_peer(peer)?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    stream.write_all(b"B")?;
    stream.write_all(&(bytes.len() as u32).to_le_bytes())?;
    stream.write_all(&bytes)?;
    let mut magic = [0u8; 8];
    stream.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err("wrong v3 peer protocol".into());
    }
    let mut accepted = [0u8; 1];
    stream.read_exact(&mut accepted)?;
    let mut hash = [0u8; 32];
    stream.read_exact(&mut hash)?;
    if accepted[0] != 1 || hash != block.hash()? {
        return Err("peer rejected relayed block".into());
    }
    Ok(())
}

pub fn relay_block(block: &BlockV3) -> Result<(usize, usize), Box<dyn std::error::Error>> {
    let mut accepted = 0;
    let mut failed = 0;
    for peer in configured_peers()? {
        if publish_block(&peer, block).is_ok() {
            accepted += 1;
        } else {
            failed += 1;
        }
    }
    Ok((accepted, failed))
}

pub(crate) fn append_extension(
    local: &ChainV3,
    remote: &ChainV3,
    blocks_dir: &Path,
) -> Result<u64, Box<dyn std::error::Error>> {
    let mut common = 0usize;
    for (ours, theirs) in local.blocks().iter().zip(remote.blocks()) {
        if ours.hash()? != theirs.hash()? {
            break;
        }
        common += 1;
    }
    if remote.cumulative_work() <= local.cumulative_work() {
        return Ok(0);
    }
    if (common as u64) < local.finalized_height() {
        return Err(format!(
            "reorg crosses finalized height {} (depth {})",
            local.finalized_height(),
            FINALITY_DEPTH
        )
        .into());
    }
    let added = (remote.blocks().len() - common) as u64;
    if common == local.blocks().len() {
        for block in &remote.blocks()[common..] {
            persist_block(blocks_dir, block)?;
        }
        return Ok(added);
    }
    let parent = blocks_dir
        .parent()
        .ok_or("v3 blocks directory has no parent")?;
    let name = blocks_dir
        .file_name()
        .ok_or("v3 blocks directory has no name")?
        .to_string_lossy();
    fs::create_dir_all(parent)?;
    let mut suffix = [0u8; 16];
    getrandom::getrandom(&mut suffix)?;
    let suffix = hex::encode(suffix);
    let candidate = parent.join(format!("{name}.candidate-{suffix}"));
    let archive = parent.join(format!("{name}.fork-{suffix}"));
    let pending = parent.join("pending");
    let pending_archive = parent.join(format!("pending.fork-{suffix}"));
    for block in remote.blocks() {
        persist_block(&candidate, block)?;
    }
    let had_pending = pending.exists();
    if had_pending {
        fs::rename(&pending, &pending_archive)?;
    }
    if let Err(error) = fs::rename(blocks_dir, &archive) {
        if had_pending {
            fs::rename(&pending_archive, &pending)?;
        }
        return Err(error.into());
    }
    if let Err(error) = fs::rename(&candidate, blocks_dir) {
        fs::rename(&archive, blocks_dir)?;
        if had_pending {
            fs::rename(&pending_archive, &pending)?;
        }
        return Err(error.into());
    }
    Ok(added)
}

pub fn sync(peer: &str, blocks_dir: &Path) -> Result<u64, Box<dyn std::error::Error>> {
    let local = load_blocks(blocks_dir, pinned_genesis()?)?;
    let remote = receive_chain(connect_peer(peer)?)?;
    append_extension(&local, &remote, blocks_dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::WalletSecrets;
    use crate::tsc1_chain_v2::reward_at_height;
    use crate::tsc1_chain_v3::ChainV3;
    use crate::tsc1_funded_output::create_reward_output;
    use std::thread;

    #[cfg(feature = "mainnet-candidate")]
    #[test]
    fn public_handshake_accepts_unregistered_client_and_rejects_devnet() {
        for valid in [true, false] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let mut suffix = [0; 8];
            getrandom::getrandom(&mut suffix).unwrap();
            let directory =
                std::env::temp_dir().join(format!("tnb-public-{}", hex::encode(suffix)));
            let server = thread::spawn(move || {
                let (stream, _) = listener.accept().unwrap();
                serve_authenticated_connection(stream, &directory).is_ok()
            });
            let mut client = TcpStream::connect(address).unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            client
                .write_all(if valid { MAGIC } else { b"TSC1P3V8" })
                .unwrap();
            client
                .write_all(&pinned_genesis().unwrap().genesis_hash())
                .unwrap();
            let mut reply = [0; 8];
            if valid {
                client.read_exact(&mut reply).unwrap();
                assert_eq!(&reply, MAGIC);
                let chain = receive_chain(client).unwrap();
                assert_eq!(chain.height(), 0);
                assert!(server.join().unwrap());
            } else {
                assert!(client.read_exact(&mut reply).is_err());
                assert!(!server.join().unwrap());
            }
        }
    }

    #[test]
    #[cfg(not(feature = "mainnet-candidate"))]
    fn v3_status_and_snapshot_are_supported() {
        let mut suffix = [0u8; 8];
        getrandom::getrandom(&mut suffix).unwrap();
        let dir = std::env::temp_dir().join(format!("tsc1-p3-status-{}", hex::encode(suffix)));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            for _ in 0..2 {
                let (stream, _) = listener.accept().unwrap();
                serve_connection(stream, &dir).unwrap();
            }
        });

        let mut client = TcpStream::connect(address).unwrap();
        client.write_all(b"H").unwrap();
        let mut magic = [0u8; 8];
        client.read_exact(&mut magic).unwrap();
        assert_eq!(&magic, MAGIC);
        let mut height_bytes = [0u8; 8];
        client.read_exact(&mut height_bytes).unwrap();
        let _height = u64::from_le_bytes(height_bytes);
        let mut tip = [0u8; 32];
        client.read_exact(&mut tip).unwrap();
        let mut confirmed_bytes = [0u8; 8];
        client.read_exact(&mut confirmed_bytes).unwrap();
        let _confirmed = u64::from_le_bytes(confirmed_bytes);
        let mut pending_bytes = [0u8; 4];
        client.read_exact(&mut pending_bytes).unwrap();
        assert_eq!(u32::from_le_bytes(pending_bytes), 0);

        let mut snapshot_client = TcpStream::connect(address).unwrap();
        snapshot_client.write_all(b"S").unwrap();
        let mut reply_magic = [0u8; 8];
        snapshot_client.read_exact(&mut reply_magic).unwrap();
        assert_eq!(&reply_magic, MAGIC);
        let mut length_bytes = [0u8; 4];
        snapshot_client.read_exact(&mut length_bytes).unwrap();
        let length = u32::from_le_bytes(length_bytes) as usize;
        assert!(length > 0);
        let mut snapshot = vec![0; length];
        snapshot_client.read_exact(&mut snapshot).unwrap();
        assert_eq!(snapshot.len(), length);
        server.join().unwrap();
    }

    #[test]
    fn connection_admission_reclaims_expired_ip_entries() {
        let admission = ConnectionAdmission::new();
        let expired = Instant::now() - CONNECTION_WINDOW - Duration::from_secs(1);
        {
            let mut entries = admission.attempts.lock().unwrap();
            for value in 0..MAX_TRACKED_IPS as u32 {
                entries.insert(IpAddr::V4(std::net::Ipv4Addr::from(value)), (expired, 8));
            }
        }
        assert!(admission.allow("192.0.2.1".parse().unwrap()));
        assert_eq!(admission.attempts.lock().unwrap().len(), 1);
    }

    #[test]
    fn connection_admission_limits_each_ip() {
        let admission = ConnectionAdmission::new();
        let ip = "127.0.0.1".parse().unwrap();
        assert!((0..MAX_CONNECTIONS_PER_IP).all(|_| admission.allow(ip)));
        assert!(!admission.allow(ip));
    }

    #[test]
    fn localhost_sync_validates_and_persists_v3_block() {
        let mut suffix = [0u8; 8];
        getrandom::getrandom(&mut suffix).unwrap();
        let root = std::env::temp_dir().join(format!("tsc1-p3-{}", hex::encode(suffix)));
        let source = root.join("source");
        let target = root.join("target");
        let mut chain = ChainV3::from_pinned_genesis().unwrap();
        let miner = WalletSecrets::from_seed(&[91; 32]);
        let reward = create_reward_output(&miner.address(), 0, reward_at_height(1)).unwrap();
        let mut block = chain.next_block(reward, chain.rewards().tip_timestamp() + 1, Vec::new());
        block.mine().unwrap();
        chain.append(block.clone()).unwrap();
        persist_block(&source, &block).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            if crate::network::IS_MAINNET {
                serve_authenticated_connection(stream, &source).unwrap();
            } else {
                serve_connection(stream, &source).unwrap();
            }
        });
        assert_eq!(sync(&address.to_string(), &target).unwrap(), 1);
        server.join().unwrap();
        assert_eq!(
            load_blocks(&target, pinned_genesis().unwrap())
                .unwrap()
                .tip_hash(),
            chain.tip_hash()
        );
        let mut longer =
            ChainV3::decode(&chain.encode().unwrap(), pinned_genesis().unwrap()).unwrap();
        let next_miner = WalletSecrets::from_seed(&[92; 32]);
        let next_reward =
            create_reward_output(&next_miner.address(), 0, reward_at_height(2)).unwrap();
        let mut next_block = longer.next_block(
            next_reward,
            longer.rewards().tip_timestamp() + 1,
            Vec::new(),
        );
        next_block.mine().unwrap();
        longer.append(next_block.clone()).unwrap();
        persist_block(&target, &next_block).unwrap();
        let mut fork = ChainV3::from_pinned_genesis().unwrap();
        let fork_miner = WalletSecrets::from_seed(&[93; 32]);
        let fork_reward =
            create_reward_output(&fork_miner.address(), 0, reward_at_height(1)).unwrap();
        let mut fork_block =
            fork.next_block(fork_reward, fork.rewards().tip_timestamp() + 1, Vec::new());
        fork_block.mine().unwrap();
        fork.append(fork_block).unwrap();
        assert_eq!(append_extension(&longer, &fork, &target).unwrap(), 0);
        let mut heavier = fork;
        for height in 2..=3 {
            let reward =
                create_reward_output(&fork_miner.address(), 0, reward_at_height(height)).unwrap();
            let mut block =
                heavier.next_block(reward, heavier.rewards().tip_timestamp() + 1, Vec::new());
            block.mine().unwrap();
            heavier.append(block).unwrap();
        }
        assert_eq!(append_extension(&longer, &heavier, &target).unwrap(), 3);
        assert_eq!(
            load_blocks(&target, pinned_genesis().unwrap())
                .unwrap()
                .tip_hash(),
            heavier.tip_hash()
        );
        let archives: Vec<_> = std::fs::read_dir(&root)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("target.fork-")
            })
            .collect();
        assert_eq!(archives.len(), 1);
        assert_eq!(
            load_blocks(&archives[0], pinned_genesis().unwrap())
                .unwrap()
                .tip_hash(),
            longer.tip_hash()
        );
        std::fs::remove_file(root.join("source").join("00000000000000000001.bin")).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_wrong_v3_peer_magic() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.write_all(b"BADPEER!").unwrap();
        });
        assert!(receive_chain(TcpStream::connect(address).unwrap()).is_err());
        server.join().unwrap();
    }

    #[test]
    fn rejects_invalid_submitted_transaction_over_tcp() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let directory = std::env::temp_dir().join("tsc1-v3-invalid-submit-no-files");
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            if crate::network::IS_MAINNET {
                assert!(serve_authenticated_connection(stream, &directory).is_err());
            } else {
                assert!(serve_connection(stream, &directory).is_err());
            }
        });
        assert!(submit(&address.to_string(), b"not a transaction").is_err());
        server.join().unwrap();
    }
}
