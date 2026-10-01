//! Read-only chain snapshot exchange for the local devnet, not mainnet P2P.

use crate::tsc1_chain_v2::Chain;
use crate::tsc1_devnet_v2::{load_chain, persist_block, pinned_genesis};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::time::Duration;

const MAGIC: &[u8; 8] = b"TSC1P2V2";
const MAX_SNAPSHOT: usize = 16 * 1024 * 1024;

fn serve_connection(
    mut stream: TcpStream,
    blocks_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let snapshot = load_chain(blocks_dir)?.encode();
    if snapshot.len() > MAX_SNAPSHOT {
        return Err("devnet snapshot exceeds protocol limit".into());
    }
    stream.write_all(MAGIC)?;
    stream.write_all(&(snapshot.len() as u32).to_le_bytes())?;
    stream.write_all(&snapshot)?;
    Ok(())
}

pub fn serve(bind: &str, blocks_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(bind)?;
    println!("devnet_v2_listening={}", listener.local_addr()?);
    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                if let Err(error) = serve_connection(stream, blocks_dir) {
                    eprintln!("peer request failed: {error}");
                }
            }
            Err(error) => eprintln!("peer accept failed: {error}"),
        }
    }
    Ok(())
}

fn receive_chain(mut stream: TcpStream) -> Result<Chain, Box<dyn std::error::Error>> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut magic = [0; 8];
    stream.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err("wrong devnet peer protocol".into());
    }
    let mut length = [0; 4];
    stream.read_exact(&mut length)?;
    let length = u32::from_le_bytes(length) as usize;
    if length == 0 || length > MAX_SNAPSHOT {
        return Err("invalid devnet snapshot length".into());
    }
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes)?;
    let genesis = pinned_genesis()?.genesis_hash();
    Ok(Chain::decode(&bytes, genesis)?)
}

fn append_extension(
    local: &Chain,
    remote: &Chain,
    blocks_dir: &Path,
) -> Result<u64, Box<dyn std::error::Error>> {
    for (ours, theirs) in local.blocks().iter().zip(remote.blocks()) {
        if ours.hash() != theirs.hash() {
            return Err(
                "peer chain forks from local history; automatic reorganization disabled".into(),
            );
        }
    }
    if remote.blocks().len() < local.blocks().len() {
        return Ok(0);
    }
    let added = (remote.blocks().len() - local.blocks().len()) as u64;
    for block in &remote.blocks()[local.blocks().len()..] {
        persist_block(blocks_dir, block)?;
    }
    Ok(added)
}

pub fn sync(peer: &str, blocks_dir: &Path) -> Result<u64, Box<dyn std::error::Error>> {
    let local = load_chain(blocks_dir)?;
    let addresses = peer.to_socket_addrs()?;
    let mut connection = None;
    for address in addresses {
        if let Ok(stream) = TcpStream::connect_timeout(&address, Duration::from_secs(5)) {
            connection = Some(stream);
            break;
        }
    }
    let remote = receive_chain(connection.ok_or("could not connect to devnet peer")?)?;
    append_extension(&local, &remote, blocks_dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::WalletSecrets;
    use crate::tsc1_chain_v2::reward_at_height;
    use crate::tsc1_funded_output::create_reward_output;
    use std::thread;

    #[test]
    fn snapshot_round_trip_matches_pinned_genesis() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let missing_dir = std::env::temp_dir().join("tsc1-peer-test-nonexistent-blocks");
            serve_connection(stream, &missing_dir).unwrap();
        });
        let received = receive_chain(TcpStream::connect(address).unwrap()).unwrap();
        server.join().unwrap();
        assert_eq!(
            received.genesis_hash(),
            pinned_genesis().unwrap().genesis_hash()
        );
        assert_eq!(received.height(), 0);
    }

    #[test]
    fn rejects_wrong_protocol_before_snapshot() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.write_all(b"BADPEER!").unwrap();
        });
        let result = receive_chain(TcpStream::connect(address).unwrap());
        server.join().unwrap();
        assert!(result.is_err());
    }

    #[test]
    fn persists_valid_extension_and_rejects_fork() {
        let local = pinned_genesis().unwrap();
        let mut remote = local.clone();
        let recipient = WalletSecrets::from_seed(&[31; 32]).address();
        let output = create_reward_output(&recipient, 0, reward_at_height(1)).unwrap();
        let mut block = remote.next_block(output, remote.tip_timestamp() + 1);
        block.mine().unwrap();
        remote.append(block).unwrap();

        let mut nonce = [0; 8];
        getrandom::getrandom(&mut nonce).unwrap();
        let dir = std::env::temp_dir().join(format!("tsc1-peer-{}", hex::encode(nonce)));
        assert_eq!(append_extension(&local, &remote, &dir).unwrap(), 1);
        assert_eq!(load_chain(&dir).unwrap().tip_hash(), remote.tip_hash());

        let other = WalletSecrets::from_seed(&[32; 32]).address();
        let other_output = create_reward_output(&other, 0, reward_at_height(1)).unwrap();
        let mut fork = local.clone();
        let mut fork_block = fork.next_block(other_output, fork.tip_timestamp() + 1);
        fork_block.mine().unwrap();
        fork.append(fork_block).unwrap();
        assert!(append_extension(&remote, &fork, &dir).is_err());
        assert_eq!(load_chain(&dir).unwrap().tip_hash(), remote.tip_hash());

        let mut longer = remote.clone();
        let next = WalletSecrets::from_seed(&[33; 32]).address();
        let next_output = create_reward_output(&next, 0, reward_at_height(2)).unwrap();
        let mut next_block = longer.next_block(next_output, longer.tip_timestamp() + 1);
        next_block.mine().unwrap();
        longer.append(next_block).unwrap();
        assert_eq!(append_extension(&remote, &longer, &dir).unwrap(), 1);
        assert!(append_extension(&longer, &fork, &dir).is_err());

        std::fs::remove_file(dir.join("00000000000000000001.bin")).unwrap();
        std::fs::remove_file(dir.join("00000000000000000002.bin")).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }
}
