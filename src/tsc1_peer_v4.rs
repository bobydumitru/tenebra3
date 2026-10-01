//! Bounded authenticated relay for v4 microblocks.

use crate::tsc1_microblock_v4::MicroBlockV4;
use crate::tsc1_spend_state_v2::SpendState;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const MAGIC: &[u8; 8] = b"TSC1P4V1";
const MAX_MICROBLOCK_BYTES: usize = 64 * 1024 * 1024;

pub fn encode_relay(block: &MicroBlockV4) -> Result<Vec<u8>, &'static str> {
    block.verify_authorization_commitment()?;
    let bytes = block.encode()?;
    if bytes.len() > MAX_MICROBLOCK_BYTES {
        return Err("oversized v4 microblock relay");
    }
    let mut frame = Vec::with_capacity(12 + bytes.len());
    frame.extend_from_slice(MAGIC);
    frame.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    frame.extend_from_slice(&bytes);
    Ok(frame)
}

pub fn decode_relay(frame: &[u8]) -> Result<MicroBlockV4, &'static str> {
    if frame.len() < 12 || &frame[..8] != MAGIC {
        return Err("wrong v4 relay magic");
    }
    let length = u32::from_le_bytes(frame[8..12].try_into().unwrap()) as usize;
    if length == 0 || length > MAX_MICROBLOCK_BYTES || frame.len() != 12 + length {
        return Err("invalid v4 relay length");
    }
    let block = MicroBlockV4::decode(&frame[12..])?;
    block.verify_authorization_commitment()?;
    Ok(block)
}

pub fn accept_relay(frame: &[u8], state: &mut SpendState) -> Result<MicroBlockV4, &'static str> {
    let block = decode_relay(frame)?;
    block.validate_and_apply(state)?;
    Ok(block)
}

pub fn publish_microblock(
    peer: &str,
    block: &MicroBlockV4,
) -> Result<(), Box<dyn std::error::Error>> {
    let frame = encode_relay(block)?;
    let mut stream = TcpStream::connect(peer)?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.write_all(&frame)?;
    let mut response = [0; 2];
    stream.read_exact(&mut response)?;
    if &response != b"OK" {
        return Err("v4 peer rejected microblock".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_rejects_missing_anonymous_commitment() {
        let block = MicroBlockV4 {
            parent_hash: [0; 32],
            height: 1,
            timestamp: 1,
            transactions: Vec::new(),
            aggregate_authorization: Vec::new(),
        };
        assert!(encode_relay(&block).is_err());
    }
}
