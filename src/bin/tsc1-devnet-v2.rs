//! Persistent local mining experiment. No peer network or spend authorization.

use std::env;
use tenebra::Address;
use tenebra::tsc1_devnet_v2::{default_blocks_dir, load_chain, mine_to};
use tenebra::tsc1_peer_v2::{serve, sync};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    match (args.next().as_deref(), args.next(), args.next()) {
        (Some("status"), None, None) => {
            let chain = load_chain(&default_blocks_dir())?;
            println!("devnet_v2_height={}", chain.height());
            println!("genesis_hash={}", hex::encode(chain.genesis_hash()));
            println!("tip_hash={}", hex::encode(chain.tip_hash()));
            println!("issued_nox={}", chain.issued_nox());
            Ok(())
        }
        (Some("mine"), Some(address), None) => {
            let result = mine_to(&default_blocks_dir(), &Address::parse(&address)?)?;
            println!("mined_height={}", result.height);
            println!("reward_nox={}", result.reward_nox);
            println!("tip_hash={}", hex::encode(result.tip_hash));
            Ok(())
        }
        (Some("serve"), Some(bind), None) => serve(&bind, &default_blocks_dir()),
        (Some("sync"), Some(peer), None) => {
            let added = sync(&peer, &default_blocks_dir())?;
            println!("synced_blocks={added}");
            Ok(())
        }
        _ => Err("usage: tsc1-devnet-v2 status | mine <tsc1_public_address> | serve <bind_address> | sync <peer_address>".into()),
    }
}
