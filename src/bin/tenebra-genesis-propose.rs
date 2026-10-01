//! Create a public genesis proposal without accessing any wallet secrets.
use std::{
    env,
    fs::OpenOptions,
    io::Write,
    time::{SystemTime, UNIX_EPOCH},
};
use tenebra::tsc1_chain_v2::Chain;
use tenebra::tsc1_funded_output::create_reward_output;
use tenebra::{Address, FOUNDER_ALLOCATION_NOX};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = env::args().skip(1).collect();
    if args.len() != 1 {
        return Err("usage: tenebra-genesis-propose <new-output-file>".into());
    }
    let founder = Address::parse(include_str!("../../config/founder-address.txt"))?;
    let output = create_reward_output(&founder, 0, FOUNDER_ALLOCATION_NOX)?;
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let chain = Chain::new(output, timestamp)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args[0])?;
    writeln!(file, "# TENEBRA mainnet genesis proposal; not deployed")?;
    writeln!(file, "# timestamp={timestamp}")?;
    writeln!(file, "# genesis_hash={}", hex::encode(chain.genesis_hash()))?;
    writeln!(file, "{}", hex::encode(chain.genesis_block().encode()))?;
    file.sync_all()?;
    println!("genesis_hash={}", hex::encode(chain.genesis_hash()));
    Ok(())
}
