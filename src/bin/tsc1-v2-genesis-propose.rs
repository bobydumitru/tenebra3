//! Prints a candidate v2 genesis built only from the public founder address.
//! The output is random; review and pin one proposal before mining it.

use tenebra::tsc1_chain_v2::Chain;
use tenebra::tsc1_funded_output::create_reward_output;
use tenebra::{Address, FOUNDER_ALLOCATION_NOX};

const FOUNDER: &str = include_str!("../../config/founder-address.txt");
const TIMESTAMP: u64 = 1_789_776_000;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let founder = Address::parse(FOUNDER)?;
    let output = create_reward_output(&founder, 0, FOUNDER_ALLOCATION_NOX)?;
    let chain = Chain::new(output, TIMESTAMP)?;
    println!("genesis_hash={}", hex::encode(chain.genesis_hash()));
    println!(
        "genesis_block={}",
        hex::encode(chain.genesis_block().encode())
    );
    Ok(())
}
