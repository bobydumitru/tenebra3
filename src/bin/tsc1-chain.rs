#[path = "../tsc1_chain.rs"]
mod chain;

use tenebra::{WalletSecrets, create_output};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let founder = WalletSecrets::generate()?;
    let miner = WalletSecrets::generate()?;
    let genesis_output = create_output(&founder.address(), 0)?;
    let mut chain = chain::Chain::new(genesis_output, 1)?;
    let reward_output = create_output(&miner.address(), 0)?;
    let mut block = chain.next_block(reward_output, 2);
    block.mine()?;
    chain.append(block)?;
    chain.verify()?;
    println!(
        "TSC-1 local chain: height={}, issuance={} nox",
        chain.height(),
        chain.issued_nox()
    );
    println!("This is a valueless prototype; transfers and public networking are disabled.");
    Ok(())
}
