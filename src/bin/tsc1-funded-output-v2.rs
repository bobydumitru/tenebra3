//! Candidate funded output demonstration. Not connected to consensus.

use tenebra::WalletSecrets;
use tenebra::tsc1_funded_output::create_funded_output;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let wallet = WalletSecrets::generate()?;
    let output = create_funded_output(&wallet.address(), 0, 42)?;
    let recovered = wallet
        .scan_funded_output(&output, 0)
        .ok_or("recovery failed")?;
    println!(
        "Recovered {} nox; local candidate only",
        recovered.amount_nox
    );
    Ok(())
}
