//! Verifies the native TNB coin rules of the local TSC-1 prototype.

#[path = "../tsc1_chain.rs"]
mod chain;

const SYMBOL: &str = tenebra::SYMBOL;
const NETWORK: &str = "TSC-1";

fn verify_coin_rules() -> Result<(), &'static str> {
    if SYMBOL != "TNB" || NETWORK != "TSC-1" {
        return Err("wrong native coin identity");
    }
    if chain::NOX_PER_TNB != tenebra::NOX_PER_TNB {
        return Err("unit mismatch");
    }
    if chain::MAX_SUPPLY_NOX != tenebra::MAX_SUPPLY_NOX
        || chain::FOUNDER_NOX != tenebra::FOUNDER_ALLOCATION_NOX
        || chain::MINING_POOL_NOX != tenebra::MINING_ALLOCATION_NOX
    {
        return Err("supply mismatch");
    }
    if chain::FOUNDER_NOX
        .checked_add(chain::MINING_POOL_NOX)
        .ok_or("supply overflow")?
        != chain::MAX_SUPPLY_NOX
    {
        return Err("allocation exceeds maximum supply");
    }
    if chain::reward_at_height(0) != 0 || chain::reward_at_height(chain::EMISSION_BLOCKS + 1) != 0 {
        return Err("mining outside emission schedule");
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    verify_coin_rules()?;
    println!("Native coin: {SYMBOL} on {NETWORK}");
    println!("Smallest unit: 1 TNB = {} nox", chain::NOX_PER_TNB);
    println!("Maximum supply: 100,000,000 TNB");
    println!("Founder genesis allocation: 10,000,000 TNB");
    println!("Proof-of-work mining allocation: 90,000,000 TNB");
    println!("Target block time: {} seconds", chain::TARGET_BLOCK_SECONDS);
    println!("Research prototype only: no public network or spendable coins yet.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_coin_rules_are_consistent() {
        assert_eq!(verify_coin_rules(), Ok(()));
    }

    #[test]
    fn emission_finishes_at_mining_allocation() {
        let mut total = 0u64;
        for height in 1..=chain::EMISSION_BLOCKS {
            total = total.checked_add(chain::reward_at_height(height)).unwrap();
        }
        assert_eq!(total, chain::MINING_POOL_NOX);
        assert_eq!(total + chain::FOUNDER_NOX, chain::MAX_SUPPLY_NOX);
    }
}
