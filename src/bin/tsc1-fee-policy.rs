//! TSC-1 transaction-fee and mining-reward payout policy.

use tenebra::tsc1_fee::{split_mining_reward, transaction_fee_payouts};

fn main() {
    let (fee_miner, fee_treasury) = transaction_fee_payouts(100, 22_000);
    let (reward_miner, reward_treasury) = split_mining_reward(100);
    println!("Transaction fee: {fee_miner} nox miner, {fee_treasury} nox TENEBRA treasury.");
    println!("Mining reward: {reward_miner} nox miner, {reward_treasury} nox TENEBRA treasury.");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transaction_fee_is_paid_entirely_to_treasury() {
        let expected = if tenebra::network::IS_MAINNET {
            (0, 100)
        } else {
            (90, 10)
        };
        assert_eq!(transaction_fee_payouts(100, 22_000), expected);
        let large_expected = if tenebra::network::IS_MAINNET {
            (0, 1_000_000_000)
        } else {
            (900_000_000, 100_000_000)
        };
        assert_eq!(transaction_fee_payouts(1_000_000_000, 22_000), large_expected);
        assert_eq!(transaction_fee_payouts(100, 21_999), (90, 10));
    }

    #[test]
    fn tiny_fees_never_create_or_lose_nox() {
        for fee in 0..=1_000 {
            let (miner, treasury) = transaction_fee_payouts(fee, 22_000);
            assert_eq!(miner + treasury, fee);
            if tenebra::network::IS_MAINNET {
                assert_eq!(miner, 0);
                assert_eq!(treasury, fee);
            } else {
                assert_eq!(treasury, fee / 10);
            }
        }
    }

    #[test]
    fn largest_possible_fee_does_not_overflow() {
        let (miner, treasury) = transaction_fee_payouts(u64::MAX, 22_000);
        assert_eq!(miner.checked_add(treasury), Some(u64::MAX));
    }

    #[test]
    fn mining_reward_remains_ninety_ten() {
        assert_eq!(split_mining_reward(100), (90, 10));
        assert_eq!(split_mining_reward(1_000_000_000), (900_000_000, 100_000_000));
    }
}
