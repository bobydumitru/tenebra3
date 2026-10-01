//! Native transaction-fee and mining-reward distribution rules.

pub const FEE_POLICY_ACTIVATION_HEIGHT: u64 = 22_000;

pub fn transaction_fee_payouts(total_fee_nox: u64, height: u64) -> (u64, u64) {
    if crate::network::IS_MAINNET && height >= FEE_POLICY_ACTIVATION_HEIGHT {
        (0, total_fee_nox)
    } else {
        let treasury_nox = total_fee_nox / 10;
        (total_fee_nox - treasury_nox, treasury_nox)
    }
}

pub fn split_mining_reward(reward_nox: u64) -> (u64, u64) {
    let treasury_nox = reward_nox / 10;
    (reward_nox - treasury_nox, treasury_nox)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transaction_fees_keep_old_split_until_activation_then_go_to_treasury() {
        for amount in [0, 1, 9, 10, 99, 100, u64::MAX] {
            let before_activation = FEE_POLICY_ACTIVATION_HEIGHT - 1;
            let (miner_before, treasury_before) = transaction_fee_payouts(amount, before_activation);
            assert_eq!(miner_before.checked_add(treasury_before), Some(amount));
            assert_eq!(treasury_before, amount / 10);
            let (miner_after, treasury_after) = transaction_fee_payouts(amount, FEE_POLICY_ACTIVATION_HEIGHT);
            assert_eq!(miner_after.checked_add(treasury_after), Some(amount));
            if crate::network::IS_MAINNET {
                assert_eq!(miner_after, 0);
                assert_eq!(treasury_after, amount);
            } else {
                assert_eq!(treasury_after, amount / 10);
            }
        }
    }

    #[test]
    fn mining_reward_keeps_ninety_ten_split_and_all_nox() {
        for amount in [0, 1, 9, 10, 99, 100, u64::MAX] {
            let (miner, treasury) = split_mining_reward(amount);
            assert_eq!(miner.checked_add(treasury), Some(amount));
            assert_eq!(treasury, amount / 10);
        }
    }
}
