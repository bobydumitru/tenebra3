# TSC-1 development genesis

`src/bin/tsc1-devnet-genesis.rs` builds a reproducible local genesis block for
the TSC-1 research devnet. It assigns 10,000,000 TNB to a deterministic
one-time output derived from the approved public founder address. The remaining
90,000,000 TNB follow the prototype's 50-year mining reward schedule.

The founder allocation is intentionally public. The deterministic devnet
ephemeral value is not a secret and does not provide privacy for that initial
allocation. It does not reveal the founder wallet's private spend key.

This is **not mainnet** and does not create spendable real-value coins. The
prototype still lacks accepted transfers, private spend authorization, fee
payouts, peer-to-peer networking, difficulty adjustment, and a finalized
consensus specification. A real launch needs independent security review.
