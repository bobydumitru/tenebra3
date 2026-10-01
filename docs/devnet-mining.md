# TSC-1 devnet mining demonstration

## Persistent v2 local devnet

`cargo run --bin tsc1-devnet-v2 -- status` loads the pinned v2 genesis from
`config/devnet-v2-genesis.hex` and revalidates every block in
`data/devnet-v2/blocks`. The genesis hash is
`962ea954fe2344106531c67b6fcf391f0ff74d3e3b349b1e41fe8703ba168932`.
It assigns 10,000,000 TNB to the approved public founder address as a funded
output that the matching wallet can scan.

`cargo run --bin tsc1-devnet-v2 -- mine <tsc1_public_address>` mines one
reward-only block to that address and persists it. The main desktop wallet
can also mine a local block after unlock and rescans the validated chain to
show its local devnet reward balance. No wallet password or private key is
needed by the miner.

The v2 difficulty is only 8 bits. This is a single-machine research devnet,
not a public network or spendable coin. Transfers and anonymous spend
authorization are disabled. A displayed devnet balance is not a mainnet or
real-value balance.

## Legacy v1 demonstration

Run `cargo run --bin tsc1-devnet-mine` in the TENEBRA project to create an
in-memory development chain from the fixed founder genesis and mine one block.
The demo uses the separate public treasury address as the miner's receiving
address. It never reads a private key, password, or encrypted wallet file.

The code verifies the known genesis hash, the proof-of-work block, the first
scheduled mining reward, and the maximum-supply invariant. Its 8-bit mining
difficulty is intentionally tiny for testing and provides no real network
security. The chain is discarded when the process exits: there is no persistent
balance, public peer network, or spendable TNB yet.

This demonstration is not a public coin launch. A production chain needs
private spend authorization, durable consensus state, networking, difficulty
adjustment, fee payout enforcement, and independent security review.
