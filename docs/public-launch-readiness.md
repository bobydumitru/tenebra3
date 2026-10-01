# TSC-1 public launch readiness

Current status: **not ready for public launch**. The pinned genesis allocates
10,000,000 TNB to the founder address on a local devnet. The remaining
90,000,000 TNB is scheduled as mining rewards. These are not yet transferable
mainnet coins.

V3f is the current isolated candidate. V3e added a difficulty field, bounded
12..24-bit retargeting, cumulative required-work comparison and heavier-fork
snapshot reorganization. V3f limits transactions to two inputs and has a
separate network ID to bound signature work and reject v3e transaction replay.
Its default data directory is `data/devnet-v3f/blocks`.
These devnet parameters are not production PoW; the inner reward block still
uses a fixed 8-bit target. A replaced local branch and pending inbox are
archived, not deleted. No public mainnet was launched.

An isolated v3 devnet candidate now commits transactions inside mined block
hashes and replays verified spend state when loading block files. It has a
separate `tsc1-devnet-v3 status|mine` executable. The original v2 local chain
and wallet balance are unchanged. V3d is not a public network: its simple PoW,
double reward/block work, lack of cumulative-work fork choice, and
limited static-peer block propagation are unsuitable for mainnet.

The historical isolated v3b candidate committed explicit fee outputs in each block.
Consensus checks the sum of transaction fees, a 90% miner / 10% treasury
split (integer remainder to the miner), exact public commitments, and the
fixed treasury destination from `config/treasury-address.txt`. These outputs
are spendable on the devnet, but this fee design and its cryptography are
unaudited. V3b changes the block/chain encoding and peer protocol; older v3
snapshots are not migrated or silently accepted.

The subsequent v3c candidate rejected blocks more than 120 seconds in
the future. It changes the block/chain tags, genesis anchor, and peer magic
again; old v3b snapshots require an explicit migration plan. Median-past-time
and reward maturity remain open.

V3d added a 10-block reward maturity rule for every reward referenced by a
transaction ring; its protocol identifiers differ from v3c. The window is a
devnet parameter, not a production-final security policy. No automatic
migration from older v3 formats is available.

For local v3d experiments, `tsc1-wallet sign-v3 <recipient_address>
<amount_nox> <fee_nox> <output.bin>` creates a signed transaction after an
explicit local password prompt. `tsc1-devnet-v3 submit <peer> <output.bin>`
sends it to a node. The node validates and stores at most 16 pending
transactions; `tsc1-devnet-v3 mine <public_miner_address>` mines them and
creates the required 90/10 fee outputs. `TSC1_DEVNET_V3_PEERS` can contain
up to eight comma-separated peer addresses for transaction and freshly mined
block relay. Receiving nodes fully validate and persist only direct chain
extensions. This is a research devnet workflow, not a public-funds-ready
payment network.

## Required before mainnet

1. Specify and independently review anonymous spend authorization, including
   destination ownership, commitment equality, and deterministic key images.
   Keep consensus spend validation fail-closed until complete.
2. Complete transaction/block integration with reorganization rules and
   adversarial tests. Atomic spend validation, persistent replay state, range
   proofs, and fee accounting exist only in this devnet candidate.
3. Define production PoW difficulty adjustment, fork choice, timestamp rules,
   reward maturity, and protocol upgrade/version rules. The current easy
   devnet PoW is not production security.
4. Build bounded peer discovery, block and transaction relay, synchronization,
   reorganization, abuse resistance, and operational observability. The
   current TCP snapshot exchange is for trusted local devnet peers only.
5. Run public testnets and adversarial/fuzz testing; obtain independent
   cryptographic and consensus audits. Publish reproducible builds, genesis
   parameters, source, binaries, node setup, and incident procedures.
6. Provision independently operated public nodes and monitoring. Confirm
   legal, operational, and release decisions with the project owner before
   declaring mainnet live.

The founder wallet balance must always be derived from a validated chain and
the wallet's own keys. Never hard-code a balance or treat a local devnet balance
as public value.

## Local two-node smoke test

Set `TSC1_DEVNET_BLOCKS_DIR` separately for each process. Run
`tsc1-devnet-v2 serve 127.0.0.1:39451` for node A, then
`tsc1-devnet-v2 sync 127.0.0.1:39451` for node B. The sync command accepts
only a validated extension of node B's existing chain. Use separate storage
directories; this snapshot protocol does not relay new blocks continuously.

For current v3f, use `TSC1_DEVNET_V3_BLOCKS_DIR` with separate directories and run
`tsc1-devnet-v3 serve 127.0.0.1:39453` on node A, then
`tsc1-devnet-v3 sync 127.0.0.1:39453` on node B. This validates an entire
snapshot and accepts a strictly higher-work chain, archiving a displaced
fork. It is not public peer discovery or production-grade networking.
