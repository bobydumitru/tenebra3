# Private block validation status

`src/bin/tsc1-private-block.rs` prototypes an atomic block-state transition:
it rejects duplicate/reused key images and output destinations, checks bounds
and fee overflow, and computes the proposed 90% miner / 10% treasury fee split.
Tests use a deliberately fake verifier only to exercise state transitions.

The production verifier rejects every private spend. The prototype is not yet
connected to `tsc1_chain.rs`, does not verify amount commitments, ring proofs,
transaction serialization, miner/treasury reward outputs, persistent state,
or peer consensus. Its fee numbers are calculations, not actual payouts.

The existing genesis block has a one-time destination but no amount commitment
or spendable private-output record. Genesis and mining outputs must be redesigned
as fully specified spendable outputs before valid private transactions can be
accepted. No mainnet or transferable TNB exists yet.
