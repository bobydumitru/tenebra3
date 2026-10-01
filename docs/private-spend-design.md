# TSC-1 private spending: implementation boundary

TSC-1 must not accept a transfer merely because its confidential amounts
balance. A valid private spend also needs an independently reviewed proof that
the spender controls one eligible output, without revealing which output in a
decoy set is theirs. A deterministic key image (or equivalent nullifier) must
make a second spend of that output detectable across all blocks.

The current `tsc1-tx-validator` names exact input IDs. That links a spend to
its prior output and is **not anonymous spending**. The current Ristretto
commitments and Bulletproofs do not make the signer anonymous by themselves.

Required consensus work, before enabling transfers:

1. Choose and review a complete, compatible anonymous-spend scheme. Do not
   copy a signature from a different curve or commitment construction.
2. Specify canonical transaction serialization and domain-separated signing
   transcript binding network ID, ring members, output commitments, range
   proofs, asset IDs, fee, and expiry/version fields.
3. Verify membership and ownership proofs, canonical encodings, and key-image
   derivation. Reject duplicate key images within a transaction, block, and
   persistent chain state. Define decoy selection and minimum ring size.
4. Verify amount conservation and range proofs for every asset, with native
   TNB fees. Apply all output additions and key-image insertions atomically.
5. Add adversarial tests, fuzzing, cross-implementation vectors, and an
   independent cryptographic and consensus audit before any real funds.

`tsc1-spend-boundary` checks a proposed envelope's structural limits and
replay set, but deliberately rejects every spend at the cryptographic gate.
It is not an anonymous transaction protocol. The research devnet has no
private-spend consensus, no production mainnet, and no real transferable TNB.

## Current v2 transaction envelope

`src/tsc1_tx_v2.rs` now defines a bounded canonical transaction format tied
to the pinned local v2 genesis hash. It commits to 16-member rings, key
images, pseudo-output commitments, funded outputs, a native fee, and expiry.
Public checks verify encodings, output proofs, ring ordering, duplicate key
images, and commitment balance. Ring membership can currently be checked
against reward outputs only; transaction outputs are not in the chain yet.
The authorization field is part of the transaction ID, while the signing
message excludes it. `validate_for_consensus` still rejects all spends because
transactions and spent key images are not yet persisted in block consensus.

The experimental two-row linkable ring proof has one canonical challenge
scalar and 16 canonical responses for each of the key and amount rows.
Ring statements resolve each on-chain output into its one-time destination
point and `(output commitment - pseudo-output commitment)`. The shared
challenge binds both rows, the key image, and the transaction signing hash.
`AuthorizationProof::sign` and `verify` pass a synthetic 16-output mined-chain
test, including tampering failures. This is a new MLSAG-style Ristretto
prototype, **not audited CLSAG** and not approved for real funds. The proof
format and transcript need independent review and cross-implementation tests.

`src/tsc1_spend_state_v2.rs` adds an in-memory output registry and spent
key-image set. It applies a batch against a cloned state and commits only when
every transaction passes public rules, on-chain ring resolution, anonymous
authorization, destination uniqueness, and replay checks. A synthetic test
spends a founder output, spends the received output again, and rejects replay
without changing the state. This state by itself is **not block consensus**;
the separate v3 candidate below adds block commitments, but no production
reorganization rules, reward maturity, or fee payout exist yet.

`src/tsc1_spend_journal_v2.rs` now persists candidate transaction batches in
bounded, hash-linked files. Every load checks the pinned reward-chain anchor
and rebuilds spend state by revalidating all transactions. An end-to-end test
persists two successive transfers, reloads them, and rejects a corrupted
record. These files are **not confirmed blocks** and must never be shown as
confirmed wallet balance or relayed as mainnet consensus.

`src/tsc1_chain_v3.rs` is a separate transaction-bearing devnet candidate.
Its outer PoW hash commits the v2 reward block and canonical transactions;
append checks both reward-chain rules and atomic spend state before changing
the tip. Block files and whole-chain decoding revalidate transactions and
reconstruct spent key images. Tests include two successive private transfers
in mined blocks, a modified transaction, and a replayed spend. V3 is not
audited, has only bounded snapshot exchange between manually configured
peers, and does not yet pay or split fees.

The v3 wallet balance scanner uses validated block outputs and excludes any
output whose derived key image is spent. It is tested with synthetic wallets
across two transfers and chain reload. It is not yet connected to the user's
desktop wallet or a public network.

Research basis: [Monero CLSAG implementation](https://github.com/monero-project/monero/blob/master/src/ringct/rctSigs.cpp)
and [Zero to Monero, Second Edition](https://moneroresearch.info/index.php?action=attachments_ATTACHMENTS_CORE&filename=fce78ca4dc243f0b7c6ab2efd7d23824dde1b458&id=5&method=downloadAttachment&resourceId=3).
These use a different curve/encoding context and are not drop-in TSC-1 code.
