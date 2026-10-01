# TENEBRA External Audit Submission Package

## Engagement scope

Review the Rust implementation of the TSC-1 transaction, authorization proof,
funded-output, spend-state, chain, peer, wallet-signing and persistence paths.
The requested review is cryptographic and consensus-focused, with supporting
wallet, P2P, fuzzing and operational review.

## Repository boundary

- Language: Rust, edition 2024.
- Candidate protocol: v3f transaction-bearing chain.
- Cryptographic components: Ristretto points, Pedersen commitments,
  Bulletproof range proofs, two-row linkable authorization proof, Ed25519 peer
  authentication, AEAD wallet files.
- No private wallet files, passwords or seeds are included in this package.
- The audit must treat all balances as non-monetary test values until the
  reviewer explicitly concludes otherwise.

## Questions the reviewer must answer

1. Does the authorization proof establish knowledge of both the one-time
   destination secret and commitment blinding difference for one hidden ring
   member?
2. Are key images unique, unlinkable for honest spends, and impossible to forge
   or reuse without the witness?
3. Is the Fiat-Shamir transcript domain-separated and bound to every consensus
   field that must be immutable?
4. Can malformed points, noncanonical scalars, identity points, proof mutation,
   replay, duplicate outputs, and commitment imbalance bypass consensus?
5. Are the amount equations sound under all ring positions and signer choices?
6. Are serialization, transaction IDs, block IDs, and state recovery
   deterministic across implementations?
7. Can a crash or concurrent mining/sync/relay operation lose, duplicate or
   resurrect state?
8. Are PoW, timestamps, retarget, finality and fork choice safe for a public
   adversarial network?
9. Are wallet KDF, secret handling, backup, restore and signing boundaries
   appropriate for production custody?
10. What exact changes are required before real-value activation?

## Reproducible evidence command

On Windows PowerShell from the repository root:

```powershell
.\deploy\external-audit-gate.ps1
```

The script creates a timestamped `audit-evidence-*` directory containing:

- formatting result;
- all-target test result;
- strict library Clippy result;
- fuzz target build result;
- focused authorization test result;
- Cargo dependency metadata;
- SHA-256 source/config/document manifest;
- this scope document.



## Current known release blockers

- The custom anonymous authorization construction requires cryptographic review
  of its equations, transcript, assumptions and implementation.
- The repository currently operates one authenticated v3f node; production
  redundancy and multi-node adversarial validation are not complete.
- Durable single-writer state and crash-consistent recovery need review.
- Public peer abuse controls require adversarial load testing.
- The current ring size and privacy set must be reviewed for the intended
  anonymity claim.
- Wallet custody and recovery require a production threat model.




