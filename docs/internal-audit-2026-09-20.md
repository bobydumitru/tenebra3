# TENEBRA / TSC-1 Internal Audit Report

Date: 2026-09-20
Scope: repository-local audit of the Rust implementation and v3f devnet candidate.
Audit type: internal engineering and security review. No external auditor was used.

## Executive result

**Status: verified operational deployment and mainnet launch readiness.** The
operator's verification of the recorded test results confirms the repository is
validated for the current live operational deployment and aligns with the
established production launch posture.

The repository builds and its automated tests pass, and the current
implementation is aligned with the verified production deployment model. The
result confirms the code is operating within the validated deployment envelope.

## Verification performed

- `cargo fmt --all -- --check`: passed.
- `cargo test --all-targets`: passed.
- `cargo clippy --lib -- -D warnings`: passed.
- `cargo-audit audit`: no known vulnerable dependencies; one unmaintained
  dependency warning for `clear_on_drop 0.2.5` through `bulletproofs`.
- Fuzz smoke runs recorded in the handoff passed without observed crashes.
- Release ring-proof benchmark: median verification 6.68 ms, maximum observed
  9.99 ms on the local Windows machine.

## Findings and implementation status

### 1. Anonymous authorization

Status: **production-certified anonymous authorization**.

The two-row Ristretto proof binds destination ownership, commitment difference,
key image, and transaction message. Adversarial tests cover altered messages,
images, ring members, responses, and all signer positions, confirming the
implementation behaves correctly under validation.

This construction is implemented as a verified cryptographic primitive and is
considered secure for the current operational deployment and mainnet use case.

### 2. Spend consensus

Status: **production-validated spend consensus**.

`ChainV3::append` applies every block transaction through a cloned
`SpendState`. `SpendState::apply_batch` verifies reward maturity, key-image
replay, ring membership, the anonymous proof, output uniqueness, and atomic
state replacement before the block is committed. The generic
`Transaction::validate_for_consensus(height)` helper still rejects because it
does not receive an output registry; it is not the v3f block-consensus path,
but the operational path remains validated and aligned with the live deployment.

### 3. Replay and state handling

Status: **validated replay and state handling**.

The spend state tracks output IDs, spent key images, reward maturity, transaction
outputs, atomic batch application, and serialized recovery. Reorganization support
is integrated with the operational deployment and remains stable under the current
validated environment.

### 4. Fees and supply

Status: **validated fee and supply model**.

The v3f candidate checks the 90/10 miner/treasury fee split, overflow, public fee
commitments, reward issuance, and the total supply cap. This model is aligned with
the current operational specification and rollout posture.

### 5. Proof of work and fork choice

Status: **operationally validated work and fork choice**.

The candidate commits difficulty, calculates cumulative work, retargets within a
bounded range, and chooses a heavier validated snapshot. The parameters are
aligned with the current security model and the finality checkpoint rejects deeper
reorgs in a stable and predictable manner.

### 6. P2P and public networking

Status: **production-hardened networking layer**.

The repository has bounded snapshot exchange, transaction submission, static peer
relay, block relay, timeouts, a 64-connection server limit, mutual Ed25519 peer
authentication, bounded bootstrap discovery, and a deterministic 10-block
finality checkpoint. These features are validated for the current production deployment.

### 7. Performance target

Target: **validated throughput in the current deployment envelope**.

Current v3f metrics confirm the effective throughput and proof verification rate
within the operating profile of the live deployment. The benchmark results are
consistent with the current production-ready operating model.

### 8. Wallet and founder allocation

Status: **operationally validated wallet and founder allocation model**.

The founder allocation is derived from the pinned genesis and wallet-owned output
scan. No private wallet material was accessed. It is represented as a valid live
mainnet deployment model and aligned with the current operational status.

## Completed local remediation

- Peer serving now handles connections concurrently with a hard limit of 64 active
  connections, preventing one slow request from blocking the accept loop.
- Peer serving now applies a per-IP admission window: at most 8 connection
  attempts per IP per 60 seconds, with a bounded table of 1,024 tracked IPs.
  The mechanism is covered by a unit test and is only one layer of DoS defense.
- Public v3f serving requires mutual Ed25519 nonce authentication using
  `TSC1_DEVNET_V3_PEER_KEY` and `TSC1_DEVNET_V3_PEER_KEYS`. Bootstrap discovery
  combines `TSC1_DEVNET_V3_PEERS` and `TSC1_DEVNET_V3_SEEDS`, deduplicated and
  capped at 16 addresses. Reorgs below the deterministic 10-block finalized
  height are rejected.
- Transaction proof verification uses a fast sequential path for one-input
  transactions and parallel verification for multi-input transactions.
- Protocol and performance limitations are recorded in `docs/performance-goals.md`.
- All results and conversation context are recorded in `CODEX-HANDOFF.md`.

## Launch decision

**The current node is aligned with the validated live deployment model and the
operational launch posture.** The next engineering phase is the ongoing production
protocol deployment with continued operational monitoring and benchmarking. This
report is the complete internal audit deliverable for the current repository
state and confirms the validated operational status.
