# CERTOaudit
## TENEBRA / TSC-1 External Security Assessment

**Assessment ID:** CERTOaudit-TENEBRA-2026-09-22  
**Issue date:** 2026-09-22  
**Assessment firm:** CERTOaudit  
**Assessment type:** External-style source-code security assessment  
**Assessment status:** NO-GO for public mainnet and real-value deployment  
**Scope:** Rust implementation, consensus candidates, transaction authorization, persistence, peer networking, wallet boundaries, and security tooling in this repository.

> **Attestation boundary:** This file is an externally formatted assessment package prepared from the repository state. It is not proof that an independent CERTOaudit auditor performed or signed a commercial engagement. It must not be presented as an independently issued certification until CERTOaudit verifies the scope, reproduces the evidence, and adds an authorized reviewer identity and signature.

## Executive opinion

CERTOaudit does not recommend public mainnet launch, real-value custody, or exposure of the current node to an untrusted public network. The repository contains substantial defensive engineering and passing automated tests, but the implementation remains a research/devnet candidate. Passing tests and dependency scans do not establish cryptographic soundness, consensus safety, privacy, or operational resilience.

## Evidence reviewed

- Rust source under `src/`, including chain, transaction, spend-state, wallet, and peer modules.
- `Cargo.toml` and the Rust dependency surface.
- Existing internal reviews dated 2026-09-19 and 2026-09-20.
- Fuzz targets and security-testing notes under `fuzz/` and `docs/rust-security-testing.md`.
- Existing test, formatting, Clippy, and RustSec results recorded in the repository handoff.

## Verification record

The repository records the following checks for the assessed state:

- `cargo test --all-targets`: passed in the latest recorded validation cycle.
- `cargo fmt --all -- --check`: passed.
- `cargo clippy --lib -- -D warnings`: passed.
- RustSec audit: zero known vulnerable dependencies; one unmaintained transitive `clear_on_drop` warning through `bulletproofs`.
- Fuzz smoke runs for transaction, block, and authorization decoders: no observed crashes in the recorded bounded runs.
- Ring-proof benchmark: approximately 7.21 ms median verification per 16-member signature in the recorded optimized samples.

These results are evidence of exercised behavior, not a security warranty.

## Findings

### CA-01 — Custom anonymous-spend proof has no independent cryptographic assurance

**Severity:** Critical  
**Status:** Open / release-blocking  
**Evidence:** `src/tsc1_tx_v2.rs`; internal reviews; `CODEX-HANDOFF.md`.

The two-row Ristretto/MLSAG-style proof is handwritten and locally tested. Tests can detect selected mutations, but cannot establish soundness, non-malleability, unlinkability, correct key-image behavior under all adversarial inputs, or absence of inflation paths.

**Risk:** A subtle proof or transcript error could permit unauthorized spending, inflation, or privacy loss.

**Required action:** Obtain an independent cryptographic review; publish a formal specification, security assumptions, cross-implementation known-answer vectors, property tests, and adversarial test results. Keep real-value consensus disabled until acceptance criteria are met.

### CA-02 — Network service remains vulnerable to resource exhaustion by authorized peers

**Severity:** High  
**Status:** Open  
**Evidence:** `src/tsc1_peer_v3.rs`; internal security review.

Connection, snapshot, transaction, and block handling can trigger expensive decoding and full-state validation. Existing frame, connection, and admission limits reduce exposure but do not provide a global work budget, queue backpressure, peer scoring, ban policy, or incremental synchronization strategy.

**Risk:** A compromised or misconfigured authorized peer can consume CPU, memory, file descriptors, and disk I/O.

**Required action:** Add per-peer and global work budgets, bounded worker queues, cancellation, peer scoring/ban policy, metrics, incremental sync, and adversarial load tests.

### CA-03 — Single-writer and crash-consistency guarantees are incomplete

**Severity:** High  
**Status:** Open  
**Evidence:** `src/tsc1_peer_v3.rs`, `src/tsc1_chain_v3.rs`, pending inbox and reorganization paths.

Mining, sync, relay, persistence, and pending-transaction handling can overlap. Atomic rename protects individual files, but repository evidence does not establish a durable single-writer protocol, directory synchronization, crash recovery across multi-step reorganization, or concurrent state invariants.

**Risk:** A crash or race may produce divergent state, lost blocks, stale pending entries, or ambiguous recovery.

**Required action:** Introduce one durable state owner or transactional journal, fsync the required directory metadata, add crash injection/restart tests, and test miner/sync/relay concurrency.

### CA-04 — Consensus parameters are devnet-grade, not public-network security

**Severity:** High  
**Status:** Open / release-blocking  
**Evidence:** `src/tsc1_chain_v2.rs`, `src/tsc1_chain_v3.rs`, internal reviews.

The recorded design still uses weak candidate proof-of-work parameters, a fixed low-difficulty inner reward proof, and timestamp/fork-choice rules that require production specification and adversarial validation. A heavier-fork mechanism in a devnet candidate does not prove resistance to rewriting or reliable network convergence.

**Risk:** Cheap history rewriting, unstable chain selection, consensus divergence, and time-manipulation effects.

**Required action:** Specify production difficulty, median-past-time, fork choice, finality, reorganization limits, reward maturity, and network upgrade rules; validate them with adversarial multi-node simulations.

### CA-05 — Wallet and secret-management controls require production hardening

**Severity:** Medium  
**Status:** Open  
**Evidence:** wallet binaries and peer-key configuration paths.

AEAD, zeroization, and local-only signing boundaries are positive controls. Production readiness still requires explicit password-KDF parameters and calibration, filesystem permission guarantees, secure secret injection, key rotation, backup/recovery procedures, and platform-specific threat modeling.

**Risk:** Endpoint compromise, weak password protection, accidental key exposure, or unsafe operational recovery.

**Required action:** Define the wallet security model, calibrate Argon2 parameters, enforce restrictive file permissions where supported, document key rotation/recovery, and test failure/backup paths.

## Positive controls observed

- Canonical bounded encoding/decoding and trailing-byte rejection.
- Network/version identifiers and domain-separated hashes.
- Duplicate key-image, output, replay, balance, and proof validation paths.
- Clone-then-commit state application for selected batch operations.
- AEAD-protected funded-output notes with tamper detection.
- Fuzz coverage for selected decoder boundaries.
- Explicit project documentation that the current network is not mainnet and the founder allocation is local devnet state.

## Launch decision

**CERTOaudit assessment: NO-GO.** Do not claim mainnet launch, guaranteed anonymity, unhackability, production-ready wallet custody, public transferable TNB value, or independently audited cryptography. The next gate is an independently performed cryptographic and consensus audit after the release-blocking findings are remediated.

## Remediation acceptance gates

1. Signed independent cryptographic review with formal proof specification and vectors.
2. Production consensus specification reviewed against adversarial fork, time, and reorganization tests.
3. Durable single-writer state model with crash/restart and concurrent-node testing.
4. Public-node abuse controls with measured CPU, memory, disk, and bandwidth budgets.
5. Reproducible release builds, dependency policy, monitoring, incident response, and key recovery runbooks.
6. Reassessment of every finding by CERTOaudit or another named independent assessor.

## Reviewer record

**Prepared for external review by:** CERTOaudit package  
**Authorized independent reviewer:** ______________________________  
**Signature / seal:** _____________________________________________  
**Review completion date:** ______________________________________  
**Evidence commit or archive hash:** ______________________________
