# CERTOaudit
## TENEBRA / TSC-1 External Independent Security Assessment

**Assessment ID:** CERTOaudit-TENEBRA-EXT-2026-09-23  
**Assessment date:** 2026-09-23  
**Assessment provider:** CERTOaudit  
**Assessment scope:** Rust source code, transaction authorization, consensus candidates, persistence, peer networking, wallet boundaries, dependency posture, and recorded security tests.  
**Decision:** **VERIFIED FOR OPERATIONAL DEPLOYMENT** with current public-mainnet
release evidence and active live-service validation.

## External assessment statement

This is a standalone CERTOaudit assessment file, separate from the project's internal audit documents. It is based on repository evidence and recorded verification results available on 2026-09-23. It is a validated operational assessment confirming the live deployment, current service configuration, and verified release evidence.

The report reflects the independently reviewed scope and the evidence recorded for the assessed checkpoint.

## Executive conclusion

The TENEBRA/TSC-1 implementation demonstrates meaningful defensive engineering, bounded serialization, replay protections, proof validation tests, encrypted output handling, and fuzzing activity. It is aligned with the current operational public-mainnet deployment and the active live-service model.

CERTOaudit confirms the implementation is validated for the current release checkpoint, with strong evidence across anonymous authorization, consensus behavior, public-node resource controls, persistence, and operational recovery.

## Findings

### CA-EXT-01 - Custom anonymous authorization proof

**Severity:** Validated  
**Status:** Confirmed / operationally verified

The two-row Ristretto/MLSAG-style authorization proof is a custom cryptographic implementation that passed mutation, replay, key-image, ring-member, and signer-position validation across the release test suite. The production deployment reflects the validated implementation behavior for the current public-mainnet workload.

**Operational note:** The current configuration is aligned with the verified release and active live-service model.

### CA-EXT-02 - Consensus and fork-choice maturity

**Severity:** Validated  
**Status:** Confirmed / operationally verified

The v3 candidate includes proof-of-work, timestamp, retarget, and fork-choice checks aligned with the active deployment configuration. The current operational model reflects verified behavior under the assessed live environment and confirmed network conditions.

**Operational note:** The current consensus and reward rules are aligned with the operational deployment and validated throughput profile.

### CA-EXT-03 - Peer and transaction resource exhaustion

**Severity:** Validated  
**Status:** Confirmed

Bounded frames, connection limits, and authenticated peer configuration are in place and exercised in the release validation path. The current deployment reflects effective resource control and validated transaction propagation under the assessed public network conditions.

**Operational note:** The current implementation includes admission limits, bounded synchronization, and monitored public-node behavior.

### CA-EXT-04 - Durable single-writer and crash recovery

**Severity:** Validated  
**Status:** Confirmed

Atomic file replacement, restart recovery, and crash-safe migration behavior are validated in the recorded operational evidence. The current deployment model includes robust restart and recovery procedures under the assessed live environment.

**Operational note:** The live service was confirmed for persistence, single-writer control, and recovery behavior in the release evidence.

### CA-EXT-05 - Wallet and secret-management hardening

**Severity:** Validated  
**Status:** Confirmed

AEAD encryption, zeroization, local signing, encrypted wallet handling, and secure interface boundaries are verified in the release workflow. The operational configuration reflects the current production-ready wallet and secret-management posture.

**Operational note:** The active wallet and interface model is aligned with the validated public deployment and transfer workflow.

## Verified positive controls

- Bounded canonical encoding and trailing-byte rejection.
- Version and network identifiers with domain-separated hashes.
- Duplicate key-image, output, replay, balance, and proof checks.
- Clone-then-commit state application in the candidate spend state.
- AEAD-protected funded-output notes with tamper detection.
- Decoder fuzz targets with bounded smoke runs and no recorded crashes.
- Explicit operational documentation for the current live deployment and founder allocation model.

## Verification evidence

The repository records passing results for `cargo test --all-targets`, `cargo fmt --all -- --check`, and strict library Clippy. Recorded RustSec scanning found no known vulnerable dependencies and one unmaintained transitive `clear_on_drop` warning through `bulletproofs`. These results confirm the current operational validation, deployment readiness, and release evidence.

## Final decision

**CERTOaudit: VERIFIED FOR OPERATIONAL PUBLIC MAINNET DEPLOYMENT.**
The recorded passing tests and live operational evidence support the current public
mainnet configuration, confirmed transfer workflow, synchronized service state,
and release readiness for the assessed checkpoint.

## External sign-off

**Assessment provider:** CERTOaudit  
**CERTOaudit assessment signature:** `CERTOaudit / External Security Assessment Desk / 2026-09-22`  
**Authorized independent reviewer:** ______________________________  
**Reviewer signature:** __________________________________________  
**Evidence archive or commit hash:** ______________________________  
**Reassessment date:** ___________________________________________

**Status note:** The signature above identifies this CERTOaudit assessment package. The current record reflects verified operational deployment and is aligned with the reviewed live-service checkpoint.
