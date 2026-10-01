# TENEBRA Roadmap

Last updated: 2026-09-26

This roadmap describes the work needed to operate TENEBRA reliably and to make future releases reproducible. The public wallet currently calculates a 1% transaction fee automatically from the transfer amount.

## Current State

- Mainnet status: reported live by the operator after the internal audit dated 2026-09-20.
- Web wallet: local signing, encrypted browser storage, QR receiving address, recipient QR scanning, automatic login, logout, transaction history and automatic 1% fee calculation.
- Network operations: public API, seed endpoints, health checks, backups and monitoring scripts are present in the repository.
- Product surfaces: DEX, NFT Marketplace and Scan pages are part of the public web experience and require their own live-data and failure-state verification.
- Audit status: the internal audit remains a historical record of the pre-mainnet state; current production claims require current evidence.
- Dependency note: `clear_on_drop 0.2.5` is unmaintained indirectly through `bulletproofs` and remains a tracked maintenance item.

## Phase 1: Mainnet Stabilization

Goal: establish a repeatable operational baseline for the live network.

- [ ] Run live health checks from an independent machine.
- [ ] Confirm seed endpoint reachability, peer connectivity, block propagation and transaction confirmation.
- [ ] Verify that submitted transactions are visible from more than one public observer.
- [ ] Record block height, chain tip, peer count, confirmation latency and error rate daily.
- [ ] Confirm restore-from-backup on a clean host.

Exit criteria:

- Two independent observers agree on chain height and tip.
- A test transfer completes, confirms and appears in transaction history.
- Restore and rollback procedures are documented and tested.

## Phase 2: Security and Dependency Hardening

Goal: reduce known maintenance and operational risk.

- [ ] Investigate a maintained replacement or upgrade path for the `clear_on_drop` dependency chain.
- [ ] Run `cargo audit`, `cargo clippy --lib -- -D warnings`, formatting checks and all targets in CI.
- [ ] Review cryptographic dependencies and record compatibility results before changing versions.
- [ ] Add dependency pinning, checksum review and reproducible build instructions.
- [ ] Rotate production keys through a documented procedure and test recovery.

Exit criteria:

- No unreviewed dependency upgrade is deployed.
- Security checks pass in a clean environment.
- Key rotation and emergency recovery are tested without exposing private material.

## Phase 3: Wallet and Transfer UX

Goal: make common wallet actions clear and dependable.

- [ ] Publish the wallet version containing recipient QR scanning and the 1% fee calculation.
- [ ] Verify on desktop and mobile that the fee field is empty on load and becomes 1% only after an amount is entered.
- [ ] Verify examples: 10 TNB -> 0.1 TNB fee; 20 TNB -> 0.2 TNB fee; 30 TNB -> 0.3 TNB fee.
- [ ] Verify logout, automatic reconnection and encrypted local storage behavior.
- [ ] Test pending, confirmed and failed transfer states against the public API.
- [ ] Add a clear network/status indicator and a recovery message for stale chain data.

Exit criteria:

- Wallet behavior matches the published fee policy.
- A transfer can be followed from signing to confirmation without ambiguous status.
- No private seed or password is sent to the server.

## Phase 4: DEX, NFT Marketplace and Scan

Goal: make the public product surfaces useful, consistent and observable on mainnet.

- [ ] DEX: verify market data, asset balances, quote freshness and transaction status against the live API.
- [ ] DEX: define the supported swap/listing lifecycle and clear unavailable-market states.
- [ ] NFT Marketplace: verify collection loading, metadata, ownership display and purchase/listing flows.
- [ ] NFT Marketplace: validate rejected, pending and confirmed transaction states without losing user context.
- [ ] Scan: verify blocks, transactions, addresses and search results against the same public chain tip as the wallet.
- [ ] Scan: add clear empty, delayed-index and network-error states.
- [ ] Add mobile layout checks and independent smoke tests for all three surfaces.

Exit criteria:

- DEX, NFT Marketplace and Scan show consistent chain height and transaction status.
- Every write action exposes pending, confirmed and failed states.
- A live-data outage is visible to users and does not present stale data as confirmed.

## Phase 5: Operations and Observability

Goal: detect failures before users do.

- [ ] Maintain uptime, peer, block-production, transaction-confirmation and disk-space alerts.
- [ ] Test chaos and concurrency smoke checks on a controlled environment.
- [ ] Verify log rotation, backup retention and alert delivery.
- [ ] Publish an incident response runbook with severity levels and contacts.
- [ ] Define maintenance windows and a public communication procedure.

Exit criteria:

- Alerts are demonstrated with a controlled failure.
- An operator can restore service from backup using the runbook.
- Public status updates distinguish incidents, maintenance and confirmed recovery.

## Phase 6: Independent Review and Release Governance

Goal: make security and release claims externally reproducible.

- [ ] Freeze a release candidate with a tagged commit and manifest.
- [ ] Provide build, test, genesis, network-parameter and deployment evidence.
- [ ] Commission an independent review of cryptography, consensus, networking and wallet boundaries.
- [ ] Track every finding with owner, severity, evidence, remediation and verification.
- [ ] Publish a release note that separates verified facts, operator reports and open limitations.

Exit criteria:

- Independent reviewers can reproduce the stated test results.
- Release-blocking findings are closed or explicitly accepted by a documented decision.
- Mainnet status and wallet fee behavior are consistent across code, UI and documentation.

## Release Cadence

- Patch releases: security fixes, operational fixes and documentation corrections.
- Minor releases: backward-compatible wallet, API and observability improvements.
- Major releases: consensus, cryptography, network identity or transaction-format changes; require a migration plan, testnet rehearsal and explicit operator approval.

Every release should include the commit identifier, deployment time, changed consensus behavior, test evidence, rollback path and any remaining limitations.
