# TSC-1 internal launch security review (2026-09-19)

Scope: local source inspection of v3b consensus, transaction authorization,
peer exchange, persistence, and the devnet CLI, with later v3d remediations
tracked below. This is an internal review,
not an independent cryptographic audit or a mainnet certification. No private
wallet files or keys were accessed.

## Release-blocking findings

1. **Critical: fixed, trivial PoW and no chain selection.** Both the inner
   reward block (`src/tsc1_chain_v2.rs`, `Block::mine` and `Chain::append`) and
   outer transaction block (`src/tsc1_chain_v3.rs`, `BlockV3::mine` and
   `ChainV3::append`) only require the first SHA-256 byte to be zero. There
   is no difficulty adjustment or cumulative-work fork choice. The v3 peer
   (`src/tsc1_peer_v3.rs`, `append_extension`) rejects all divergent chains.
   A public network could neither resist cheap rewriting nor converge after
   ordinary competing blocks. Replace the consensus and test adversarial
   forks before any public-value launch.
2. **High: transaction lifecycle is not production-ready.** The v3d CLI
   wallet now creates one-input signed transfers, nodes accept bounded TCP
   submissions, keep a 16-transaction disk inbox, relay to explicitly
   configured peers, and mine pending transactions. A synthetic two-node
   end-to-end test passes. Freshly mined blocks are also pushed to configured
   peers, where they are validated as direct extensions. This is still a
   single-writer research protocol: no reorganization, durable queue
   recovery, fee selection, or public-node abuse resistance. The graphical v2 wallet
   remains separate and cannot send on v3d.
3. **High: timestamp policy needs production review.** The v3d candidate
   rejects blocks more than 120 seconds ahead of local time and requires 10
   blocks of maturity for every mining reward used in a transaction ring.
   The older v2 chain is unchanged; it only requires increasing timestamps.
   There is no median-past-time rule or analysis of clock disagreement and
   reorganization effects. Define and test the remaining production rules.
4. **High: unaudited custom anonymous-spend proof.** The two-row ring proof
   in `src/tsc1_tx_v2.rs` is handwritten and only exercised by local tests.
   Those tests cannot establish soundness, key-image uniqueness under all
   adversarial inputs, or resistance to inflation and privacy failures.
   Independent cryptographic review, vectors, and fuzz/property tests are
   required before it protects real funds.
5. **High: public-node abuse resistance is absent.** `src/tsc1_peer_v3.rs`
   serially handles unauthenticated TCP clients and revalidates an entire
   snapshot for each request/import, with no peer management, request budget,
   or incremental sync. The 64 MiB frame limit is useful but insufficient
   against resource exhaustion. Do not expose this service as production P2P.

## Additional risks

- `src/tsc1_chain_v3.rs`, `persist_block`, writes then renames one file but
  does not synchronize the directory or coordinate concurrent miners/syncs.
  Crash and race behavior needs tests and a durable single-writer policy.
- The v3b 90/10 fee split is checked by consensus, but the fixed treasury
  output deliberately has a publicly derivable one-time destination; it
  is not a private payment. Confirm this disclosure is acceptable to policy.
- There is no evidence in this review of independently operated public nodes,
  monitoring, reproducible release artifacts, or an external audit report.

## Decision

**No-go for mainnet and real-value claims.** The pinned 10 million TNB is a
validated local devnet allocation, not a publicly transferable balance.
Continue isolated testnet development; rerun this review after the critical
findings are fixed and obtain independent security review before launch.

## Remediation log

- 2026-09-19: v3c enforces a 120-second future timestamp bound and rejects
  a fully mined block beyond it. Block/chain tags, genesis anchor, and peer
  magic changed so v3b snapshots are not silently accepted. This does not
  resolve the median-time, reward maturity, or other release blockers above.
- 2026-09-19: v3d adds a 10-block maturity check for all mining rewards in
  transaction rings. A mined block containing an immature ring member is
  rejected; a mature signed transfer still passes. V3d changes the block,
  chain, genesis-anchor, and peer identifiers. It does not solve PoW, fork
  choice, public transaction relay, or independent cryptographic review.
- 2026-09-19: the v3d miner CLI accepts one canonical signed transaction
  file, prevalidates spend state before PoW, includes it in the mined block,
  and uses the consensus-checked 90/10 fee payout builder. This is not a
  mempool, transaction relay, wallet signing flow, or public network.
- 2026-09-20: added explicit `tsc1-wallet sign-v3` file creation; the node
  accepts `submit`, validates and stores up to 16 transactions, relays newly
  accepted transactions to up to eight configured peers, and mines pending
  transactions. A synthetic wallet-to-two-node-to-block test passes. The
  protocol remains unsuitable for public funds without the critical PoW,
  fork-choice, node-hardening, and audit work above.
- 2026-09-20: newly mined blocks are pushed to configured peers using a
  bounded block message; receiving nodes revalidate and persist only direct
  extensions. The two-node synthetic test confirms matching validated tips
  after a signed transfer. No fork resolution or production DoS resistance.

## 2026-09-20 v3e internal review update

- V3e separates block, chain, genesis-anchor, and peer identifiers. Its CLI
  defaults to `data/devnet-v3e/blocks`, leaving previous v3d data untouched.
- Outer PoW now commits a validated difficulty field, starts at 12 leading
  zero bits, and adjusts one bit per 16-block window within 12..24 bits.
  Nodes sum required work and snapshot sync chooses a strictly heavier
  validated fork. The old fork and pending inbox are archived on reorg.
- These parameters are intentionally still **devnet-only**. Twelve to 24
  bits are cheap to attack, timestamps can influence retargeting, and the
  inner v2 reward block still uses a fixed 8-bit target. No production
  security claim follows from adding a fork-choice rule.
- Important remaining release blockers: independent review of the custom
  anonymous transaction proof, single-writer/durable state and crash tests,
  public-node DoS resistance, automatic fork recovery and peer management,
  production PoW/timestamp specification, adversarial testing, and external
  audit. This internal review is not mainnet certification.
- Verification: full `cargo test --all-targets` passed, as did strict library
  clippy. All-target clippy passes without `-D warnings`; legacy binaries
  still have unused-code warnings. Passing tests do not prove the anonymous
  proof secure against novel attacks.
- RustSec scanned both the application and fuzzing lockfiles on 2026-09-20:
  zero known vulnerabilities; one unmaintained transitive dependency,
  `clear_on_drop 0.2.5` via `bulletproofs 5.0.0` (RUSTSEC-2026-0283).
  This warning needs a planned proof-library migration, not an unreviewed
  dependency swap. See `docs/rust-security-testing.md`.

## 2026-09-20 v3f signature-cost update

- Ten optimized samples measured 7.21 ms median verification per 16-member
  anonymous signature on this machine (10.40 ms maximum). The former
  16-input by 16-transaction block budget allowed 256 proofs, about 1.85 s
  of signature CPU alone at the median. V3f limits transactions to two
  inputs, reducing the block ceiling to 32 proofs (about 0.23 s median).
- V3f changes block/chain/anchor/peer identifiers, transaction network ID,
  and default storage path. Existing v3e data is not silently migrated.
  This caps one consensus workload but does not stop repeated unauthenticated
  submissions, serial TCP blocking, or expensive range-proof validation.
- Three short Windows ASan/libFuzzer runs passed without crash: transaction
  decoding 406,721 inputs, block decoding 529,713, and authorization proof
  decoding 439,298 after fixing its exact-length harness. These are smoke
  tests, not a comprehensive cryptographic audit.
