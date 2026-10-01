# Mainnet candidate preparation

Status: local implementation and testing; nothing has been deployed to the server.
The user requires at least 150 anonymous transactions confirmed per second and
has explicitly approved local protocol changes needed to pursue that target.

## Implemented candidate

- Build feature: `mainnet-candidate`; node binary: `tenebra-node`.
- Separate proposed genesis, transaction network ID, handshake and data directory.
- Public participation without an allowlist; devnet retains authentication.
- Up to 9,000 transactions and 64 MiB per candidate block; 30-second target.
  This is theoretical capacity, not evidence of measured throughput.
- Mainnet-specific block encoding and content-bound PoW header. Nonce search
  reuses the content commitment; validation still binds all block fields.
- Mainnet difficulty ceiling 120 bits; devnet ceiling remains 24 bits.
- Public PoW fork choice uses validated cumulative work. Ten successor blocks
  are confirmations, not an irreversible finality guarantee.
- Cached chain state, bounded durable transaction batches, one writer per data
  directory, incremental block synchronization and optional integrated mining.
- Proof cache entries bind the full signed transaction AND full referenced ring
  output contents. Expiry, maturity and spent-state checks are always repeated.
- Immutable public Bulletproof generators are reused; fresh transcripts and
  proof verification are retained. No proof algorithm or proof strength was
  weakened for the optimization.

Public founder and treasury addresses remain the user-confirmed files in config.
No private wallet keys were read, exported or sent to a server.

## Measurements to date

All results below are from the local i3-8145U (2 cores, 4 logical CPUs), not the
Ubuntu server. Client transaction/proof construction is outside measured time.
The workload uses one ring input, two confidential outputs and a fee per payment.

| Measurement | Result | What it establishes |
|---|---:|---|
| Historical v4 validation benchmark | 249.72 tx/s | In-memory validation; synthetic settlement only |
| New 1,024-tx complete local pipeline, before generator reuse | 147.49 tx/s | TCP, disk, PoW and ten successor blocks; accelerated timestamps |
| Same pipeline after generator reuse | 226.03 tx/s | Same accelerated local scope; not sustained public-network TPS |
| Sustained wall-clock gate, 20,000 unique transactions | 166.44 TPS average; 166.32 minimum | Four 5,000-tx workload blocks and ten successors, real 30-second intervals |

The sustained gate requires both the average confirmed throughput and the lowest
confirmation-window throughput to be at least 150 tx/s. It counts only workload
transaction IDs, excludes warm-up confirmations from its steady-state rate,
and reloads the chain from disk before passing. The intended steady measurement
window is about 90 seconds following confirmation warm-up. It uses a controlled
single-node local chain, not public competing miners or an independent server.

Artifacts: `docs/performance/confirmed-tps-local-20260922.log` and its source
fingerprint JSON. The sustained run uses the exact code identified there; later
regression-test additions do not alter the running executable.

## Reproduce

In the local project terminal, or later from the project on the server:

    python deploy/measure-mainnet-candidate.py --mode accelerated
    python deploy/measure-mainnet-candidate.py --mode sustained

The sustained run first prepares valid funded outputs and unique signed
transactions. Preparation can take several minutes. The timed block schedule
then takes about seven minutes, followed by a full recovery check. No arbitrary
funded outputs or fabricated settlement heights are used in the new tests.

For candidate binaries, keep a separate output directory:

    cargo build --locked --release --features mainnet-candidate --target-dir target/mainnet-candidate --bin tenebra-node --bin tsc1-wallet --bin tenebra-wallet

The default build still selects devnet. Do not reuse devnet data directories.

## Remaining launch work

- Sustained local gate passed; candidate regression passed (63 tests). Final default-devnet regression passed (55 tests); CLI cleanup and both candidate CLI tests passed. See CODEX-HANDOFF.md for the checkpoint.
- Measure the actual server and a second independently validating node. Local
  loopback figures do not establish Internet throughput or public fork behavior.
- Exercise public peer propagation, forks, concurrent requests and recovery.
- Assess long-running growth: the candidate retains chain/output state in RAM;
  a short throughput gate does not establish days of sustained capacity.
- Verify Linux installation and operational settings with the user in PuTTY,
  one explicitly labelled command at a time. No server cutover has occurred.

The proof system currently uses two-member rings. These performance numbers do
not establish anonymity strength, resistance to traffic analysis, or uniqueness
relative to other currencies. The old audit documents were not used or changed.

## Ubuntu server measurement - 2026-09-22

The same controlled sustained gate passed on the Ubuntu server: 166.68 confirmed TPS average, 166.14 minimum interval, 20,000 transactions and ten successor blocks. Steady window: 89.99 seconds; whole test: 803.53 seconds. Candidate regression: 54 library and 2 node CLI tests passed.

Evidence: performance/confirmed-tps-sustained-20260922T201544Z.json and .log. Retrieved locally and all recorded source hashes verified. This updates the earlier pending-server-measurement status. The raw external_server_tps label is hardcoded; this run was on Ubuntu, but external Internet peers and competing public miners remain unmeasured. No mainnet cutover occurred.
