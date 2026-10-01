# TSC-1 TNB transaction validation status

The local validator in `src/bin/tsc1-tx-validator.rs` checks TNB asset identity,
input references, duplicate or already-spent inputs, one-time output points,
bounded output range proofs, amount conservation, and a positive fee. Tests
cover balanced private-amount examples and malformed transactions.

**All consensus transfers still fail closed.** The current code has no
privacy-preserving proof that a spender controls an input. It also has no
network-wide UTXO database, transaction ordering, atomic block application,
fee payout integration, or peer-to-peer consensus. A locally passing public
rules check is not an accepted payment and does not make TNB spendable.

Before throughput benchmarking can describe real transactions, implement and
review private spend authorization, persistent state transitions, block-level
double-spend checks, transaction serialization, fee payouts, and network
consensus. Measure full verification and confirmation, not only proof checking.

No mainnet has been created. The founder and treasury addresses are public
configuration for the research prototype only, not funded accounts.
