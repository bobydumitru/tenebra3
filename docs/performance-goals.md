# TSC-1 performance goals

TSC-1 aims for world-leading throughput and low transaction latency while
preserving private transfers, permissionless participation, and verifiable
security. These are goals, not measured properties of the current prototype.

The published performance metric must be **sustained, fully validated private
transactions per second** on a geographically distributed network. A
transaction counts only after all required privacy proofs and spend checks are
verified and the transaction reaches the stated confirmation level. Raw message
ingestion, mempool acceptance, and synthetic transfers are separate metrics.

Every benchmark report must state transaction size and type, hardware, node
count, geographic distribution, network conditions, test duration, fees,
confirmation latency (median and 95th percentile), stale-block rate, and
whether it used a testnet or a public network. Results must be reproducible.

## 2,000-5,000 TPS target

The project target is 2,000-5,000 fully validated private transactions per
second. This is not achieved by the current v3f candidate. The current
consensus permits at most 16 transactions per block and targets a 30-second
block interval, which caps the protocol at about 0.53 transactions per
second before CPU, disk, or network costs are considered. The measured median
verification cost of the current 16-member ring proof is 6.68 ms per input in
an optimized local build, or about 150 proof verifications per second on the
benchmark machine.

Reaching even 2,000 TPS requires a separately specified production design
with parallel or aggregated privacy-proof verification, a larger bounded
block budget, high-throughput authenticated propagation, parallel state
execution, and a production finality/fork-choice rule. At the current proof
cost, 2,000-5,000 one-input transactions would require roughly 14-34 proof
verification workers before accounting for range proofs, I/O, networking, or
redundancy. Any claimed result must include all privacy and spend checks;
mempool acceptance, unsigned message intake, and unverified batch throughput
do not count.

The current 30-second proof-of-work block target does not imply 30-second
finality or a particular TPS. The 50-year mining emission schedule is separate
from transaction throughput. Do not claim TSC-1 is the fastest blockchain until
independent, like-for-like measurements support that claim.
