# TSC-1 fee and reward policy

The mainnet candidate schedules the new rules for block 22,000. All nodes must
be upgraded before activation. Recheck the public chain height before release.

- TNB transfer: 1% of the confidential primary payment output, rounded up to
  the next nox, is paid to the TNB treasury from block 22,000. The payment is
  output index 0; later outputs are change by wallet convention. A paired range
  proof binds the public `fee_nox` to the hidden output amount without revealing
  it. Before activation, consensus requires only a positive fee.
- TSC-1 asset transfer: 1% of the nominal asset amount in TNB to the TNB
  treasury, active from block 20,000. An issuer may add an optional 0-8% fee in
  TNB to its configured treasury from block 22,000.
- Asset creation: 100 TNB per fungible token and 10 TNB per NFT from block
  22,000. Exactly one fee is attached to the signed creation operation. The
  legacy creation fee remains 10 TNB before activation.
- DEX swap: 0.30% through block 21,999 and 1% from block 22,000. The full DEX
  fee is routed to the configured TNB treasury address, in the input asset.
- Scheduled mining reward: from block 22,000, 90% is paid to the miner and 10%
  to the TNB treasury. Both outputs count against the existing mining
  allocation and maximum supply. Before activation, the reward goes to miner.

Transaction-fee routing and scheduled mining rewards are separate policies.
The treasury address is configured in `config/treasury-address.txt`; the
founder genesis allocation remains separate. Fee revenue and market value are
not guaranteed.
