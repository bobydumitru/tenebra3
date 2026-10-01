# TSC-1 Cross-Implementation Vector Set

These vectors are canonical byte-level fixtures for an independent
implementation. They are generated from the repository's canonical encoders;
a second implementation must reproduce every expected value before consensus
interoperability is claimed.

## Fixed protocol constants

```text
transaction_unsigned_tag = 5453432d313a74783a756e7369676e65643a7631
block_v3_tag             = 54534331424c4b334631
journal_tag              = 545343314a4f55524e414c31
network_id_v3f           = 1fd83bc5be9d9528bd98d31eb6fab09c7ef955e528ad0f3709298110b03666d4
ring_size                = 16
authorization_bytes      = 1056
```

## Required generated cases

An implementation must generate and compare canonical bytes and SHA-256 IDs for:

1. the same deterministic wallet seed and address;
2. the same one-time output at indexes 0 and 1;
3. one authorization proof for each signer position 0 through 15;
4. a transaction with the fixed network ID, expiry, fee and outputs;
5. the corresponding transaction ID and unsigned signing hash;
6. a genesis-only v3 chain and one mined block;
7. a v3 block with miner and treasury fee outputs;
8. a journal record and its chained record hash.

## Negative vectors

Each implementation must reject identical fixtures after one mutation of:

- every proof scalar and each key-image byte;
- every ring member ID and commitment;
- the unsigned transaction message, expiry, fee and output order;
- block previous hash, difficulty, timestamp, nonce and fee outputs;
- journal previous hash, anchor hash, record index and transaction bytes.

## Status

The repository has deterministic canonical encoders and local mutation tests.
The expected hash/byte table for the cases above still requires an independent
implementation to reproduce and sign off. Until then this file is a vector
contract and not evidence of cross-implementation compatibility.
