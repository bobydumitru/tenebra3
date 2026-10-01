# Ring Size and Anonymity Analysis

## Current parameter

The transaction protocol now requires `RING_SIZE = 16`. A transaction contains
one real output and 15 decoys selected from eligible mature outputs. Ring member
IDs are sorted and duplicate IDs are rejected.

## Why 16

A two-member ring provides only one decoy and is a demonstration parameter, not
a meaningful anonymity set. Sixteen members provide a bounded verification cost
and match the existing transaction CPU budget, while preserving the protocol's
fixed-size encoding. This is a protocol parameter, not a measured anonymity
guaranty.

## Decoy requirements

The wallet signer must select decoys that are:

- mature and present in the validated output registry;
- not the owned output;
- not duplicated in the ring;
- valid funded outputs with valid range proofs;
- eligible under the same chain-height rules as the real member.

The current signer path selects 15 eligible IDs and the consensus path resolves
all 16 members before proof verification.

## Limitations

A ring size of 16 does not prove a 16-member effective anonymity set. The
selection distribution, wallet timing, amount distribution, output age,
activity correlation and adversarial decoy knowledge can reduce the effective
set. A reviewer must analyze those distributions and require simulation or
published methodology before making privacy claims.

## Required vectors

An audit package should include fixed vectors for each signer position, with the
same 16 ring members, message, key image, commitment differences, proof bytes,
and expected verification result. Mutations must cover every ring key,
commitment, response, key image and signed transaction field.
