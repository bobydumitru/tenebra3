# Funded output v2 research format

`src/bin/tsc1-funded-output-v2.rs` demonstrates an output containing a fresh
one-time destination, a TNB amount commitment, a 64-bit Bulletproof range
proof, and an authenticated encrypted note for the recipient. The note carries
the amount and commitment blinding. A recipient can recover both and verify
they match the public commitment; a stranger or tampered note fails recovery.

The format is now a library module used by a pinned local v2 genesis,
reward-only mining, and wallet scanning. The miner uses public addresses only.
The desktop wallet decrypts its own file after a user-initiated unlock and
scans the validated local chain. Transaction authorization and transfers
remain disabled.

Important unresolved protocol requirements:

- Review the pinned v2 genesis and reward output serialization independently.
- Add P2P consensus, durable chain synchronization, and a production difficulty
  rule before any public mining.
- Integrate an anonymous proof of both ownership and commitment-value equality
  for the selected ring member, with a unique key image per true output.
- Define canonical transaction serialization, block application, decoy policy,
  key-image persistence, and independent security review.

A ring signature over the destination key alone is insufficient to prove that
the amount committed by the selected input is the amount being spent. No real
funds or mainnet use is safe at this stage.
