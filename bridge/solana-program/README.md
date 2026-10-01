# TENEBRA Solana bridge program

This is the first on-chain bridge component. It is intentionally incomplete for mainnet activation: it accepts SOL deposits into an explicitly configured vault and records a unique deposit ID, but it does not mint `tSOL` by itself.

## Instructions

- `Initialize`: creates the PDA state account at `find_program_address([b"vault", authority], program_id)` and stores the authority and vault public keys.
- `Deposit`: transfers lamports from the signed depositor to the configured vault and records a 32-byte deposit ID. Replays are rejected.

The `recipient` field is recorded in the signed instruction format for the off-chain TENEBRA verifier. The verifier must read the transaction, verify the program ID, vault, finalized slot, amount, recipient, and deposit ID before submitting a TENEBRA mint operation.

## Mainnet restrictions

- No program ID, vault address, authority, or private key is stored in this repository.
- The TENEBRA bridge remains disabled until this program is deployed, tested, reviewed, and connected to the verifier.
- The vault must be multisig or otherwise independently controlled. A single key is not an acceptable production custody model.

## Build prerequisites

Install the Solana toolchain and Rust BPF/SBF target. Then run:

```powershell
cargo build-sbf
```

The resulting program must be deployed to a new program ID and its address recorded only after independent verification.
