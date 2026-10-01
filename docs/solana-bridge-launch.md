# Solana bridge launch gate

The TENEBRA multichain wallet may display Solana addresses and public balances, but SOL deposits and cross-chain swaps remain disabled until every item below is complete.

## Required components

1. A reviewed Solana program that accepts SOL deposits and emits a unique deposit event.
2. A multisig vault address controlled by the bridge operators. No private key belongs in this repository or in the browser wallet.
3. A TENEBRA asset definition for `tSOL`, with mint authority restricted to the bridge consensus path.
4. A finalized Solana RPC verifier that checks program ID, vault address, amount, recipient, slot finality, and an unrepeatable deposit identifier.
5. A TENEBRA-side mint operation that accepts only verified deposit proofs and rejects replay.
6. A burn-and-release operation for `tSOL` that is authorized by the bridge and sends SOL to the user's Solana address.
7. Independent tests for duplicate deposits, wrong program, wrong vault, reorg/finality changes, malformed proofs, and insufficient reserves.

## Current state

The bridge is deliberately disabled. `config/solana-bridge.env.example` contains empty program, mint, and vault identifiers. Do not send SOL to any address claiming to be a TENEBRA bridge vault until these identifiers are published and independently verified.

## Activation rule

The API must refuse deposits unless `TENEBRA_SOLANA_BRIDGE_ENABLED=true` and all identifiers are non-empty. Enabling the flag before the program, multisig, verifier, and reserve tests are complete would allow unbacked or unrecoverable credits and is not permitted.
