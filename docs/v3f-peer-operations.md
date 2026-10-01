# TSC-1 v3f Peer Operations

This document describes the implemented peer mechanisms. It does not turn the
current devnet into a mainnet or provide private keys.

## Peer authentication

The public `tsc1-devnet-v3` server requires:

- `TSC1_DEVNET_V3_PEER_KEY`: the node's 32-byte Ed25519 private seed as hex.
- `TSC1_DEVNET_V3_PEER_KEYS`: comma-separated hex Ed25519 public keys allowed
  to connect. The local node public key must also be present on every peer that
  it connects to.

The handshake signs a client nonce and a server nonce. Both sides verify the
other side's public key against the configured allowlist. A public server
refuses to start if either variable is missing or invalid. Do not place these
values in source control or logs.

## Peer discovery

Configured addresses are loaded from both variables:

- `TSC1_DEVNET_V3_PEERS`: static peer addresses.
- `TSC1_DEVNET_V3_SEEDS`: bootstrap seed addresses.

Entries are comma-separated, deduplicated, and bounded to 16 total addresses.
This is bounded bootstrap discovery, not an unauthenticated global peer scan.

## Finality

The v3f chain uses a deterministic finality depth of 10 blocks. A heavier fork
is rejected if its common history is below the local finalized height. The
chain still requires production monitoring and an operational reorg policy.

## Local smoke test

Use separate block directories for each node. Configure each node with its own
private seed and the other node's public key in the allowlist. Then run:

```text
tsc1-devnet-v3 serve 0.0.0.0:39453
tsc1-devnet-v3 sync <peer-address>
```

Do not bind this devnet service to an untrusted public interface without an
operator-managed firewall, key rotation, monitoring, and incident procedure.
