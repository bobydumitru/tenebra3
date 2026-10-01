# Public, Unlisted v3f Testnet Deployment

This is a deployment runbook for a public but unannounced testnet. It does not
create DNS records or VPS instances automatically.

## DNS

After buying the domain, create A/AAAA records pointing to real VPS addresses:

```text
seed1.tenebra-network.com -> <node-1-public-ip>
seed2.tenebra-network.com -> <node-2-public-ip>
```

Use `seed1.tenebra-network.com:39453` and
`seed2.tenebra-network.com:39453` in `TSC1_DEVNET_V3_SEEDS`.

## Node configuration

Copy `config/public-testnet.env.example` to a protected file on each VPS.
Replace every placeholder. Each node needs a unique private seed, and every
node's public key must be present in the allowlist on the other nodes. Never
commit or send `TSC1_DEVNET_V3_PEER_KEY` through chat.

Open only the selected TCP P2P port in the VPS firewall. Keep SSH restricted
to the operator's administration addresses. Store blocks under a persistent
volume and back up the configuration separately from the private key.

## Start a node

From the built release directory, load the protected environment file and run:

```text
tsc1-devnet-v3 status
tsc1-devnet-v3 serve 0.0.0.0:39453
```

Start at least two independently hosted nodes. From a second node, verify:

```text
tsc1-devnet-v3 sync seed1.tenebra-network.com:39453
```

The server requires Ed25519 authentication variables before public serving.
Unauthenticated local test helpers do not represent public operation.

## Launch boundary

The current v3f code is an authenticated public testnet candidate. It is not a
mainnet release: the custom privacy proof is unaudited, the throughput target
of 2,000-5,000 fully validated TPS has not been measured, and the protocol is
still identified as v3f/devnet. Do not assign real-world value to its balances.
