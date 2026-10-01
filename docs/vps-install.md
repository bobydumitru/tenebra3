# VPS installation

The deployment files are intended for the Hostico Ubuntu 24 Go1 server.
They do not contain keys, passwords, tokens, or payment data.

## Build the release locally

```text
cargo build --release --bin tsc1-devnet-v3
```

Copy `target/release/tsc1-devnet-v3`, `deploy/install-v3f-ubuntu.sh`, and
`deploy/tenebra-v3f.service` to the server. Keep the private peer seed only on
the server.

## Install on Ubuntu

```text
sudo bash install-v3f-ubuntu.sh /path/to/release
sudo nano /etc/tenebra/v3f.env
sudo systemctl restart tenebra-v3f
sudo systemctl --no-pager status tenebra-v3f
```

Required protected values in `/etc/tenebra/v3f.env`:

```text
TSC1_DEVNET_V3_PEER_KEY=<node-private-seed-hex>
TSC1_DEVNET_V3_PEER_KEYS=<allowlisted-public-key-hex>
TSC1_DEVNET_V3_SEEDS=seed1.tenebra-network.com:39453
TSC1_DEVNET_V3_BLOCKS_DIR=/var/lib/tenebra-v3f/blocks
```

The installer enables UFW for SSH and TCP `39453`, creates a locked-down
`tenebra` service account, enables automatic restart, and keeps chain data in
`/var/lib/tenebra-v3f/blocks`.

## Backup

The installer also installs `deploy/backup-v3f.sh` as
`/usr/local/sbin/backup-tenebra-v3f` and runs it daily with a systemd timer. It
creates an atomically published compressed block backup, verifies the tar
archive, writes a SHA-256 manifest, and deletes local backups older than 14
days. Keep at least one copy outside this VPS.

To verify a restore without overwriting the live chain, use a separate target:

```text
sudo systemctl stop tenebra-v3f
sudo restore-tenebra-v3f /var/backups/tenebra-v3f/blocks-<timestamp>.tar.gz /var/lib/tenebra-v3f/restore-check
sudo systemctl start tenebra-v3f
```

The restore script validates the checksum when present, decodes the complete
chain with the installed node binary, then atomically moves the previous target
aside as `.pre-restore.<timestamp>`. Remove that directory only after the
restored node has passed its health checks.

The installer enables `tenebra-v3f-healthcheck.timer`, which runs every minute.
Failures are visible with:

```text
systemctl status tenebra-v3f-healthcheck.timer
journalctl -u tenebra-v3f-healthcheck.service --since today
```

The node writes service output to `/var/log/tenebra/v3f.log`. Logrotate keeps
14 compressed rotations and caps an individual log at 50 MiB. The alert unit
records health failures in journald and can post JSON to an operator webhook
when `TSC1_DEVNET_V3_ALERT_WEBHOOK` is set in `/etc/tenebra/v3f.env`.

After changing the environment or service files, apply them with:

```text
sudo systemctl daemon-reload
sudo systemctl restart tenebra-v3f
sudo systemctl start tenebra-v3f-healthcheck.service
sudo logrotate -f /etc/logrotate.d/tenebra-v3f
```

The webhook URL is an operational secret and must not be committed or printed.

### Second independent node

Install the same release on a second VPS using the same installer, but generate
a new Ed25519 seed and use a separate block directory. Each node's
`TSC1_DEVNET_V3_PEER_KEYS` must include both public keys, while each private
`TSC1_DEVNET_V3_PEER_KEY` remains only on its own VPS. Set the peer addresses
explicitly:

```text
# node 1
TSC1_DEVNET_V3_PEERS=seed2.tenebra-network.com:39453
TSC1_DEVNET_V3_SEEDS=seed2.tenebra-network.com:39453

# node 2
TSC1_DEVNET_V3_PEERS=seed1.tenebra-network.com:39453
TSC1_DEVNET_V3_SEEDS=seed1.tenebra-network.com:39453
```

After both services start, run `sync` from the node with the shorter chain,
restart both services, and compare `tip_hash` from `status`. A successful
redundancy check requires matching height and tip after restart, plus a
successful backup restore check on a separate directory.

## Important

The VPS is an authenticated v3f testnet node. Do not put wallet seeds in the
environment file or expose them through the website. The current protocol is
not a mainnet or real-value guarantee.
