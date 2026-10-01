# TENEBRA v3f redundancy runbook

This runbook applies to the controlled v3f testnet. It does not make the
network a production mainnet.

## Primary node operations

From Windows, upload the `deploy` directory to the primary VPS:

```text
scp -r deploy root@<primary-ip>:/tmp/tenebra-deploy
```

In the VPS shell, install the operational units without replacing the node or
chain data:

```text
bash /tmp/tenebra-deploy/install-operations-v3f.sh /tmp/tenebra-deploy
systemctl status tenebra-v3f tenebra-v3f-healthcheck.timer tenebra-v3f-backup.timer
```

Verify the first backup and a non-destructive restore check:

```text
backup=$(/usr/local/sbin/backup-tenebra-v3f | sed -n 's/^backup=//p')
sudo /usr/local/sbin/restore-tenebra-v3f "$backup" /var/lib/tenebra-v3f/restore-check
TSC1_DEVNET_V3_BLOCKS_DIR=/var/lib/tenebra-v3f/restore-check /opt/tenebra/bin/tsc1-devnet-v3 status
```

The restore target is separate from the live chain. Remove it only after the
status output matches the live node.

## Second node

Provision a second Ubuntu VPS and install the same release binary and deploy
files. Use a different persistent directory and a new Ed25519 seed. Generate
that seed on node2, never on Windows or in chat:

```text
install -d -m 0750 /etc/tenebra
node <<'NODE'
const { generateKeyPairSync } = require('crypto');
const fs = require('fs');
const key = generateKeyPairSync('ed25519');
const privateSeed = Buffer.from(key.privateKey.export({ format: 'jwk' }).d, 'base64url').toString('hex');
const publicKey = Buffer.from(key.publicKey.export({ format: 'jwk' }).x, 'base64url').toString('hex');
fs.writeFileSync('/etc/tenebra/node2-private.env', `TSC1_DEVNET_V3_PEER_KEY=${privateSeed}\n`, { mode: 0o640 });
fs.writeFileSync('/etc/tenebra/node2-public.key', `${publicKey}\n`, { mode: 0o644 });
NODE
cat /etc/tenebra/node2-public.key
```

Add node2's public key to the allowlist on node1 and node1's public key to the
allowlist on node2. Keep each private seed only in its own protected env file.
Set the peers in each `/etc/tenebra/v3f.env`:

```text
TSC1_DEVNET_V3_BLOCKS_DIR=/var/lib/tenebra-v3f/blocks
TSC1_DEVNET_V3_SEEDS=<other-node-host>:39453
TSC1_DEVNET_V3_PEERS=<other-node-host>:39453
```

Run the operations installer on node2, then start both services. On the node
with the shorter chain:

```text
TSC1_DEVNET_V3_BLOCKS_DIR=/var/lib/tenebra-v3f/blocks /opt/tenebra/bin/tsc1-devnet-v3 sync <other-node-host>:39453
systemctl restart tenebra-v3f
```

Verify both nodes after restart:

```text
/opt/tenebra/bin/tsc1-devnet-v3 status
journalctl -u tenebra-v3f-healthcheck.service -n 20 --no-pager
```

The height and `tip_hash` must match. A mismatch is an operational failure;
do not delete either chain or force a reorg manually.

## Alerting and logs

Set `TSC1_DEVNET_V3_ALERT_WEBHOOK` only in the protected environment file if
an operator webhook is available. Healthcheck failures are always recorded in
journald. Node output is in `/var/log/tenebra/v3f.log`; logrotate keeps 14
compressed rotations.
