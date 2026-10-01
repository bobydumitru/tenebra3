#!/usr/bin/env bash
set -euo pipefail

SERVICE=${TSC1_DEVNET_V3_SERVICE:-tenebra-v3f}
BINARY=${TSC1_DEVNET_V3_BINARY:-/opt/tenebra/bin/tsc1-devnet-v3}
PORT=${TSC1_DEVNET_V3_PORT:-39453}
BLOCKS_DIR=${TSC1_DEVNET_V3_BLOCKS_DIR:-/var/lib/tenebra-v3f/blocks}

systemctl is-active --quiet "$SERVICE"
[[ -x "$BINARY" ]] || { echo "Missing node binary: $BINARY" >&2; exit 1; }
[[ -d "$BLOCKS_DIR" ]] || { echo "Missing blocks directory: $BLOCKS_DIR" >&2; exit 1; }

port_ready=false
for attempt in $(seq 1 15); do
  if timeout 5 bash -c "</dev/tcp/127.0.0.1/$PORT"; then
    port_ready=true
    break
  fi
  sleep 2
done
if [[ "$port_ready" != true ]]; then
  echo "Node port is closed: $PORT" >&2
  exit 1
fi

status=$(TSC1_DEVNET_V3_BLOCKS_DIR="$BLOCKS_DIR" "$BINARY" status)
grep -Eq '^devnet_v3_height=[0-9]+$' <<<"$status"
grep -Eq '^tip_hash=[0-9a-f]{64}$' <<<"$status"
printf '%s\n' "$status"
