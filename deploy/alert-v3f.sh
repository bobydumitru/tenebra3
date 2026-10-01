#!/usr/bin/env bash
set -euo pipefail

WEBHOOK=${TSC1_DEVNET_V3_ALERT_WEBHOOK:-}
MESSAGE=${1:-TENEBRA v3f healthcheck failed}

logger -t tenebra-v3f-alert -- "$MESSAGE"
if [[ -n "$WEBHOOK" ]]; then
  curl --fail --silent --show-error --max-time 10 \
    -H 'Content-Type: application/json' \
    --data "$(printf '{\"text\":\"%s\"}' "${MESSAGE//"/\\\"}")" \
    "$WEBHOOK" >/dev/null
fi
