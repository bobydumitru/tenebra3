#!/usr/bin/env bash
set -euo pipefail

APP_DIR=/opt/tenebra
BIN_DIR="$APP_DIR/bin"
CONFIG_DIR=/etc/tenebra
DATA_DIR=/var/lib/tenebra-v3f
LOG_DIR=/var/log/tenebra
SERVICE_NAME=tenebra-v3f

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run as root: sudo bash install-v3f-ubuntu.sh /path/to/tenebra-release" >&2
  exit 1
fi
RELEASE_DIR="${1:-}"
if [[ -z "$RELEASE_DIR" || ! -x "$RELEASE_DIR/tsc1-devnet-v3" ]]; then
  echo "Usage: sudo bash install-v3f-ubuntu.sh /path/to/release" >&2
  echo "The release directory must contain an executable tsc1-devnet-v3 binary." >&2
  exit 1
fi

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y ufw ca-certificates
id tenebra >/dev/null 2>&1 || useradd --system --home-dir "$APP_DIR" --create-home --shell /usr/sbin/nologin tenebra
install -d -o tenebra -g tenebra -m 0750 "$APP_DIR" "$BIN_DIR" "$DATA_DIR/blocks" "$LOG_DIR"
install -d -o root -g tenebra -m 0750 "$CONFIG_DIR"
install -m 0755 "$RELEASE_DIR/tsc1-devnet-v3" "$BIN_DIR/tsc1-devnet-v3"

if [[ ! -f "$CONFIG_DIR/v3f.env" ]]; then
  install -o root -g tenebra -m 0640 /dev/null "$CONFIG_DIR/v3f.env"
  cat >&2 <<'NOTICE'
Created /etc/tenebra/v3f.env. Add the node's Ed25519 key and allowlist before starting:
  TSC1_DEVNET_V3_PEER_KEY=<private seed hex>
  TSC1_DEVNET_V3_PEER_KEYS=<allowed public keys>
  TSC1_DEVNET_V3_SEEDS=seed1.tenebra-network.com:39453
  TSC1_DEVNET_V3_BLOCKS_DIR=/var/lib/tenebra-v3f/blocks
NOTICE
fi
printf 'TSC1_DEVNET_V3_BLOCKS_DIR=%s\n' "$DATA_DIR/blocks" >> "$CONFIG_DIR/v3f.env.tmp"
if ! grep -q '^TSC1_DEVNET_V3_BLOCKS_DIR=' "$CONFIG_DIR/v3f.env"; then
  cat "$CONFIG_DIR/v3f.env.tmp" >> "$CONFIG_DIR/v3f.env"
fi
rm -f "$CONFIG_DIR/v3f.env.tmp"
chown root:tenebra "$CONFIG_DIR/v3f.env"
chmod 0640 "$CONFIG_DIR/v3f.env"

install -m 0644 "$(dirname "$0")/tenebra-v3f.service" /etc/systemd/system/tenebra-v3f.service
install -m 0644 "$(dirname "$0")/tenebra-v3f-backup.service" /etc/systemd/system/tenebra-v3f-backup.service
install -m 0644 "$(dirname "$0")/tenebra-v3f-backup.timer" /etc/systemd/system/tenebra-v3f-backup.timer
install -m 0644 "$(dirname "$0")/tenebra-v3f-healthcheck.service" /etc/systemd/system/tenebra-v3f-healthcheck.service
install -m 0644 "$(dirname "$0")/tenebra-v3f-healthcheck.timer" /etc/systemd/system/tenebra-v3f-healthcheck.timer
install -m 0644 "$(dirname "$0")/tenebra-v3f-alert.service" /etc/systemd/system/tenebra-v3f-alert.service
install -m 0750 "$RELEASE_DIR/backup-v3f.sh" /usr/local/sbin/backup-tenebra-v3f 2>/dev/null || true
install -m 0750 "$(dirname "$0")/restore-v3f.sh" /usr/local/sbin/restore-tenebra-v3f
install -m 0750 "$(dirname "$0")/healthcheck-v3f.sh" /usr/local/sbin/healthcheck-tenebra-v3f
install -m 0750 "$(dirname "$0")/alert-v3f.sh" /usr/local/sbin/alert-tenebra-v3f
install -m 0644 "$(dirname "$0")/tenebra-v3f.logrotate" /etc/logrotate.d/tenebra-v3f
ufw limit OpenSSH comment 'TENEBRA SSH rate limit'
ufw allow 80/tcp comment 'TENEBRA HTTP redirect'
ufw allow 443/tcp comment 'TENEBRA HTTPS web and API'
ufw allow 39453/tcp comment 'TENEBRA TSC-1 P2P'
ufw --force enable
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
if [[ -x /usr/local/sbin/backup-tenebra-v3f ]]; then
  systemctl enable --now tenebra-v3f-backup.timer
fi
systemctl enable --now tenebra-v3f-healthcheck.timer
if grep -q '^TSC1_DEVNET_V3_PEER_KEY=<private seed hex>' "$CONFIG_DIR/v3f.env"; then
  echo "Installation complete. Fill /etc/tenebra/v3f.env before starting the service."
else
  systemctl restart "$SERVICE_NAME"
  systemctl --no-pager --full status "$SERVICE_NAME" || true
fi
