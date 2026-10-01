#!/usr/bin/env bash
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run as root" >&2
  exit 1
fi
SOURCE=${1:-"$(cd "$(dirname "$0")" && pwd)"}
install -d -o tenebra -g tenebra -m 0750 /var/log/tenebra
install -m 0750 "$SOURCE/backup-v3f.sh" /usr/local/sbin/backup-tenebra-v3f
install -m 0750 "$SOURCE/restore-v3f.sh" /usr/local/sbin/restore-tenebra-v3f
install -m 0750 "$SOURCE/healthcheck-v3f.sh" /usr/local/sbin/healthcheck-tenebra-v3f
install -m 0750 "$SOURCE/alert-v3f.sh" /usr/local/sbin/alert-tenebra-v3f
for unit in tenebra-v3f-healthcheck.service tenebra-v3f-healthcheck.timer tenebra-v3f-alert.service tenebra-v3f-backup.service tenebra-v3f-backup.timer; do
  install -m 0644 "$SOURCE/$unit" "/etc/systemd/system/$unit"
done
install -m 0644 "$SOURCE/tenebra-v3f.logrotate" /etc/logrotate.d/tenebra-v3f
systemctl daemon-reload
systemctl enable --now tenebra-v3f-backup.timer tenebra-v3f-healthcheck.timer
systemctl restart tenebra-v3f
systemctl start tenebra-v3f-healthcheck.service
systemctl --no-pager --full status tenebra-v3f tenebra-v3f-healthcheck.timer tenebra-v3f-backup.timer
