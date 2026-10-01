#!/usr/bin/env bash
set -euo pipefail

SOURCE=${TSC1_DEVNET_V3_BLOCKS_DIR:-/var/lib/tenebra-v3f/blocks}
DEST=${TSC1_DEVNET_V3_BACKUP_DIR:-/var/backups/tenebra-v3f}
STAMP=$(date -u +%Y%m%dT%H%M%SZ)

if [[ ! -d "$SOURCE" ]]; then
  echo "Missing chain directory: $SOURCE" >&2
  exit 1
fi
install -d -m 0750 "$DEST"
ARCHIVE="$DEST/blocks-$STAMP.tar.gz"
TEMP_ARCHIVE="$ARCHIVE.tmp.$$"
tar -C "$SOURCE" -czf "$TEMP_ARCHIVE" .
tar -tzf "$TEMP_ARCHIVE" >/dev/null
mv "$TEMP_ARCHIVE" "$ARCHIVE"
sha256sum "$ARCHIVE" > "$ARCHIVE.sha256"
find "$DEST" -type f -name 'blocks-*.tar.gz' -mtime +14 -delete
find "$DEST" -type f -name 'blocks-*.tar.gz.sha256' -mtime +14 -delete
printf 'backup=%s\n' "$DEST/blocks-$STAMP.tar.gz"
