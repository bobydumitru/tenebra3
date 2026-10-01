#!/usr/bin/env bash
set -euo pipefail

ARCHIVE=${1:-}
TARGET=${2:-/var/lib/tenebra-v3f/blocks}
BINARY=${3:-/opt/tenebra/bin/tsc1-devnet-v3}

if [[ -z "$ARCHIVE" || ! -f "$ARCHIVE" ]]; then
  echo "Usage: restore-v3f.sh <backup.tar.gz> [blocks-dir] [node-binary]" >&2
  exit 2
fi
if [[ ! -x "$BINARY" ]]; then
  echo "Missing executable node binary: $BINARY" >&2
  exit 1
fi

if [[ -f "$ARCHIVE.sha256" ]]; then
  sha256sum --check "$ARCHIVE.sha256"
fi
tar -tzf "$ARCHIVE" >/dev/null

PARENT=$(dirname "$TARGET")
STAGING=$(mktemp -d "$PARENT/.restore-v3f.XXXXXX")
BACKUP="$TARGET.pre-restore.$(date -u +%Y%m%dT%H%M%SZ)"
cleanup() { rm -rf "$STAGING"; }
trap cleanup EXIT

tar -C "$STAGING" -xzf "$ARCHIVE"
TSC1_DEVNET_V3_BLOCKS_DIR="$STAGING" "$BINARY" status >/dev/null

if [[ -e "$TARGET" ]]; then
  mv "$TARGET" "$BACKUP"
fi
mv "$STAGING" "$TARGET"
trap - EXIT
printf 'restored=%s\n' "$TARGET"
printf 'previous=%s\n' "$BACKUP"