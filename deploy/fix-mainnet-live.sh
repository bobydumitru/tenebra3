#!/usr/bin/env bash
set -euo pipefail

systemctl stop tenebra-v3f.service || true
systemctl disable tenebra-v3f.service || true
systemctl stop tenebra-mainnet.service || true
systemctl daemon-reload
systemctl enable --now tenebra-mainnet.service
systemctl --no-pager status tenebra-mainnet.service
ss -lntp | grep 39453 || true
/opt/tenebra/bin/tenebra-node status

python3 - <<'PY'
import socket, struct
host = '127.0.0.1'
port = 39453
magic = b'TNBMN001'
genesis = bytes.fromhex('58ed7d7dcf4c173a25059585f1b06489a190ee8f42e2e03d5a88b69af65d0652')

s = socket.create_connection((host, port), timeout=8)
s.settimeout(8)
s.sendall(magic + genesis)
server_magic = s.recv(8)
print('SERVER_MAGIC=', server_magic)
print('MAGIC_OK=', server_magic == magic)
if server_magic != magic:
    raise SystemExit(1)

s.sendall(b'H')
payload = s.recv(60)
print('PAYLOAD_LEN=', len(payload))
print('PAYLOAD_HEX=', payload.hex())
if len(payload) < 60:
    raise SystemExit(2)

magic2 = payload[:8]
height = struct.unpack_from('<Q', payload, 8)[0]
tip_hash = payload[16:48].hex()
confirmed = struct.unpack_from('<Q', payload, 48)[0]
pending = struct.unpack_from('<I', payload, 56)[0]
print('MAGIC2_OK=', magic2 == magic)
print('HEIGHT=', height)
print('TIP_HASH=', tip_hash)
print('CONFIRMED_TX=', confirmed)
print('PENDING_COUNT=', pending)
s.close()
PY
