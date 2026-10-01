#!/usr/bin/env python3
"""Browser API for TENEBRA mainnet status, assets, and miner controls."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import re
import socket
import time
import base64
import hashlib
import secrets
import subprocess
import threading
import urllib.parse
from pathlib import Path

PEER_HOST = os.environ.get("TENEBRA_API_PEER_HOST", "127.0.0.1")
PEER_PORT = int(os.environ.get("TENEBRA_API_PEER_PORT", "39453"))
BIND_HOST = os.environ.get("TENEBRA_API_BIND_HOST", "0.0.0.0")
BIND_PORT = int(os.environ.get("TENEBRA_API_BIND_PORT", "39455"))
MAGIC = b"TSC1P3V8" if os.environ.get("TSC1_DEVNET_V3_PEER_KEY") else b"TNBMN001"
GENESIS = bytes.fromhex("58ed7d7dcf4c173a25059585f1b06489a190ee8f42e2e03d5a88b69af65d0652")
MAX_PAGE = 64
NETWORK_ID = bytes.fromhex("0ca9823ad6b5355b0d5786a3755583fe00cd77fcfa16276d37c8006c7d1b9868")
ASSET_INDEX_INITIAL_TIP = hashlib.sha256(b"TSC-1:v3f-genesis-anchor" + GENESIS).hexdigest()
ASSET_INDEX_LOCK = threading.Lock()
ASSET_INDEX = {
    "height": 0,
    "tip": ASSET_INDEX_INITIAL_TIP,
    "definitions": {},
    "balances": {},
    "building": False,
    "target_height": 0,
    "error": None,
}
BLOCK_INDEX = {
    "height": 0,
    "tip": ASSET_INDEX_INITIAL_TIP,
    "blocks": {},
    "by_hash": {},
    "transactions": {},
}
ROOT_DIR = Path(__file__).resolve().parent.parent
ENV_BLOCKS_DIR = os.environ.get("TENEBRA_MAINNET_BLOCKS_DIR")
if not ENV_BLOCKS_DIR and os.environ.get("TSC1_DEVNET_V3_PEER_KEY"):
    ENV_BLOCKS_DIR = os.environ.get("TSC1_DEVNET_V3_BLOCKS_DIR")
BLOCKS_DIR_CANDIDATES = [
    Path(ENV_BLOCKS_DIR) if ENV_BLOCKS_DIR else None,
    Path("/var/lib/tenebra-mainnet-candidate/blocks"),
    ROOT_DIR / "data" / "mainnet-candidate" / "blocks",
]
BLOCKS_DIR = next((path for path in BLOCKS_DIR_CANDIDATES if path is not None and path.exists()), BLOCKS_DIR_CANDIDATES[0] or Path("/var/lib/tenebra-mainnet-candidate/blocks"))
LOCAL_BLOCKS_ENABLED = bool(os.environ.get("TENEBRA_MAINNET_BLOCKS_DIR") or os.environ.get("TSC1_DEVNET_V3_BLOCKS_DIR"))
MINER_ADDRESS_FILE = Path(os.environ.get("TENEBRA_MAINNET_MINER_ADDRESS_FILE", "/var/lib/tenebra-mainnet-candidate/miner-address"))
MINER_AUTH_VERIFY = Path(os.environ.get("TENEBRA_MAINNET_MINER_AUTH_VERIFY", "/opt/tenebra/mainnet-candidate/tenebra-miner-auth-verify"))
MINER_ADDRESS_LOCK = threading.Lock()
MINER_CHALLENGES = {}
MINER_CHALLENGES_LOCK = threading.Lock()
MINER_CHALLENGE_TTL = 60


def read_miner_addresses():
    try:
        contents = MINER_ADDRESS_FILE.read_text()
    except FileNotFoundError:
        return []
    return list(dict.fromkeys(line.strip() for line in contents.splitlines() if line.strip()))


def write_miner_addresses(addresses):
    MINER_ADDRESS_FILE.parent.mkdir(parents=True, exist_ok=True)
    temporary = MINER_ADDRESS_FILE.with_name(MINER_ADDRESS_FILE.name + ".tmp")
    contents = "" if not addresses else "\n".join(addresses) + "\n"
    temporary.write_text(contents)
    os.replace(temporary, MINER_ADDRESS_FILE)


def update_miner_address(address, enabled):
    with MINER_ADDRESS_LOCK:
        addresses = read_miner_addresses()
        if enabled and address not in addresses:
            addresses.append(address)
        elif not enabled:
            addresses = [active for active in addresses if active != address]
        write_miner_addresses(addresses)
        return addresses


def issue_miner_challenge():
    challenge = secrets.token_bytes(32)
    now = time.time()
    with MINER_CHALLENGES_LOCK:
        MINER_CHALLENGES[challenge.hex()] = now + MINER_CHALLENGE_TTL
        for key, expires in list(MINER_CHALLENGES.items()):
            if expires <= now:
                del MINER_CHALLENGES[key]
    return challenge


def consume_miner_challenge(challenge_hex):
    now = time.time()
    with MINER_CHALLENGES_LOCK:
        expires = MINER_CHALLENGES.pop(challenge_hex, None)
    return expires is not None and expires > now


def verify_miner_signature(address, challenge_hex, signature_hex):
    if len(challenge_hex) != 64 or len(signature_hex) != 128:
        return False
    try:
        bytes.fromhex(challenge_hex)
        bytes.fromhex(signature_hex)
    except ValueError:
        return False
    try:
        result = subprocess.run(
            [str(MINER_AUTH_VERIFY), address, challenge_hex, signature_hex],
            check=False,
            capture_output=True,
            timeout=2,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def read_exact(stream, size):
    data = b""
    while len(data) < size:
        part = stream.recv(size - len(data))
        if not part:
            raise ConnectionError("peer closed connection")
        data += part
    return data


def _peer_auth_enabled():
    value = os.environ.get("TSC1_DEVNET_V3_PEER_KEY", "").strip()
    return bool(value) and len(value) >= 64


def _peer_public_keys():
    values = os.environ.get("TSC1_DEVNET_V3_PEER_KEYS", "")
    keys = []
    for text in values.split(","):
        candidate = text.strip()
        if candidate:
            try:
                keys.append(bytes.fromhex(candidate))
            except ValueError:
                continue
    return keys


def authenticate_peer(stream):
    if not _peer_auth_enabled():
        return
    try:
        from nacl.signing import SigningKey, VerifyKey
    except ModuleNotFoundError:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

        private = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(os.environ["TSC1_DEVNET_V3_PEER_KEY"]))
        public = private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        client_nonce = os.urandom(32)
        message = b"TSC1P3:client-auth:v1" + public + client_nonce
        signature = private.sign(message)
        stream.sendall(b"A" + public + client_nonce + signature)
        if read_exact(stream, 2) != b"OK":
            raise ValueError("peer authentication rejected")
        server_public = read_exact(stream, 32)
        server_nonce = read_exact(stream, 32)
        server_signature = read_exact(stream, 64)
        allowed = _peer_public_keys()
        if server_public not in allowed:
            raise ValueError("server key is not allowlisted")
        server_message = b"TSC1P3:server-auth:v1" + public + client_nonce + server_public + server_nonce
        Ed25519PublicKey.from_public_bytes(server_public).verify(server_signature, server_message)
        return

    private = SigningKey(bytes.fromhex(os.environ["TSC1_DEVNET_V3_PEER_KEY"]))
    public = bytes(private.verify_key)
    client_nonce = os.urandom(32)
    message = b"TSC1P3:client-auth:v1" + public + client_nonce
    signature = private.sign(message).signature
    stream.sendall(b"A" + public + client_nonce + signature)
    if read_exact(stream, 2) != b"OK":
        raise ValueError("peer authentication rejected")
    server_public = read_exact(stream, 32)
    server_nonce = read_exact(stream, 32)
    server_signature = read_exact(stream, 64)
    allowed = [VerifyKey(key) for key in _peer_public_keys()]
    if bytes(VerifyKey(server_public)) not in [bytes(key) for key in allowed]:
        raise ValueError("server key is not allowlisted")
    server_message = b"TSC1P3:server-auth:v1" + public + client_nonce + server_public + server_nonce
    VerifyKey(server_public).verify(server_message, server_signature)


def peer_connect():
    stream = socket.create_connection((PEER_HOST, PEER_PORT), timeout=10)
    if _peer_auth_enabled():
        authenticate_peer(stream)
        return stream
    stream.sendall(MAGIC + GENESIS)
    if read_exact(stream, 8) != MAGIC:
        raise ValueError("invalid peer response")
    return stream


def peer_status():
    with peer_connect() as stream:
        stream.sendall(b"H")
        if read_exact(stream, 8) != MAGIC:
            raise ValueError("invalid status response")
        height = int.from_bytes(read_exact(stream, 8), "little")
        tip = read_exact(stream, 32).hex()
        confirmed = int.from_bytes(read_exact(stream, 8), "little")
        pending = int.from_bytes(read_exact(stream, 4), "little")
    return {
        "network": "TSC-1 mainnet",
        "online": True,
        "height": height,
        "tip": tip,
        "confirmed_transactions": confirmed,
        "pending_transactions": pending,
        "checked_at": int(time.time()),
    }


def local_blocks(start, limit, anchor_hex=None):
    files = sorted(BLOCKS_DIR.glob("*.bin"))
    if start < 1 or limit < 1 or limit > MAX_PAGE:
        raise ValueError("invalid block page")
    selected = files[start - 1:start - 1 + limit]
    if start > 1 and len(files) >= start - 1:
        previous = files[start - 2].read_bytes()
        expected = block_hash(previous).hex()
        if anchor_hex != expected:
            raise ValueError("invalid local block anchor")
    blocks = [path.read_bytes() for path in selected]
    tip = anchor_hex or hashlib.sha256(b"TSC-1:v3f-genesis-anchor" + GENESIS).hexdigest()
    for block in blocks:
        tip = block_hash(block).hex()
    return {
        "start": start,
        "height": len(files),
        "count": len(blocks),
        "tip": tip,
        "blocks": [base64.b64encode(block).decode("ascii") for block in blocks],
    }


def latest_local_blocks(limit):
    files = sorted(BLOCKS_DIR.glob("*.bin"))
    if limit < 1 or limit > MAX_PAGE:
        raise ValueError("invalid block page")
    if not files:
        raise FileNotFoundError("local block index is unavailable")
    start = max(1, len(files) - limit + 1)
    anchor = block_hash(files[start - 2].read_bytes()).hex() if start > 1 else None
    page = local_blocks(start, limit, anchor)
    blocks = [base64.b64decode(encoded) for encoded in page.pop("blocks")]
    page["activity"] = [
        summarize_mainnet_block(block, start + offset, page["height"])
        for offset, block in enumerate(blocks)
    ]
    return page


def safe_peer_status():
    try:
        return peer_status()
    except Exception:
        files = sorted(BLOCKS_DIR.glob("*.bin"))
        page = local_blocks(1, 1)
        tip = block_hash(files[-1].read_bytes()).hex() if files else page["tip"]
        return {
            "network": "TSC-1 mainnet",
            "online": True,
            "height": page["height"],
            "tip": tip,
            "confirmed_transactions": 0,
            "pending_transactions": 0,
            "checked_at": int(time.time()),
        }


def block_hash(block):
    content = hashlib.sha256(block[:-8]).digest()
    return hashlib.sha256(b"TENEBRA:mainnet:pow:v1" + NETWORK_ID + content + block[-8:]).digest()


def summarize_mainnet_block(block, height, chain_height):
    if len(block) < 51 or block[:10] != b"TNB1BLK001":
        raise ValueError("invalid mainnet block")
    cursor = 42
    reward_length = int.from_bytes(block[cursor:cursor + 4], "little")
    cursor += 4 + reward_length
    transaction_count = int.from_bytes(block[cursor:cursor + 2], "little")
    cursor += 2
    transactions = []
    confirmations = max(0, chain_height - height)
    for _ in range(transaction_count):
        length = int.from_bytes(block[cursor:cursor + 4], "little")
        cursor += 4
        encoded = block[cursor:cursor + length]
        if length == 0 or len(encoded) != length:
            raise ValueError("invalid mainnet transaction length")
        cursor += length
        transactions.append({
            "txid": hashlib.sha256(b"TSC-1:txid:v1" + encoded).hexdigest(),
            "included": True,
            "finality_confirmed": confirmations >= 10,
            "confirmed": confirmations >= 10,
            "confirmations": confirmations,
        })
    for _ in range(2):
        present = block[cursor]
        cursor += 1
        if present == 1:
            length = int.from_bytes(block[cursor:cursor + 4], "little")
            cursor += 4 + length
        elif present != 0:
            raise ValueError("invalid mainnet fee output flag")

    asset_operations = []
    if len(block) - cursor != 9:
        asset_count = int.from_bytes(block[cursor:cursor + 2], "little")
        cursor += 2
        for _ in range(asset_count):
            length = int.from_bytes(block[cursor:cursor + 4], "little")
            cursor += 4
            signed = block[cursor:cursor + length]
            cursor += length
            if length < 96 or len(signed) != length:
                raise ValueError("invalid signed asset operation")
            operation = signed[:-96]
            prefix = b"TSC-1:asset-tx:v2"
            if not operation.startswith(prefix) or len(operation) <= len(prefix):
                raise ValueError("invalid asset transaction format")
            kind = operation[len(prefix)]
            position = len(prefix) + 1
            event = {
                "txid": hashlib.sha256(operation).hexdigest(),
                "kind": {0: "create", 1: "mint", 2: "transfer", 3: "create", 4: "burn", 5: "increase_max_supply", 6: "update_options", 7: "create"}.get(kind, "unknown"),
                "block_height": height,
                "included": True,
                "finality_confirmed": confirmations >= 10,
                "confirmed": confirmations >= 10,
                "confirmations": confirmations,
            }
            if kind in (0, 3, 7):
                issuer = operation[position:position + 32]
                position += 32
                nonce = int.from_bytes(operation[position:position + 8], "little")
                position += 8
                name_length = operation[position]
                position += 1
                name = operation[position:position + name_length].decode("utf-8")
                position += name_length
                symbol_length = operation[position]
                position += 1
                symbol = operation[position:position + symbol_length].decode("utf-8")
                position += symbol_length
                decimals = operation[position]
                position += 1
                max_supply = int.from_bytes(operation[position:position + 8], "little")
                position += 8
                initial_supply = int.from_bytes(operation[position:position + 8], "little")
                position += 8
                mintable = kind == 0
                burnable = False
                if kind in (3, 7):
                    mintable = operation[position] == 1
                    burnable = operation[position + 1] == 1
                    position += 2
                    issuer_fee_bps = int.from_bytes(operation[position:position + 2], "little")
                    position += 2
                    issuer_treasury = None
                    if operation[position] == 1:
                        position += 1
                        issuer_treasury = _asset_address(operation[position:position + 32], operation[position + 32:position + 64])
                else:
                    issuer_fee_bps = 0
                    issuer_treasury = None
                event.update({
                    "asset_id": hashlib.sha256(b"TENEBRA:asset:v1" + issuer + nonce.to_bytes(8, "little")).hexdigest(),
                    "issuer": issuer.hex(),
                    "name": name,
                    "symbol": symbol,
                    "decimals": decimals,
                    "max_supply": max_supply,
                    "amount": initial_supply,
                    "mintable": mintable,
                    "burnable": burnable,
                    "issuer_fee_bps": issuer_fee_bps,
                    "issuer_treasury": issuer_treasury,
                    "asset_type": "nft" if kind == 7 else ("fungible" if kind == 3 else None),
                })
            elif kind == 1:
                event["asset_id"] = operation[position:position + 32].hex()
                position += 32
                event["amount"] = int.from_bytes(operation[position + 32:position + 40], "little")
            elif kind == 2:
                event["asset_id"] = operation[position:position + 32].hex()
                position += 32
                event["amount"] = int.from_bytes(operation[position + 64:position + 72], "little")
            elif kind in (4, 5, 6):
                event["asset_id"] = operation[position:position + 32].hex()
                position += 32
                if kind == 4:
                    event["amount"] = int.from_bytes(operation[position + 32:position + 40], "little")
                elif kind == 5:
                    event["max_supply"] = int.from_bytes(operation[position + 32:position + 40], "little")
                else:
                    event["mintable"] = operation[position + 32] == 1
                    event["burnable"] = operation[position + 33] == 1
                    event["issuer_fee_bps"] = int.from_bytes(operation[position + 34:position + 36], "little")
                    treasury_flag = operation[position + 36]
                    event["issuer_treasury"] = _asset_address(operation[position + 37:position + 69], operation[position + 69:position + 101]) if treasury_flag else None
            asset_operations.append(event)

    dex_count = 0
    if len(block) - cursor != 9:
        if block[cursor:cursor + 4] != b"DEX1":
            raise ValueError("invalid mainnet DEX extension")
        dex_count = int.from_bytes(block[cursor + 4:cursor + 6], "little")
        cursor += 6
        for _ in range(dex_count):
            length = int.from_bytes(block[cursor:cursor + 2], "little")
            cursor += 2 + length
    if cursor + 9 != len(block):
        raise ValueError("invalid mainnet block extension")
    return {
        "height": height,
        "hash": block_hash(block).hex(),
        "confirmations": confirmations,
        "transactions": transactions,
        "asset_operations": asset_operations,
        "dex_operations": dex_count,
    }


def public_blocks(start, limit, anchor_hex=None):
    if start < 1 or limit < 1 or limit > MAX_PAGE:
        raise ValueError("invalid block page")
    anchor = (hashlib.sha256(b"TSC-1:v3f-genesis-anchor" + GENESIS).digest()
              if anchor_hex is None else bytes.fromhex(anchor_hex))
    if len(anchor) != 32:
        raise ValueError("invalid block anchor")
    with socket.create_connection((PEER_HOST, PEER_PORT), timeout=10) as stream:
        if _peer_auth_enabled():
            authenticate_peer(stream)
        stream.sendall(MAGIC + GENESIS)
        if read_exact(stream, 8) != MAGIC:
            raise ValueError("invalid peer response")
        stream.sendall(b"G" + start.to_bytes(8, "little") + limit.to_bytes(2, "little") + anchor)
        if read_exact(stream, 8) != MAGIC:
            raise ValueError("invalid block response")
        accepted = read_exact(stream, 1)[0]
        height = int.from_bytes(read_exact(stream, 8), "little")
        count = int.from_bytes(read_exact(stream, 2), "little")
        if not accepted or count > MAX_PAGE:
            raise ValueError("node rejected block page")
        blocks = []
        tip = anchor
        for _ in range(count):
            length = int.from_bytes(read_exact(stream, 4), "little")
            if length == 0 or length > 64 * 1024 * 1024:
                raise ValueError("invalid public block")
            data = read_exact(stream, length)
            blocks.append(base64.b64encode(data).decode("ascii"))
            tip = block_hash(data)
    return {"start": start, "height": height, "count": len(blocks), "tip": tip.hex(), "blocks": blocks}


def _asset_owner(owner_address):
    if owner_address.startswith("tsc1_") and len(owner_address) == 141:
        return bytes.fromhex(owner_address[69:133]).hex()
    return None


def _asset_address(view_key, spend_key):
    payload = view_key + spend_key
    checksum = hashlib.sha256(b"TSC1-address-v1" + payload).digest()[:4]
    return "tsc1_" + (payload + checksum).hex()


def _apply_asset_block(block, block_height, definitions, balances):
    if len(block) < 51 or block[:10] != b"TNB1BLK001":
        raise ValueError("invalid mainnet block in asset index")
    cursor = 42
    reward_length = int.from_bytes(block[cursor:cursor + 4], "little")
    cursor += 4 + reward_length
    count_size = 1 if os.environ.get("TSC1_DEVNET_V3_PEER_KEY") else 2
    transaction_count = int.from_bytes(block[cursor:cursor + count_size], "little")
    cursor += count_size
    for _ in range(transaction_count):
        length = int.from_bytes(block[cursor:cursor + 4], "little")
        cursor += 4 + length
    for _ in range(2):
        present = block[cursor]
        cursor += 1
        if present == 1:
            length = int.from_bytes(block[cursor:cursor + 4], "little")
            cursor += 4 + length
        elif present != 0:
            raise ValueError("invalid fee output flag in asset index")
    if len(block) - cursor == 9:
        return
    asset_count = int.from_bytes(block[cursor:cursor + 2], "little")
    cursor += 2
    for _ in range(asset_count):
        length = int.from_bytes(block[cursor:cursor + 4], "little")
        cursor += 4
        signed = block[cursor:cursor + length]
        cursor += length
        prefix = b"TSC-1:asset-tx:v2"
        if len(signed) < len(prefix) + 1 + 96:
            raise ValueError("invalid signed asset operation")
        body = signed[:-96]
        if not body.startswith(prefix):
            raise ValueError("invalid asset transaction format")
        kind = body[len(prefix)]
        position = len(prefix) + 1
        if kind in (0, 3, 7):
            issuer = body[position:position + 32]
            position += 32
            nonce = int.from_bytes(body[position:position + 8], "little")
            position += 8
            name_length = body[position]
            position += 1
            name = body[position:position + name_length].decode("ascii")
            position += name_length
            symbol_length = body[position]
            position += 1
            symbol = body[position:position + symbol_length].decode("ascii")
            position += symbol_length
            decimals = body[position]
            position += 1
            max_supply = int.from_bytes(body[position:position + 8], "little")
            position += 8
            initial = int.from_bytes(body[position:position + 8], "little")
            position += 8
            mintable = kind == 0
            burnable = False
            if kind in (3, 7):
                mintable = body[position] == 1
                burnable = body[position + 1] == 1
                position += 2
                issuer_fee_bps = int.from_bytes(body[position:position + 2], "little")
                position += 2
                issuer_treasury = None
                if body[position] == 1:
                    position += 1
                    issuer_treasury = _asset_address(body[position:position + 32], body[position + 32:position + 64])
            else:
                issuer_fee_bps = 0
                issuer_treasury = None
            asset_id = hashlib.sha256(b"TENEBRA:asset:v1" + issuer + nonce.to_bytes(8, "little")).hexdigest()
            definitions[asset_id] = {
                "asset_id": asset_id,
                "issuer": issuer.hex(),
                "name": name,
                "symbol": symbol,
                "decimals": decimals,
                "max_supply": max_supply,
                "minted": initial,
                "mintable": mintable,
                "burnable": burnable,
                "issuer_fee_bps": issuer_fee_bps,
                "issuer_treasury": issuer_treasury,
                "asset_type": "nft" if kind == 7 else ("fungible" if kind == 3 else None),
                "created_height": block_height,
                "creation_txid": hashlib.sha256(body).hexdigest(),
            }
            if initial:
                balances.setdefault(asset_id, {})[issuer.hex()] = initial
        elif kind == 1:
            asset_id = body[position:position + 32].hex()
            position += 32
            issuer = body[position:position + 32]
            position += 32
            amount = int.from_bytes(body[position:position + 8], "little")
            if asset_id in definitions:
                definitions[asset_id]["minted"] += amount
                owners = balances.setdefault(asset_id, {})
                owners[issuer.hex()] = owners.get(issuer.hex(), 0) + amount
        elif kind == 2:
            asset_id = body[position:position + 32].hex()
            position += 32
            source = body[position:position + 32].hex()
            position += 32
            target = body[position:position + 32].hex()
            position += 32
            amount = int.from_bytes(body[position:position + 8], "little")
            owners = balances.setdefault(asset_id, {})
            owners[source] = owners.get(source, 0) - amount
            owners[target] = owners.get(target, 0) + amount
        elif kind == 4:
            asset_id = body[position:position + 32].hex()
            position += 32
            owner = body[position:position + 32].hex()
            position += 32
            amount = int.from_bytes(body[position:position + 8], "little")
            if asset_id in definitions:
                definitions[asset_id]["minted"] -= amount
                owners = balances.setdefault(asset_id, {})
                owners[owner] = owners.get(owner, 0) - amount
        elif kind == 5:
            asset_id = body[position:position + 32].hex()
            position += 32
            position += 32
            new_max_supply = int.from_bytes(body[position:position + 8], "little")
            if asset_id in definitions:
                definitions[asset_id]["max_supply"] = new_max_supply
        elif kind == 6:
            asset_id = body[position:position + 32].hex()
            position += 32
            position += 32
            mintable = body[position] == 1
            burnable = body[position + 1] == 1
            issuer_fee_bps = int.from_bytes(body[position + 2:position + 4], "little")
            treasury_flag = body[position + 4]
            issuer_treasury = _asset_address(body[position + 5:position + 37], body[position + 37:position + 69]) if treasury_flag else None
            if asset_id in definitions:
                definitions[asset_id]["mintable"] = mintable
                definitions[asset_id]["burnable"] = burnable
                definitions[asset_id]["issuer_fee_bps"] = issuer_fee_bps
                definitions[asset_id]["issuer_treasury"] = issuer_treasury
        else:
            raise ValueError("unknown asset operation")


def _asset_index_snapshot(status, owner, definitions, balances, indexed_height, indexing=False, error=None):
    assets = []
    for asset_id, definition in definitions.items():
        confirmations = max(0, indexed_height - definition["created_height"])
        balance = balances.get(asset_id, {}).get(owner, 0) if owner else 0
        assets.append({
            **definition,
            "balance": balance,
            "balance_units": str(balance),
            "minted_units": str(definition["minted"]),
            "max_supply_units": str(definition["max_supply"]),
            "included": True,
            "finality_confirmed": confirmations >= 10,
            "confirmations": confirmations,
            "confirmed": confirmations >= 10,
        })
    return {
        "assets": assets,
        "indexed": not indexing and indexed_height >= status["height"],
        "indexing": indexing,
        "indexed_height": indexed_height,
        "target_height": status["height"],
        "error": error,
    }


def _scan_asset_index(status):
    with ASSET_INDEX_LOCK:
        indexed_height = ASSET_INDEX["height"]
        indexed_tip = ASSET_INDEX["tip"]
        definitions = {key: value.copy() for key, value in ASSET_INDEX["definitions"].items()}
        balances = {key: value.copy() for key, value in ASSET_INDEX["balances"].items()}
    if indexed_height > status["height"] or (indexed_height == status["height"] and indexed_tip != status["tip"]):
        indexed_height = 0
        indexed_tip = ASSET_INDEX_INITIAL_TIP
        definitions = {}
        balances = {}
        with ASSET_INDEX_LOCK:
            BLOCK_INDEX.update(height=0, tip=ASSET_INDEX_INITIAL_TIP, blocks={}, by_hash={}, transactions={})
    start = indexed_height + 1
    anchor = indexed_tip if indexed_height else None
    local_files = sorted(BLOCKS_DIR.glob("*.bin")) if LOCAL_BLOCKS_ENABLED else []
    while start <= status["height"]:
        limit = min(MAX_PAGE, status["height"] - start + 1)
        if local_files and start + limit - 1 <= len(local_files):
            page = local_blocks(start, limit, anchor)
        else:
            page = public_blocks(start, limit, anchor)
        if page.get("start") != start or page.get("count") != len(page.get("blocks", [])) or page["count"] == 0:
            raise ValueError("invalid asset index block page")
        indexed_blocks = []
        for offset, encoded in enumerate(page["blocks"]):
            block_height = start + offset
            block = base64.b64decode(encoded)
            _apply_asset_block(block, block_height, definitions, balances)
            indexed_blocks.append(summarize_mainnet_block(block, block_height, status["height"]))
        indexed_height = start + page["count"] - 1
        indexed_tip = page["tip"]
        with ASSET_INDEX_LOCK:
            ASSET_INDEX.update(
                height=indexed_height,
                tip=indexed_tip,
                definitions={key: value.copy() for key, value in definitions.items()},
                balances={key: value.copy() for key, value in balances.items()},
                error=None,
            )
            for summary in indexed_blocks:
                BLOCK_INDEX["blocks"][str(summary["height"])] = summary
                BLOCK_INDEX["by_hash"][summary["hash"]] = summary["height"]
                for transaction in summary["transactions"]:
                    BLOCK_INDEX["transactions"][transaction["txid"]] = summary["height"]
                for operation in summary["asset_operations"]:
                    BLOCK_INDEX["transactions"][operation["txid"]] = summary["height"]
            BLOCK_INDEX.update(height=indexed_height, tip=indexed_tip)
        start = indexed_height + 1
        anchor = indexed_tip
    if indexed_height == status["height"] and indexed_tip != status["tip"]:
        raise ValueError("chain changed during asset indexing")


def asset_snapshot(owner_address=""):
    status = peer_status()
    _scan_asset_index(status)
    with ASSET_INDEX_LOCK:
        definitions = {key: value.copy() for key, value in ASSET_INDEX["definitions"].items()}
        balances = {key: value.copy() for key, value in ASSET_INDEX["balances"].items()}
        indexed_height = ASSET_INDEX["height"]
    return _asset_index_snapshot(status, _asset_owner(owner_address), definitions, balances, indexed_height)


def _build_asset_index(status):
    try:
        _scan_asset_index(status)
    except Exception as error:
        with ASSET_INDEX_LOCK:
            ASSET_INDEX["error"] = str(error)
    finally:
        with ASSET_INDEX_LOCK:
            ASSET_INDEX["building"] = False


def asset_snapshot_status(owner_address=""):
    status = safe_peer_status()
    owner = _asset_owner(owner_address)
    with ASSET_INDEX_LOCK:
        if ASSET_INDEX["height"] > status["height"] or (ASSET_INDEX["height"] == status["height"] and ASSET_INDEX["tip"] != status["tip"]):
            ASSET_INDEX.update(height=0, tip=ASSET_INDEX_INITIAL_TIP, definitions={}, balances={}, error=None)
        ready = ASSET_INDEX["height"] >= status["height"] and ASSET_INDEX["tip"] == status["tip"]
        if not ready and not ASSET_INDEX["building"]:
            ASSET_INDEX.update(building=True, target_height=status["height"], error=None)
            try:
                threading.Thread(target=_build_asset_index, args=(status,), daemon=True).start()
            except RuntimeError as error:
                ASSET_INDEX.update(building=False, error=str(error))
        definitions = {key: value.copy() for key, value in ASSET_INDEX["definitions"].items()}
        balances = {key: value.copy() for key, value in ASSET_INDEX["balances"].items()}
        indexed_height = ASSET_INDEX["height"]
        indexing = ASSET_INDEX["building"] or not ready
        error = ASSET_INDEX["error"]
    return _asset_index_snapshot(status, owner, definitions, balances, indexed_height, indexing, error)


def search_snapshot(query):
    query = query.strip()
    if not query:
        raise ValueError("enter a block height, block hash or transaction ID")
    if query.startswith("tsc1_"):
        return {
            "query": query,
            "found": False,
            "available": False,
            "message": "Address lookup is unavailable because transaction outputs are private; use the wallet to scan your own balance.",
        }
    is_height = query.isdecimal() and len(query) < 64
    if not is_height and not re.fullmatch(r"[0-9a-fA-F]{64}", query):
        raise ValueError("search accepts a block height, 64-character block hash or transaction ID")
    index_status = asset_snapshot_status()
    with ASSET_INDEX_LOCK:
        height = ASSET_INDEX["height"]
        error = ASSET_INDEX["error"]
        if is_height:
            block_height = int(query)
            summary = BLOCK_INDEX["blocks"].get(str(block_height))
            kind = "block"
        else:
            value = query.lower()
            block_height = BLOCK_INDEX["by_hash"].get(value)
            kind = "block" if block_height is not None else "transaction"
            if block_height is None:
                block_height = BLOCK_INDEX["transactions"].get(value)
            summary = BLOCK_INDEX["blocks"].get(str(block_height)) if block_height is not None else None
    if summary is not None:
        block = dict(summary)
        block["transactions"] = [dict(item) for item in summary["transactions"]]
        block["asset_operations"] = [dict(item) for item in summary["asset_operations"]]
        confirmations = max(0, index_status["target_height"] - block["height"])
        block["confirmations"] = confirmations
        for transaction in block["transactions"]:
            transaction["confirmations"] = confirmations
            transaction["included"] = True
            transaction["finality_confirmed"] = confirmations >= 10
            transaction["confirmed"] = confirmations >= 10
        for operation in block["asset_operations"]:
            operation["confirmations"] = confirmations
            operation["included"] = True
            operation["finality_confirmed"] = confirmations >= 10
            operation["confirmed"] = confirmations >= 10
        record = {"block": block}
        if kind == "transaction" and not is_height:
            record["transaction"] = next(
                (item for item in block["transactions"] if item["txid"] == query.lower()),
                None,
            )
            record["asset_operation"] = next(
                (item for item in block["asset_operations"] if item["txid"] == query.lower()),
                None,
            )
        return {
            "query": query,
            "found": True,
            "kind": kind,
            "indexed_height": height,
            **record,
        }
    return {
        "query": query,
        "found": False,
        "indexing": index_status["indexing"],
        "indexed_height": height,
        "target_height": index_status["target_height"],
        "error": error,
        "message": "Search index is still building." if index_status["indexing"] else "No matching block or transaction was found.",
    }


def submit_transaction(encoded):
    data = base64.b64decode(encoded, validate=True)
    if not data or len(data) > 512 * 1024:
        raise ValueError("invalid transaction size")
    batch = (1).to_bytes(2, "little") + len(data).to_bytes(4, "little") + data
    with peer_connect() as stream:
        stream.sendall(b"Q" + len(batch).to_bytes(4, "little") + batch)
        if read_exact(stream, 8) != MAGIC:
            raise ValueError("invalid transaction response")
        accepted = read_exact(stream, 1)[0]
        count = int.from_bytes(read_exact(stream, 2), "little")
        if not accepted:
            raise ValueError("peer rejected signed transaction")
        if count != 1:
            raise ValueError("invalid transaction response count")
        txid = read_exact(stream, 32).hex()
        return txid


def submit_asset_transaction(encoded):
    data = base64.b64decode(encoded, validate=True)
    if len(data) < 96 or len(data) > 512 * 1024:
        raise ValueError("invalid asset transaction size")
    with peer_connect() as stream:
        stream.sendall(b"A" + len(data).to_bytes(4, "little") + data)
        if read_exact(stream, 8) != MAGIC:
            raise ValueError("invalid asset response")
        accepted = read_exact(stream, 1)[0]
        txid = read_exact(stream, 32).hex()
        if not accepted:
            raise ValueError("asset transaction rejected")
        return txid


def submit_dex_operation(encoded):
    data = base64.b64decode(encoded, validate=True)
    if len(data) == 0 or len(data) > 512:
        raise ValueError("invalid dex operation size")
    with peer_connect() as stream:
        stream.sendall(b"D" + len(data).to_bytes(4, "little") + data)
        if read_exact(stream, 8) != MAGIC:
            raise ValueError("invalid dex response")
        accepted = read_exact(stream, 1)[0]
        operation_id = read_exact(stream, 32).hex()
        if not accepted:
            raise ValueError("dex operation rejected")
        return operation_id


def dex_operation_status(operation_id):
    if len(operation_id) != 64:
        raise ValueError("invalid operation id")
    operation = bytes.fromhex(operation_id)
    with peer_connect() as stream:
        stream.sendall(b"J" + operation)
        if read_exact(stream, 8) != MAGIC:
            raise ValueError("invalid dex status response")
        status = read_exact(stream, 1)[0]
    return {0: "unknown", 1: "pending", 2: "confirmed"}.get(status, "unknown")


class Handler(BaseHTTPRequestHandler):
    def send_cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Vary", "Origin")

    def send_json(self, status, payload):
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_cors_headers()
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            self.close_connection = True

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        path = urllib.parse.urlsplit(self.path).path
        if path == "/health":
            self.send_json(200, {"service": "tenebra-public-api", "online": True})
            return
        if path == "/api/search":
            try:
                query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
                self.send_json(200, search_snapshot(query.get("q", [""])[0]))
            except ValueError as error:
                self.send_json(400, {"error": str(error)})
            except Exception as error:
                self.send_json(503, {"error": str(error)})
            return
        if path == "/api/status":
            try:
                self.send_json(200, safe_peer_status())
            except Exception as error:
                self.send_json(503, {"online": False, "error": str(error)})
            return
        if path == "/api/blocks/latest":
            try:
                query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
                limit = int(query.get("limit", ["10"])[0])
                self.send_json(200, latest_local_blocks(limit))
            except Exception as error:
                status = 503 if isinstance(error, (ConnectionError, OSError)) else 400
                self.send_json(status, {"error": str(error)})
            return
        if path.startswith("/api/blocks"):
            try:
                query = urllib.parse.urlsplit(self.path).query
                params = dict(item.split("=", 1) for item in query.split("&") if "=" in item)
                start = int(params.get("from", "1"))
                limit = int(params.get("limit", str(MAX_PAGE)))
                local_files = sorted(BLOCKS_DIR.glob("*.bin"))
                if local_files and start + limit - 1 <= len(local_files):
                    payload = local_blocks(start, limit, params.get("anchor"))
                else:
                    payload = public_blocks(start, limit, params.get("anchor"))
                self.send_json(200, payload)
            except Exception as error:
                status = 503 if isinstance(error, (ConnectionError, OSError)) or "peer closed" in str(error).lower() else 400
                self.send_json(status, {"error": str(error)})
            return
        if path.startswith("/api/dex/status"):
            try:
                query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
                operation_id = query.get("id", [""])[0]
                self.send_json(200, {"operation_id": operation_id, "status": dex_operation_status(operation_id)})
            except Exception as error:
                self.send_json(400, {"error": str(error)})
            return
        if path == "/api/miner":
            addresses = read_miner_addresses()
            self.send_json(200, {
                "enabled": bool(addresses),
                "address": addresses[0] if addresses else "",
                "addresses": addresses,
            })
            return
        if path == "/api/miner/challenge":
            self.send_json(200, {"challenge": issue_miner_challenge().hex(), "expires_in": MINER_CHALLENGE_TTL})
            return
        if path.startswith("/api/address"):
            try:
                query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
                address = query.get("address", [""])[0].strip()
                if not address:
                    raise ValueError("missing address")
                if not address.startswith("tsc1_") or len(address) != 141:
                    raise ValueError("invalid address")
                self.send_json(200, {
                    "address": address,
                    "balance": None,
                    "balance_tnb": None,
                    "indexed": False,
                    "transactions": [],
                    "status": "address-index-unavailable",
                    "message": "Live chain status is available, but the address index is not ready yet.",
                })
            except Exception as error:
                self.send_json(400, {"error": str(error)})
            return
        if path.startswith("/api/assets"):
            try:
                query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
                owner = query.get("owner", [""])[0]
                self.send_json(200, asset_snapshot_status(owner))
            except Exception as error:
                self.send_json(200, {"assets": [], "error": str(error)})
            return
        self.send_json(404, {"error": "not found"})

    def do_POST(self):
        path = urllib.parse.urlsplit(self.path).path
        if path == "/api/dex/submit":
            try:
                length = int(self.headers.get("Content-Length", "0"))
                payload = json.loads(self.rfile.read(length))
                operation_id = submit_dex_operation(payload["operation"])
                self.send_json(200, {"operation_id": operation_id, "accepted": True})
            except Exception as error:
                self.send_json(400, {"accepted": False, "error": str(error)})
            return
        if path == "/api/assets/submit":
            try:
                length = int(self.headers.get("Content-Length", "0"))
                payload = json.loads(self.rfile.read(length))
                self.send_json(200, {"txid": submit_asset_transaction(payload["transaction"])})
            except Exception as error:
                self.send_json(400, {"error": str(error)})
            return
        if path == "/api/submit":
            try:
                length = int(self.headers.get("Content-Length", "0"))
                payload = json.loads(self.rfile.read(length))
                self.send_json(200, {"txid": submit_transaction(payload["transaction"])})
            except Exception as error:
                self.send_json(400, {"error": str(error)})
            return
        if path != "/api/miner":
            self.send_json(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length))
            action = payload.get("action")
            address = str(payload.get("address", "")).strip()
            if not address.startswith("tsc1_") or len(address) != 141:
                raise ValueError("invalid miner address")
            challenge = str(payload.get("challenge", "")).strip().lower()
            signature = str(payload.get("signature", "")).strip().lower()
            if not verify_miner_signature(address, challenge, signature) or not consume_miner_challenge(challenge):
                self.send_json(401, {"error": "wallet signature required"})
                return
            if action not in ("start", "stop"):
                raise ValueError("invalid miner action")
            addresses = update_miner_address(address, action == "start")
            self.send_json(200, {
                "enabled": bool(addresses),
                "address": address if action == "start" else "",
                "addresses": addresses,
                "wallet_enabled": address in addresses,
            })
        except Exception as error:
            self.send_json(400, {"error": str(error)})

    def log_message(self, format_string, *args):
        return


if __name__ == "__main__":
    ThreadingHTTPServer((BIND_HOST, BIND_PORT), Handler).serve_forever()
