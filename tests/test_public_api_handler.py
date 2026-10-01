import importlib.util
import pathlib
import tempfile
import unittest
from unittest.mock import patch

MODULE_PATH = pathlib.Path(__file__).resolve().parents[1] / "deploy" / "public-api.py"
SPEC = importlib.util.spec_from_file_location("public_api_module", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
Handler = MODULE.Handler


class FailingWriter:
    def write(self, _data):
        raise BrokenPipeError("Broken pipe")

    def flush(self):
        return None


class FakePeer:
    def __init__(self, response):
        self.response = bytearray(response)
        self.sent = bytearray()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def sendall(self, data):
        self.sent.extend(data)

    def recv(self, size):
        data = self.response[:size]
        del self.response[:size]
        return bytes(data)


class PublicApiHandlerTest(unittest.TestCase):
    def test_miner_registry_keeps_concurrent_wallets_and_stops_only_selected(self):
        with tempfile.TemporaryDirectory() as directory:
            miner_file = pathlib.Path(directory) / "miner-address"
            with patch.object(MODULE, "MINER_ADDRESS_FILE", miner_file):
                addresses = [f"wallet-{index}" for index in range(20)]
                for address in addresses:
                    MODULE.update_miner_address(address, True)
                self.assertEqual(MODULE.read_miner_addresses(), addresses)
                self.assertEqual(
                    MODULE.update_miner_address("wallet-0", False),
                    addresses[1:],
                )
                self.assertEqual(MODULE.read_miner_addresses(), addresses[1:])

    def test_miner_registry_reads_legacy_single_address_file(self):
        with tempfile.TemporaryDirectory() as directory:
            miner_file = pathlib.Path(directory) / "miner-address"
            miner_file.write_text("legacy-wallet\n")
            with patch.object(MODULE, "MINER_ADDRESS_FILE", miner_file):
                self.assertEqual(MODULE.read_miner_addresses(), ["legacy-wallet"])

    def test_asset_index_replays_issuer_options_mint_burn_and_supply_cap(self):
        prefix = b"TSC-1:asset-tx:v2"
        issuer = bytes.fromhex("31" * 32)
        nonce = 11
        asset_id = MODULE.hashlib.sha256(b"TENEBRA:asset:v1" + issuer + nonce.to_bytes(8, "little")).digest()
        create = (prefix + b"\x03" + issuer + nonce.to_bytes(8, "little")
                  + b"\x04Coin\x03MNG\x09" + (1000).to_bytes(8, "little")
                  + (100).to_bytes(8, "little") + b"\x01\x01" + (500).to_bytes(2, "little")
                  + b"\x01" + bytes.fromhex("33" * 64))
        mint = prefix + b"\x01" + asset_id + issuer + (25).to_bytes(8, "little")
        burn = prefix + b"\x04" + asset_id + issuer + (5).to_bytes(8, "little")
        cap = prefix + b"\x05" + asset_id + issuer + (2000).to_bytes(8, "little")
        options = prefix + b"\x06" + asset_id + issuer + b"\x00\x01" + (250).to_bytes(2, "little") + b"\x00"

        def block(operation, height):
            signed = operation + issuer + bytes(64)
            transaction_count_size = 1 if MODULE.os.environ.get("TSC1_DEVNET_V3_PEER_KEY") else 2
            return (b"TNB1BLK001" + bytes(32) + (1).to_bytes(4, "little") + b"R"
                + (0).to_bytes(transaction_count_size, "little") + b"\x00\x00" + (1).to_bytes(2, "little")
                    + len(signed).to_bytes(4, "little") + signed + b"\x00" + bytes(8))

        definitions = {}
        balances = {}
        for height, operation in enumerate((create, mint, burn, cap, options), start=1):
            MODULE._apply_asset_block(block(operation, height), height, definitions, balances)

        asset = definitions[asset_id.hex()]
        self.assertEqual(asset["issuer"], issuer.hex())
        self.assertEqual(asset["minted"], 120)
        self.assertEqual(asset["max_supply"], 2000)
        self.assertFalse(asset["mintable"])
        self.assertTrue(asset["burnable"])
        self.assertEqual(asset["issuer_fee_bps"], 250)
        self.assertIsNone(asset["issuer_treasury"])
        self.assertEqual(balances[asset_id.hex()][issuer.hex()], 120)

    def test_asset_snapshot_indexes_creation_and_transfer(self):
        prefix = b"TSC-1:asset-tx:v2"
        issuer = bytes.fromhex("11" * 32)
        receiver = bytes.fromhex("22" * 32)
        nonce = 7
        asset_id = MODULE.hashlib.sha256(b"TENEBRA:asset:v1" + issuer + nonce.to_bytes(8, "little")).digest()
        create = (prefix + b"\x00" + issuer + nonce.to_bytes(8, "little")
                  + b"\x04Coin\x03NFT\x00" + (1).to_bytes(8, "little")
                  + (1).to_bytes(8, "little") + issuer + bytes(64))
        transfer = (prefix + b"\x02" + asset_id + issuer + receiver
                    + (1).to_bytes(8, "little") + issuer + bytes(64))

        def block(operation):
            return (b"TNB1BLK001" + bytes(32) + (1).to_bytes(4, "little") + b"R"
                    + (0).to_bytes(2, "little") + b"\x00\x00" + (1).to_bytes(2, "little")
                    + len(operation).to_bytes(4, "little") + operation + b"\x00" + bytes(8))

        blocks = [block(create), block(transfer)]
        owner_address = "tsc1_" + bytes(32).hex() + issuer.hex() + bytes(4).hex()
        receiver_address = "tsc1_" + bytes(32).hex() + receiver.hex() + bytes(4).hex()

        def page(start, _limit, _anchor=None):
            encoded = MODULE.base64.b64encode(blocks[start - 1]).decode("ascii")
            return {"start": start, "blocks": [encoded], "count": 1, "tip": str(start)}

        with patch.object(MODULE, "peer_status", return_value={"height": 2, "tip": "2"}), patch.object(MODULE, "public_blocks", side_effect=page):
            issuer_assets = MODULE.asset_snapshot(owner_address)["assets"]
            receiver_assets = MODULE.asset_snapshot(receiver_address)["assets"]

        self.assertEqual(issuer_assets[0]["asset_id"], asset_id.hex())
        self.assertEqual(issuer_assets[0]["balance"], 0)
        self.assertEqual(receiver_assets[0]["balance"], 1)
        with patch.object(MODULE, "asset_snapshot_status", return_value={"target_height": 2, "indexing": False}):
            search = MODULE.search_snapshot(issuer_assets[0]["creation_txid"])
            block_search = MODULE.search_snapshot("1")
            hash_search = MODULE.search_snapshot(blocks[0] and MODULE.block_hash(blocks[0]).hex())
        self.assertTrue(search["found"])
        self.assertEqual(search["asset_operation"]["kind"], "create")
        self.assertTrue(search["asset_operation"]["included"])
        self.assertFalse(search["asset_operation"]["finality_confirmed"])
        self.assertEqual(block_search["block"]["height"], 1)
        self.assertEqual(hash_search["kind"], "block")

    def test_submit_transaction_uses_batch_protocol(self):
        transaction = b"signed transaction"
        txid = bytes.fromhex("ab" * 32)
        peer = FakePeer(MODULE.MAGIC + MODULE.MAGIC + b"\x01\x01\x00" + txid)

        with patch.dict(MODULE.os.environ, {"TSC1_DEVNET_V3_PEER_KEY": "", "TSC1_DEVNET_V3_PEER_KEYS": ""}, clear=False):
            with patch.object(MODULE.socket, "create_connection", return_value=peer):
                result = MODULE.submit_transaction(MODULE.base64.b64encode(transaction).decode())

        self.assertEqual(result, txid.hex())
        self.assertEqual(peer.sent[:40], MODULE.MAGIC + MODULE.GENESIS)
        self.assertEqual(peer.sent[40], ord("Q"))
        batch_length = int.from_bytes(peer.sent[41:45], "little")
        self.assertEqual(peer.sent[45:47], b"\x01\x00")
        self.assertEqual(int.from_bytes(peer.sent[47:51], "little"), len(transaction))
        self.assertEqual(peer.sent[51:51 + len(transaction)], transaction)
        self.assertEqual(batch_length, len(transaction) + 6)

    def test_submit_transaction_surfaces_peer_rejection(self):
        peer = FakePeer(MODULE.MAGIC + MODULE.MAGIC + b"\x00\x00\x00")

        with patch.dict(MODULE.os.environ, {"TSC1_DEVNET_V3_PEER_KEY": "", "TSC1_DEVNET_V3_PEER_KEYS": ""}, clear=False):
            with patch.object(MODULE.socket, "create_connection", return_value=peer):
                with self.assertRaisesRegex(ValueError, "peer rejected signed transaction"):
                    MODULE.submit_transaction(MODULE.base64.b64encode(b"invalid").decode())

    def test_send_json_handles_broken_pipe(self):
        handler = object.__new__(Handler)
        handler.send_response = lambda _status: None
        handler.send_header = lambda *args, **kwargs: None
        handler.end_headers = lambda: None
        handler.wfile = FailingWriter()
        handler.close_connection = False

        handler.send_json(200, {"ok": True})

        self.assertTrue(handler.close_connection)

    def test_peer_magic_matches_the_imported_network_configuration(self):
        expected = b"TSC1P3V8" if MODULE.os.environ.get("TSC1_DEVNET_V3_PEER_KEY", "").strip() else b"TNBMN001"
        self.assertEqual(MODULE.MAGIC, expected)

    def test_asset_endpoint_returns_empty_payload_on_snapshot_failure(self):
        handler = object.__new__(Handler)
        handler.path = "/api/assets?owner=tsc1_" + ("a" * 136)
        handler.send_json = lambda status, payload: setattr(handler, "last_response", (status, payload))
        handler.headers = {}

        with patch.object(MODULE, "asset_snapshot_status", side_effect=RuntimeError("snapshot unavailable")):
            Handler.do_GET(handler)

        self.assertEqual(handler.last_response[0], 200)
        self.assertEqual(handler.last_response[1]["assets"], [])
        self.assertIn("snapshot unavailable", handler.last_response[1]["error"])

    def test_asset_endpoint_returns_progress_while_index_builds(self):
        handler = object.__new__(Handler)
        handler.path = "/api/assets"
        handler.send_json = lambda status, payload: setattr(handler, "last_response", (status, payload))

        initial = {
            "height": 0,
            "tip": MODULE.ASSET_INDEX_INITIAL_TIP,
            "definitions": {},
            "balances": {},
            "building": False,
            "target_height": 0,
            "error": None,
        }
        with patch.dict(MODULE.ASSET_INDEX, initial, clear=True), \
             patch.object(MODULE, "peer_status", return_value={"height": 12, "tip": "current-tip"}), \
             patch.object(MODULE.threading, "Thread") as worker:
            Handler.do_GET(handler)

        self.assertEqual(handler.last_response[0], 200)
        self.assertTrue(handler.last_response[1]["indexing"])
        self.assertEqual(handler.last_response[1]["indexed_height"], 0)
        self.assertEqual(handler.last_response[1]["target_height"], 12)
        worker.return_value.start.assert_called_once()

    def test_asset_snapshot_uses_local_status_when_peer_connection_resets(self):
        status = {"height": 20838, "tip": "local-tip"}
        initial = {
            "height": 0,
            "tip": MODULE.ASSET_INDEX_INITIAL_TIP,
            "definitions": {},
            "balances": {},
            "building": False,
            "target_height": 0,
            "error": None,
        }
        with patch.dict(MODULE.ASSET_INDEX, initial, clear=True), \
             patch.object(MODULE, "safe_peer_status", return_value=status), \
             patch.object(MODULE, "peer_status", side_effect=ConnectionResetError("peer reset")), \
             patch.object(MODULE.threading, "Thread") as worker:
            snapshot = MODULE.asset_snapshot_status()

        self.assertTrue(snapshot["indexing"])
        self.assertEqual(snapshot["target_height"], 20838)
        self.assertIsNone(snapshot["error"])
        worker.return_value.start.assert_called_once()

    def test_search_finds_block_and_transaction_and_discloses_private_address_limit(self):
        block_hash = "ab" * 32
        transaction_id = "12" * 32
        summary = {
            "height": 7,
            "hash": block_hash,
            "confirmations": 0,
            "transactions": [{"txid": transaction_id, "confirmed": False, "confirmations": 0}],
            "asset_operations": [],
            "dex_operations": 0,
        }
        index = {
            "height": 7,
            "tip": block_hash,
            "blocks": {"7": summary},
            "by_hash": {block_hash: 7},
            "transactions": {transaction_id: 7},
        }
        with patch.dict(MODULE.BLOCK_INDEX, index, clear=True), \
             patch.object(MODULE, "asset_snapshot_status", return_value={"target_height": 7, "indexing": False}):
            by_height = MODULE.search_snapshot("7")
            by_hash = MODULE.search_snapshot(block_hash)
            by_transaction = MODULE.search_snapshot(transaction_id)
            by_address = MODULE.search_snapshot("tsc1_" + "a" * 136)

        self.assertEqual(by_height["block"]["hash"], block_hash)
        self.assertEqual(by_hash["kind"], "block")
        self.assertEqual(by_transaction["transaction"]["txid"], transaction_id)
        self.assertFalse(by_address["available"])
        self.assertIn("private", by_address["message"])

    def test_search_endpoint_routes_query_to_index(self):
        handler = object.__new__(Handler)
        handler.path = "/api/search?q=7"
        handler.send_json = lambda status, payload: setattr(handler, "last_response", (status, payload))

        with patch.object(MODULE, "search_snapshot", return_value={"found": True, "kind": "block"}) as search:
            Handler.do_GET(handler)

        search.assert_called_once_with("7")
        self.assertEqual(handler.last_response, (200, {"found": True, "kind": "block"}))

    def test_address_lookup_endpoint_returns_basic_payload(self):
        handler = object.__new__(Handler)
        handler.path = "/api/address?address=tsc1_" + ("a" * 136)
        handler.send_json = lambda status, payload: setattr(handler, "last_response", (status, payload))
        handler.headers = {}

        Handler.do_GET(handler)

        self.assertEqual(handler.last_response[0], 200)
        self.assertIn("address", handler.last_response[1])
        self.assertIn("balance", handler.last_response[1])
        self.assertFalse(handler.last_response[1].get("indexed", True))
        self.assertIn("unavailable", handler.last_response[1].get("status", "").lower())


if __name__ == "__main__":
    unittest.main()
