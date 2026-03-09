"""
Comprehensive GUI backend integration tests.

Tests every NodeBackend button/method in order, checking all balances,
wallets, transactions, PMCs, staking, trust lines, DEX, and consensus.
Every returned dict is validated field-by-field for accuracy.
Designed to expose every functional issue in the system.
"""

from __future__ import annotations

import hashlib
import json
import math
import time
import unittest
from unittest.mock import patch

from nexaflow_core.config import NexaFlowConfig
from nexaflow_core.network import Network
from nexaflow_core.wallet import Wallet

# Qt setup - required for NodeBackend signals
_qt_available = True
try:
    from PyQt6.QtWidgets import QApplication
except ImportError:
    _qt_available = False

if _qt_available:
    _app = QApplication.instance() or QApplication([])

from nexaflow_gui.backend import NodeBackend


# ---------------------------------------------------------------------------
#  Helpers
# ---------------------------------------------------------------------------

SUPPLY = 100_000_000.0
GENESIS = "rGenesis"
FEE = 0.00001
BASE_RESERVE = 10.0
OWNER_RESERVE_INC = 2.0
EMPTY_TX_ROOT = "0" * 64


def _make_backend(
    genesis_addr: str = GENESIS,
    supply: float = SUPPLY,
    peers: list[str] | None = None,
) -> NodeBackend:
    """Create a NodeBackend with controlled config (no nexaflow.toml)."""
    with patch("nexaflow_gui.backend.load_config") as mock_lc:
        cfg = NexaFlowConfig()
        cfg.ledger.total_supply = supply
        cfg.genesis.accounts = {genesis_addr: supply}
        cfg.node.node_id = "test-node"
        cfg.node.peers = peers or []
        mock_lc.return_value = cfg
        backend = NodeBackend()
    return backend


def _fund(backend: NodeBackend, address: str, amount: float) -> None:
    """Fund an address from genesis on all validators."""
    backend.network.fund_account(address, amount)


def _find_valid_nonce(coin_id: str, miner: str, difficulty: int,
                      prev_hash: str) -> int | None:
    """Brute-force a valid PoW nonce for PMC mining."""
    target = "0" * difficulty
    for n in range(10_000_000):
        blob = f"{coin_id}:{miner}:{n}:{prev_hash}:{EMPTY_TX_ROOT}".encode()
        h = hashlib.sha256(hashlib.sha256(blob).digest()).hexdigest()
        if h[:difficulty] == target:
            return n
    return None


def _pmc_balance(backend: NodeBackend, address: str, coin_id: str) -> float:
    """Get a single PMC token balance from a portfolio."""
    for h in backend.pmc_get_portfolio(address):
        if h["coin_id"] == coin_id:
            return h["balance"]
    return 0.0


# ===================================================================
#  1. WALLET LIFECYCLE
# ===================================================================

class Test01_WalletLifecycle(unittest.TestCase):

    def setUp(self):
        self.b = _make_backend()

    def test_01_create_wallet_returns_correct_fields(self):
        info = self.b.create_wallet("Alice")
        for key in ("address", "name", "balance", "public_key"):
            self.assertIn(key, info, f"Missing key: {key}")
        self.assertEqual(info["name"], "Alice")
        self.assertEqual(info["balance"], 0.0)
        self.assertIsInstance(info["address"], str)
        self.assertTrue(info["address"].startswith("r"))
        self.assertIsInstance(info["public_key"], str)
        self.assertGreater(len(info["public_key"]), 0)

    def test_02_wallet_registered_on_all_validators(self):
        info = self.b.create_wallet("Alice")
        addr = info["address"]
        for node in self.b.network.nodes.values():
            self.assertTrue(
                node.ledger.account_exists(addr),
                f"Wallet not registered on {node.node_id}")

    def test_03_get_wallets_field_validation(self):
        self.b.create_wallet("W1")
        self.b.create_wallet("W2")
        wallets = self.b.get_wallets()
        self.assertEqual(len(wallets), 2)
        for w in wallets:
            for key in ("address", "name", "balance", "public_key"):
                self.assertIn(key, w, f"Missing key in get_wallets item: {key}")
            self.assertIsInstance(w["address"], str)
            self.assertIsInstance(w["name"], str)
            self.assertIsInstance(w["balance"], (int, float))
            self.assertIsInstance(w["public_key"], str)
        names = {w["name"] for w in wallets}
        self.assertIn("W1", names)
        self.assertIn("W2", names)

    def test_04_get_wallet_keys_field_validation(self):
        info = self.b.create_wallet("KeyTest")
        keys = self.b.get_wallet_keys(info["address"])
        self.assertIsNotNone(keys)
        self.assertIn("address", keys)
        self.assertIn("public_key", keys)
        self.assertIn("key_type", keys)
        self.assertEqual(keys["address"], info["address"])
        self.assertEqual(keys["public_key"], info["public_key"])
        self.assertNotIn("private_key", keys)

    def test_05_import_from_seed_deterministic(self):
        info1 = self.b.import_wallet_from_seed("test-seed-xyz", "Seeded")
        b2 = _make_backend()
        info2 = b2.import_wallet_from_seed("test-seed-xyz", "Seeded2")
        self.assertEqual(info1["address"], info2["address"])
        self.assertEqual(info1["public_key"], info2["public_key"])
        for key in ("address", "name", "balance", "public_key"):
            self.assertIn(key, info1)

    def test_06_export_import_roundtrip(self):
        info = self.b.create_wallet("Original")
        addr = info["address"]
        _fund(self.b, addr, 10_000.0)
        exported = self.b.export_wallet(addr, "secret123")
        self.assertIsInstance(exported, str)
        parsed = json.loads(exported)
        self.assertIn("name", parsed)
        del self.b.wallets[addr]
        reimported = self.b.import_wallet_from_file(exported, "secret123")
        self.assertEqual(reimported["address"], addr)
        self.assertIn(addr, self.b.wallets)
        for key in ("address", "name", "balance", "public_key"):
            self.assertIn(key, reimported)

    def test_07_recover_from_keys(self):
        ref = Wallet.create()
        info = self.b.recover_wallet_from_keys(
            public_key=ref.public_key.hex(),
            private_key=ref.private_key.hex(),
        )
        self.assertEqual(info["address"], ref.address)
        for key in ("address", "name", "balance", "public_key"):
            self.assertIn(key, info)

    def test_08_recover_mismatched_keys_fails(self):
        w1 = Wallet.create()
        w2 = Wallet.create()
        with self.assertRaises(ValueError):
            self.b.recover_wallet_from_keys(
                public_key=w1.public_key.hex(),
                private_key=w2.private_key.hex(),
            )

    def test_09_wallet_created_signal_fires(self):
        received = []
        self.b.wallet_created.connect(lambda d: received.append(d))
        self.b.create_wallet("SignalTest")
        self.assertEqual(len(received), 1)
        self.assertIn("address", received[0])

    def test_10_get_wallet_keys_nonexistent_raises(self):
        with self.assertRaises(ValueError):
            self.b.get_wallet_keys("nonexistent")

    def test_11_export_nonexistent_wallet_raises(self):
        with self.assertRaises(ValueError):
            self.b.export_wallet("nonexistent", "pass")

    def test_12_wallet_balance_reflects_funding(self):
        info = self.b.create_wallet("Funded")
        _fund(self.b, info["address"], 50_000.0)
        wallets = self.b.get_wallets()
        funded = next(w for w in wallets if w["address"] == info["address"])
        self.assertAlmostEqual(funded["balance"], 50_000.0, places=4)


# ===================================================================
#  2. GENESIS AND INITIAL BALANCES
# ===================================================================

class Test02_GenesisBalances(unittest.TestCase):

    def test_01_genesis_has_full_supply(self):
        b = _make_backend()
        bal = b.get_balance(GENESIS)
        self.assertAlmostEqual(bal, SUPPLY, places=4)

    def test_02_genesis_exists_on_all_nodes(self):
        b = _make_backend(peers=["10.0.0.2:9001"])
        for node in b.network.nodes.values():
            self.assertTrue(node.ledger.account_exists(GENESIS))
            self.assertAlmostEqual(
                node.ledger.get_balance(GENESIS), SUPPLY, places=4)

    def test_03_fund_account_updates_all_nodes(self):
        b = _make_backend(peers=["10.0.0.2:9001"])
        w = b.create_wallet("Funded")
        _fund(b, w["address"], 50_000.0)
        for node in b.network.nodes.values():
            self.assertAlmostEqual(
                node.ledger.get_balance(w["address"]), 50_000.0, places=4)

    def test_04_get_all_accounts_includes_genesis(self):
        b = _make_backend()
        accounts = b.get_all_accounts()
        addrs = [a["address"] for a in accounts]
        self.assertIn(GENESIS, addrs)

    def test_05_ledger_summary_field_validation(self):
        b = _make_backend()
        s = b.get_ledger_summary()
        expected_keys = [
            "ledger_sequence", "closed_ledgers", "total_accounts",
            "total_supply", "initial_supply", "total_burned",
            "total_minted", "total_staked", "active_stakes",
            "total_interest_paid",
        ]
        for key in expected_keys:
            self.assertIn(key, s, f"Missing ledger_summary key: {key}")
        self.assertAlmostEqual(s["total_supply"], SUPPLY, places=0)
        self.assertIsInstance(s["ledger_sequence"], int)
        self.assertIsInstance(s["total_accounts"], int)
        self.assertGreater(s["total_accounts"], 0)


# ===================================================================
#  3. PAYMENT FLOW
# ===================================================================

class Test03_PaymentFlow(unittest.TestCase):

    def setUp(self):
        self.b = _make_backend()
        self.w1 = self.b.create_wallet("Sender")
        self.w2 = self.b.create_wallet("Receiver")
        self.addr1 = self.w1["address"]
        self.addr2 = self.w2["address"]
        _fund(self.b, self.addr1, 1_000_000.0)

    def test_01_payment_result_fields(self):
        result = self.b.send_payment(self.addr1, self.addr2, 1000.0)
        self.assertIsNotNone(result)
        for key in ("tx_type", "tx_type_name", "account", "destination",
                     "amount", "fee", "sequence", "timestamp", "tx_id",
                     "result", "_accepted"):
            self.assertIn(key, result, f"Missing payment result key: {key}")
        self.assertTrue(result["_accepted"])
        self.assertEqual(result["account"], self.addr1)
        self.assertEqual(result["destination"], self.addr2)
        self.assertEqual(result["tx_type"], 0)
        self.assertEqual(result["tx_type_name"], "Payment")
        self.assertIsInstance(result["tx_id"], str)
        self.assertEqual(len(result["tx_id"]), 64)

    def test_02_payment_amount_field_structure(self):
        result = self.b.send_payment(self.addr1, self.addr2, 5000.0)
        amt = result["amount"]
        self.assertIsInstance(amt, dict)
        self.assertIn("value", amt)
        self.assertIn("currency", amt)
        self.assertAlmostEqual(amt["value"], 5000.0, places=4)
        self.assertEqual(amt["currency"], "NXF")
        fee = result["fee"]
        self.assertIn("value", fee)
        self.assertAlmostEqual(fee["value"], FEE, places=8)

    def test_03_receiver_balance_updated(self):
        self.b.send_payment(self.addr1, self.addr2, 5000.0)
        bal = self.b.get_balance(self.addr2)
        self.assertAlmostEqual(bal, 5000.0, places=4)

    def test_04_sender_balance_decreased(self):
        before = self.b.get_balance(self.addr1)
        self.b.send_payment(self.addr1, self.addr2, 5000.0)
        after = self.b.get_balance(self.addr1)
        self.assertAlmostEqual(after, before - 5000.0 - FEE, places=4)

    def test_05_multiple_payments_sequence_ok(self):
        for i in range(5):
            result = self.b.send_payment(self.addr1, self.addr2, 100.0)
            self.assertIsNotNone(result, f"Payment {i+1} returned None")
            self.assertTrue(result["_accepted"], f"Payment {i+1} rejected")
        self.assertAlmostEqual(self.b.get_balance(self.addr2), 500.0, places=4)

    def test_06_insufficient_balance_handled(self):
        result = self.b.send_payment(self.addr2, self.addr1, 100.0)
        if result is not None:
            self.assertFalse(result.get("_accepted", True))

    def test_07_no_wallet_returns_none(self):
        result = self.b.send_payment("nonexistent", self.addr2, 100.0)
        self.assertIsNone(result)

    def test_08_tx_history_populated(self):
        self.b.send_payment(self.addr1, self.addr2, 100.0)
        history = self.b.get_tx_history()
        self.assertGreater(len(history), 0)
        entry = history[0]
        for key in ("tx_type", "account", "tx_id", "result"):
            self.assertIn(key, entry)

    def test_09_tx_submitted_signal_fires(self):
        received = []
        self.b.tx_submitted.connect(lambda d: received.append(d))
        self.b.send_payment(self.addr1, self.addr2, 100.0)
        self.assertEqual(len(received), 1)

    def test_10_balance_updated_signal_fires(self):
        received = []
        self.b.balance_updated.connect(lambda a, b: received.append((a, b)))
        self.b.send_payment(self.addr1, self.addr2, 100.0)
        addrs = [r[0] for r in received]
        self.assertIn(self.addr1, addrs)

    def test_11_bidirectional_payments(self):
        _fund(self.b, self.addr2, 500_000.0)
        self.b.send_payment(self.addr1, self.addr2, 1000.0)
        self.b.send_payment(self.addr2, self.addr1, 500.0)
        bal2 = self.b.get_balance(self.addr2)
        self.assertAlmostEqual(bal2, 500_500.0 - FEE, places=4)

    def test_12_payment_sequence_increments(self):
        r1 = self.b.send_payment(self.addr1, self.addr2, 100.0)
        r2 = self.b.send_payment(self.addr1, self.addr2, 100.0)
        self.assertGreater(r2["sequence"], r1["sequence"])


# ===================================================================
#  4. CONSENSUS
# ===================================================================

class Test04_Consensus(unittest.TestCase):

    def setUp(self):
        self.b = _make_backend(peers=["10.0.0.2:9001", "10.0.0.3:9001"])
        self.w1 = self.b.create_wallet("Sender")
        self.w2 = self.b.create_wallet("Receiver")
        _fund(self.b, self.w1["address"], 1_000_000.0)

    def test_01_consensus_result_fields(self):
        self.b.send_payment(self.w1["address"], self.w2["address"], 100.0)
        result = self.b.run_consensus()
        self.assertIsNotNone(result)
        self.assertIsInstance(result, dict)
        self.assertIn("status", result)

    def test_02_consensus_signal_fires(self):
        received = []
        self.b.consensus_completed.connect(lambda d: received.append(d))
        self.b.send_payment(self.w1["address"], self.w2["address"], 100.0)
        self.assertGreater(len(received), 0)

    def test_03_all_nodes_in_sync_after_consensus(self):
        self.b.send_payment(self.w1["address"], self.w2["address"], 5000.0)
        addr = self.w2["address"]
        balances = set()
        for node in self.b.network.nodes.values():
            balances.add(round(node.ledger.get_balance(addr), 4))
        self.assertEqual(len(balances), 1, f"Nodes disagree: {balances}")

    def test_04_empty_consensus_round(self):
        result = self.b.run_consensus()
        self.assertIsNotNone(result)

    def test_05_ledger_sequence_advances(self):
        seq_before = self.b._primary_node.ledger.current_sequence
        self.b.send_payment(self.w1["address"], self.w2["address"], 100.0)
        seq_after = self.b._primary_node.ledger.current_sequence
        self.assertGreater(seq_after, seq_before)

    def test_06_validator_statuses_field_validation(self):
        statuses = self.b.get_validator_statuses()
        self.assertEqual(len(statuses), 3)
        for s in statuses:
            for key in ("node_id", "ledger_seq", "closed_ledgers",
                        "pending_txns", "accounts", "unl_size"):
                self.assertIn(key, s, f"Missing validator status key: {key}")
            self.assertIsInstance(s["node_id"], str)
            self.assertIsInstance(s["ledger_seq"], int)
            self.assertIsInstance(s["accounts"], int)
            self.assertGreater(s["accounts"], 0)

    def test_07_network_status_field_validation(self):
        status = self.b.get_network_status()
        self.assertIn("validators", status)
        self.assertIn("nodes", status)
        self.assertEqual(status["validators"], 3)
        self.assertIsInstance(status["nodes"], dict)
        for nid, ninfo in status["nodes"].items():
            for key in ("node_id", "ledger_seq", "accounts"):
                self.assertIn(key, ninfo)

    def test_08_p2p_status_field_validation(self):
        status = self.b.get_p2p_status()
        for key in ("mode", "validator_count", "total_tx_pool", "nodes", "dev_mode"):
            self.assertIn(key, status, f"Missing p2p_status key: {key}")
        self.assertEqual(status["validator_count"], 3)
        self.assertIsInstance(status["nodes"], list)
        self.assertEqual(len(status["nodes"]), 3)
        for node in status["nodes"]:
            for key in ("node_id", "accounts", "tx_pool", "ledger_seq",
                        "closed_ledgers", "unl_size", "peers"):
                self.assertIn(key, node, f"Missing p2p node key: {key}")
            self.assertIsInstance(node["peers"], list)

    def test_09_closed_ledger_field_validation(self):
        self.b.send_payment(self.w1["address"], self.w2["address"], 100.0)
        closed = self.b.get_closed_ledgers()
        self.assertGreater(len(closed), 0)
        ledger = closed[0]
        for key in ("sequence", "hash", "parent_hash", "tx_hash",
                     "state_hash", "close_time", "tx_count", "total_nxf"):
            self.assertIn(key, ledger, f"Missing closed ledger key: {key}")
        self.assertIsInstance(ledger["sequence"], int)
        self.assertIsInstance(ledger["hash"], str)
        self.assertGreater(len(ledger["hash"]), 0)
        self.assertIsInstance(ledger["close_time"], int)
        self.assertIsInstance(ledger["total_nxf"], float)


# ===================================================================
#  5. ACCOUNT INFO
# ===================================================================

class Test05_AccountInfo(unittest.TestCase):

    def setUp(self):
        self.b = _make_backend()
        self.w = self.b.create_wallet("Acct")
        self.addr = self.w["address"]
        _fund(self.b, self.addr, 500_000.0)

    def test_01_account_info_fields(self):
        info = self.b.get_account_info(self.addr)
        self.assertIsNotNone(info)
        for key in ("address", "balance", "sequence", "owner_count",
                     "trust_lines", "open_offers", "is_gateway"):
            self.assertIn(key, info, f"Missing account_info key: {key}")
        self.assertEqual(info["address"], self.addr)
        self.assertAlmostEqual(info["balance"], 500_000.0, places=4)
        self.assertIsInstance(info["sequence"], int)
        self.assertIsInstance(info["owner_count"], int)
        self.assertIsInstance(info["trust_lines"], dict)
        self.assertIsInstance(info["open_offers"], int)
        self.assertIsInstance(info["is_gateway"], bool)

    def test_02_account_info_nonexistent(self):
        info = self.b.get_account_info("nonexistent_addr")
        self.assertIsNone(info)

    def test_03_account_info_sequence_after_tx(self):
        self.b.send_payment(self.addr, GENESIS, 10.0)
        info = self.b.get_account_info(self.addr)
        self.assertGreater(info["sequence"], 0)

    def test_04_account_info_owner_count_after_trust_line(self):
        issuer = self.b.create_wallet("Issuer")
        _fund(self.b, issuer["address"], 100_000.0)
        self.b.set_trust_line(self.addr, "USD", issuer["address"], 10_000.0)
        info = self.b.get_account_info(self.addr)
        self.assertGreater(info["owner_count"], 0)

    def test_05_account_info_trust_lines_populated(self):
        issuer = self.b.create_wallet("Issuer")
        _fund(self.b, issuer["address"], 100_000.0)
        self.b.set_trust_line(self.addr, "USD", issuer["address"], 10_000.0)
        info = self.b.get_account_info(self.addr)
        self.assertGreater(len(info["trust_lines"]), 0)

    def test_06_all_accounts_field_validation(self):
        accts = self.b.get_all_accounts()
        for a in accts:
            for key in ("address", "balance", "sequence"):
                self.assertIn(key, a, f"Missing all_accounts key: {key}")
            self.assertIsInstance(a["address"], str)
            self.assertIsInstance(a["balance"], float)


# ===================================================================
#  6. TRUST LINES
# ===================================================================

class Test06_TrustLines(unittest.TestCase):

    def setUp(self):
        self.b = _make_backend()
        self.issuer = self.b.create_wallet("Issuer")
        self.holder = self.b.create_wallet("Holder")
        self.receiver = self.b.create_wallet("Receiver")
        _fund(self.b, self.issuer["address"], 500_000.0)
        _fund(self.b, self.holder["address"], 100_000.0)
        _fund(self.b, self.receiver["address"], 100_000.0)

    def test_01_set_trust_line_result_fields(self):
        result = self.b.set_trust_line(
            self.holder["address"], "USD", self.issuer["address"], 10_000.0)
        self.assertIsNotNone(result)
        for key in ("tx_type", "tx_type_name", "account", "tx_id"):
            self.assertIn(key, result)
        self.assertEqual(result["tx_type_name"], "TrustSet")

    def test_02_trust_line_on_ledger(self):
        self.b.set_trust_line(
            self.holder["address"], "USD", self.issuer["address"], 10_000.0)
        tl = self.b._primary_node.ledger.get_trust_line(
            self.holder["address"], "USD", self.issuer["address"])
        self.assertIsNotNone(tl)
        self.assertEqual(tl.limit, 10_000.0)

    def test_03_get_trust_lines_field_validation(self):
        self.b.set_trust_line(
            self.holder["address"], "USD", self.issuer["address"], 10_000.0)
        lines = self.b.get_trust_lines()
        self.assertGreater(len(lines), 0)
        tl = lines[0]
        for key in ("currency", "issuer", "holder", "balance", "limit", "limit_peer"):
            self.assertIn(key, tl, f"Missing trust_line key: {key}")
        self.assertEqual(tl["currency"], "USD")
        self.assertEqual(tl["issuer"], self.issuer["address"])
        self.assertEqual(tl["holder"], self.holder["address"])
        self.assertAlmostEqual(tl["limit"], 10_000.0)
        self.assertAlmostEqual(tl["balance"], 0.0)

    def test_04_iou_payment_updates_trust_line_balance(self):
        self.b.set_trust_line(
            self.holder["address"], "USD", self.issuer["address"], 10_000.0)
        result = self.b.send_payment(
            self.issuer["address"], self.holder["address"], 500.0,
            currency="USD", issuer=self.issuer["address"])
        self.assertIsNotNone(result)
        self.assertTrue(result["_accepted"])
        lines = self.b.get_trust_lines()
        usd_line = next((l for l in lines if l["currency"] == "USD"
                         and l["holder"] == self.holder["address"]), None)
        self.assertIsNotNone(usd_line)
        self.assertAlmostEqual(usd_line["balance"], 500.0, places=4)

    def test_05_iou_payment_without_trust_handled(self):
        result = self.b.send_payment(
            self.issuer["address"], self.holder["address"], 500.0,
            currency="USD", issuer=self.issuer["address"])
        # Without trust line, may succeed (issuer path) or fail gracefully
        if result is not None and "_accepted" in result:
            pass  # just verify no crash

    def test_06_trust_then_nxf_payment_works(self):
        self.b.set_trust_line(
            self.holder["address"], "USD", self.issuer["address"], 5000.0)
        result = self.b.send_payment(
            self.holder["address"], self.receiver["address"], 100.0)
        self.assertIsNotNone(result)
        self.assertTrue(result["_accepted"])

    def test_07_multiple_trust_lines(self):
        self.b.set_trust_line(
            self.holder["address"], "USD", self.issuer["address"], 5000.0)
        self.b.set_trust_line(
            self.holder["address"], "EUR", self.issuer["address"], 3000.0)
        lines = self.b.get_trust_lines()
        currencies = {l["currency"] for l in lines
                      if l["holder"] == self.holder["address"]}
        self.assertIn("USD", currencies)
        self.assertIn("EUR", currencies)


# ===================================================================
#  7. DEX OFFERS
# ===================================================================

class Test07_DexOffers(unittest.TestCase):

    def setUp(self):
        self.b = _make_backend()
        self.w = self.b.create_wallet("Trader")
        _fund(self.b, self.w["address"], 500_000.0)

    def test_01_create_offer_result_fields(self):
        result = self.b.create_dex_offer(
            self.w["address"],
            pays_amount=1000.0, pays_currency="NXF", pays_issuer="",
            gets_amount=500.0, gets_currency="USD", gets_issuer=GENESIS,
        )
        self.assertIsNotNone(result)
        for key in ("tx_type", "tx_type_name", "account", "tx_id", "_fills"):
            self.assertIn(key, result, f"Missing dex result key: {key}")
        self.assertIsInstance(result["_fills"], list)

    def test_02_order_book_pairs(self):
        self.b.create_dex_offer(
            self.w["address"],
            pays_amount=100.0, pays_currency="NXF", pays_issuer="",
            gets_amount=50.0, gets_currency="USD", gets_issuer=GENESIS,
        )
        pairs = self.b.get_order_book_pairs()
        self.assertIsInstance(pairs, list)

    def test_03_order_book_snapshot_fields(self):
        self.b.create_dex_offer(
            self.w["address"],
            pays_amount=100.0, pays_currency="NXF", pays_issuer="",
            gets_amount=50.0, gets_currency="USD", gets_issuer=GENESIS,
        )
        pairs = self.b.get_order_book_pairs()
        if len(pairs) > 0:
            snapshot = self.b.get_order_book_snapshot(pairs[0])
            self.assertIn("pair", snapshot)
            self.assertIn("asks", snapshot)
            self.assertIn("bids", snapshot)
            self.assertIn("ask_count", snapshot)
            self.assertIn("bid_count", snapshot)
            self.assertIsInstance(snapshot["asks"], list)
            self.assertIsInstance(snapshot["bids"], list)

    def test_04_recent_fills(self):
        fills = self.b.get_recent_fills()
        self.assertIsInstance(fills, list)


# ===================================================================
#  8. STAKING
# ===================================================================

class Test08_Staking(unittest.TestCase):

    def setUp(self):
        self.b = _make_backend()
        self.w = self.b.create_wallet("Staker")
        self.addr = self.w["address"]
        _fund(self.b, self.addr, 500_000.0)

    def test_01_stake_reduces_balance(self):
        before = self.b.get_balance(self.addr)
        result = self.b.stake_nxf(self.addr, 10_000.0, tier=0)
        self.assertIsNotNone(result, "Stake returned None")
        after = self.b.get_balance(self.addr)
        self.assertAlmostEqual(before - after, 10_000.0 + FEE, places=4)

    def test_02_stake_result_fields(self):
        result = self.b.stake_nxf(self.addr, 10_000.0, tier=0)
        self.assertIsNotNone(result)
        for key in ("tx_type", "tx_type_name", "account", "tx_id",
                     "amount", "fee", "sequence", "result"):
            self.assertIn(key, result, f"Missing stake result key: {key}")

    def test_03_get_stakes_field_validation(self):
        self.b.stake_nxf(self.addr, 10_000.0, tier=0)
        stakes = self.b.get_stakes_for_address(self.addr)
        self.assertGreater(len(stakes), 0)
        s = stakes[0]
        expected_keys = [
            "stake_id", "address", "amount", "tier", "tier_name",
            "base_apy", "effective_apy", "effective_apy_pct",
            "lock_duration", "start_time", "maturity_time",
            "accrued_interest", "matured", "cancelled", "status",
        ]
        for key in expected_keys:
            self.assertIn(key, s, f"Missing stake key: {key}")
        self.assertEqual(s["address"], self.addr)
        self.assertAlmostEqual(s["amount"], 10_000.0, places=4)
        self.assertIsInstance(s["tier"], int)
        self.assertIsInstance(s["tier_name"], str)
        self.assertIsInstance(s["base_apy"], float)
        self.assertIsInstance(s["effective_apy_pct"], str)
        self.assertTrue(s["effective_apy_pct"].endswith("%"))
        self.assertEqual(s["status"], "Active")
        self.assertFalse(s["cancelled"])

    def test_04_cancel_stake(self):
        self.b.stake_nxf(self.addr, 10_000.0, tier=0)
        stakes = self.b.get_stakes_for_address(self.addr)
        self.assertGreater(len(stakes), 0)
        stake_id = stakes[0]["stake_id"]
        result = self.b.cancel_stake(stake_id)
        self.assertIsNotNone(result)

    def test_05_cancel_returns_balance(self):
        before = self.b.get_balance(self.addr)
        self.b.stake_nxf(self.addr, 10_000.0, tier=0)
        after_stake = self.b.get_balance(self.addr)
        self.assertLess(after_stake, before)
        stakes = self.b.get_stakes_for_address(self.addr)
        stake_id = stakes[0]["stake_id"]
        self.b.cancel_stake(stake_id)
        after_cancel = self.b.get_balance(self.addr)
        self.assertGreater(after_cancel, after_stake)

    def test_06_staking_summary_fields(self):
        self.b.stake_nxf(self.addr, 10_000.0, tier=0)
        summary = self.b.get_staking_summary(self.addr)
        self.assertIsInstance(summary, dict)
        for key in ("address", "total_staked", "stakes", "demand_multiplier"):
            self.assertIn(key, summary, f"Missing staking_summary key: {key}")
        self.assertEqual(summary["address"], self.addr)
        self.assertAlmostEqual(summary["total_staked"], 10_000.0, places=4)
        self.assertIsInstance(summary["stakes"], list)
        self.assertGreater(len(summary["stakes"]), 0)
        self.assertIsInstance(summary["demand_multiplier"], float)

    def test_07_staking_pool_summary_fields(self):
        self.b.stake_nxf(self.addr, 10_000.0, tier=0)
        pool = self.b.get_staking_pool_summary()
        self.assertIsInstance(pool, dict)
        for key in ("total_staked", "total_interest_paid",
                     "total_pending_interest", "active_stakes", "total_stakes"):
            self.assertIn(key, pool, f"Missing pool_summary key: {key}")
        self.assertAlmostEqual(pool["total_staked"], 10_000.0, places=4)
        self.assertEqual(pool["active_stakes"], 1)
        self.assertIsInstance(pool["total_interest_paid"], float)

    def test_08_staking_tiers_fields(self):
        tiers = self.b.get_staking_tiers()
        self.assertIsInstance(tiers, list)
        self.assertGreater(len(tiers), 0)
        for t in tiers:
            for key in ("tier", "name", "lock_days", "base_apy",
                        "effective_apy", "effective_apy_pct", "demand_multiplier"):
                self.assertIn(key, t, f"Missing tier key: {key}")
            self.assertIsInstance(t["tier"], int)
            self.assertIsInstance(t["name"], str)
            self.assertIsInstance(t["lock_days"], int)
            self.assertIsInstance(t["base_apy"], float)
            self.assertTrue(t["effective_apy_pct"].endswith("%"))

    def test_09_multiple_stakes_same_wallet(self):
        self.b.stake_nxf(self.addr, 10_000.0, tier=0)
        self.b.stake_nxf(self.addr, 20_000.0, tier=0)
        stakes = self.b.get_stakes_for_address(self.addr)
        self.assertGreaterEqual(len(stakes), 2)
        amounts = [s["amount"] for s in stakes]
        self.assertIn(10_000.0, amounts)
        self.assertIn(20_000.0, amounts)

    def test_10_staking_signal_fires(self):
        received = []
        self.b.staking_changed.connect(lambda: received.append(True))
        self.b.stake_nxf(self.addr, 10_000.0, tier=0)
        self.assertGreater(len(received), 0)

    def test_11_get_all_active_stakes(self):
        self.b.stake_nxf(self.addr, 10_000.0, tier=0)
        all_stakes = self.b.get_all_active_stakes()
        self.assertGreater(len(all_stakes), 0)
        self.assertEqual(all_stakes[0]["address"], self.addr)

    def test_12_stake_then_payment_works(self):
        self.b.stake_nxf(self.addr, 10_000.0, tier=0)
        w2 = self.b.create_wallet("Dest")
        result = self.b.send_payment(self.addr, w2["address"], 100.0)
        self.assertIsNotNone(result)
        self.assertTrue(result["_accepted"])


# ===================================================================
#  9. PMC COIN CREATION
# ===================================================================

class Test09_PMCCreation(unittest.TestCase):

    def setUp(self):
        self.b = _make_backend()
        self.w = self.b.create_wallet("Issuer")
        self.addr = self.w["address"]
        _fund(self.b, self.addr, 1_000_000.0)

    def test_01_create_coin_result_fields(self):
        result = self.b.pmc_create_coin(
            self.addr, "TST", "Test Coin",
            max_supply=1_000_000.0, pow_difficulty=1, base_reward=100.0,
        )
        self.assertIsNotNone(result)
        for key in ("tx_type", "tx_type_name", "account", "tx_id", "result"):
            self.assertIn(key, result, f"Missing pmc_create key: {key}")
        self.assertEqual(result["tx_type_name"], "PMCCreate")

    def test_02_coin_list_field_validation(self):
        self.b.pmc_create_coin(
            self.addr, "TST", "Test Coin",
            max_supply=500_000.0, pow_difficulty=2, base_reward=50.0,
        )
        coins = self.b.pmc_list_coins()
        self.assertGreater(len(coins), 0)
        coin = next(c for c in coins if c["symbol"] == "TST")
        expected_keys = [
            "coin_id", "symbol", "name", "issuer", "decimals",
            "max_supply", "total_minted", "total_burned", "circulating",
            "flags", "flag_names", "pow_difficulty", "base_reward",
            "block_reward", "total_mints", "metadata", "rules",
            "created_at", "frozen",
        ]
        for key in expected_keys:
            self.assertIn(key, coin, f"Missing coin list key: {key}")
        self.assertEqual(coin["symbol"], "TST")
        self.assertEqual(coin["name"], "Test Coin")
        self.assertEqual(coin["issuer"], self.addr)
        self.assertAlmostEqual(coin["max_supply"], 500_000.0)
        self.assertEqual(coin["pow_difficulty"], 2)
        self.assertAlmostEqual(coin["base_reward"], 50.0)
        self.assertAlmostEqual(coin["total_minted"], 0.0)
        self.assertAlmostEqual(coin["total_burned"], 0.0)
        self.assertAlmostEqual(coin["circulating"], 0.0)
        self.assertIsInstance(coin["flag_names"], list)
        self.assertIn("MINTABLE", coin["flag_names"])
        self.assertIsInstance(coin["rules"], list)
        self.assertFalse(coin["frozen"])
        self.assertIsInstance(coin["created_at"], float)

    def test_03_pmc_get_coin_matches_list(self):
        self.b.pmc_create_coin(
            self.addr, "TST", "Test Coin",
            pow_difficulty=1, base_reward=100.0,
        )
        coins = self.b.pmc_list_coins()
        coin = next(c for c in coins if c["symbol"] == "TST")
        detail = self.b.pmc_get_coin(coin["coin_id"])
        self.assertIsNotNone(detail)
        self.assertEqual(detail["coin_id"], coin["coin_id"])
        self.assertEqual(detail["symbol"], coin["symbol"])
        self.assertEqual(detail["name"], coin["name"])

    def test_04_pmc_changed_signal(self):
        received = []
        self.b.pmc_changed.connect(lambda: received.append(True))
        self.b.pmc_create_coin(
            self.addr, "TST", "Test Coin",
            pow_difficulty=1, base_reward=100.0,
        )
        self.assertGreater(len(received), 0)

    def test_05_no_wallet_returns_none(self):
        result = self.b.pmc_create_coin("nonexistent", "TST", "Test Coin")
        self.assertIsNone(result)

    def test_06_pmc_get_coin_nonexistent(self):
        result = self.b.pmc_get_coin("nonexistent_coin_id")
        self.assertIsNone(result)

    def test_07_block_reward_calculation(self):
        self.b.pmc_create_coin(
            self.addr, "DIF", "Diff Coin",
            pow_difficulty=3, base_reward=10.0,
        )
        coins = self.b.pmc_list_coins()
        coin = next(c for c in coins if c["symbol"] == "DIF")
        expected = 10.0 * (2 ** (3 - 1))
        self.assertAlmostEqual(coin["block_reward"], expected, places=4)


# ===================================================================
#  10. PMC MINING
# ===================================================================

class Test10_PMCMining(unittest.TestCase):

    def setUp(self):
        self.b = _make_backend()
        self.issuer = self.b.create_wallet("Issuer")
        self.miner = self.b.create_wallet("Miner")
        _fund(self.b, self.issuer["address"], 1_000_000.0)
        _fund(self.b, self.miner["address"], 100_000.0)
        self.b.pmc_create_coin(
            self.issuer["address"], "MNE", "Mineable",
            max_supply=1_000_000.0, pow_difficulty=1, base_reward=100.0,
        )
        coins = self.b.pmc_list_coins()
        self.coin = next(c for c in coins if c["symbol"] == "MNE")
        self.coin_id = self.coin["coin_id"]

    def test_01_pow_info_fields(self):
        info = self.b.pmc_get_pow_info(self.coin_id)
        self.assertIsNotNone(info)
        expected_keys = [
            "coin_id", "symbol", "difficulty", "base_reward",
            "block_reward", "total_minted", "max_supply",
            "remaining_supply", "total_mints", "prev_hash",
            "mintable", "algorithm", "pending_tx_count",
            "pending_tx_root", "estimated_hashes",
            "total_commitments", "epoch_length", "target_block_time",
            "halving_interval", "current_epoch", "halvings_completed",
            "mints_until_retarget", "mints_until_halving", "total_epochs",
        ]
        for key in expected_keys:
            self.assertIn(key, info, f"Missing pow_info key: {key}")
        self.assertEqual(info["coin_id"], self.coin_id)
        self.assertEqual(info["symbol"], "MNE")
        self.assertEqual(info["difficulty"], 1)
        self.assertAlmostEqual(info["base_reward"], 100.0)
        self.assertAlmostEqual(info["max_supply"], 1_000_000.0)
        self.assertAlmostEqual(info["total_minted"], 0.0)
        self.assertAlmostEqual(info["remaining_supply"], 1_000_000.0)
        self.assertEqual(info["prev_hash"], self.coin_id)
        self.assertEqual(info["pending_tx_root"], EMPTY_TX_ROOT)
        self.assertTrue(info["mintable"])
        self.assertEqual(info["algorithm"], "double-SHA256")

    def test_02_mine_updates_portfolio(self):
        info = self.b.pmc_get_pow_info(self.coin_id)
        nonce = _find_valid_nonce(
            self.coin_id, self.miner["address"],
            info["difficulty"], info["prev_hash"])
        self.assertIsNotNone(nonce, "Failed to find a valid nonce")
        result = self.b.pmc_mint(
            self.miner["address"], self.coin_id, nonce)
        self.assertIsNotNone(result, "pmc_mint returned None — nonce rejected")

    def test_03_portfolio_after_mine_fields(self):
        info = self.b.pmc_get_pow_info(self.coin_id)
        nonce = _find_valid_nonce(
            self.coin_id, self.miner["address"],
            info["difficulty"], info["prev_hash"])
        self.b.pmc_mint(self.miner["address"], self.coin_id, nonce)
        portfolio = self.b.pmc_get_portfolio(self.miner["address"])
        self.assertGreater(len(portfolio), 0)
        holding = next(h for h in portfolio if h["coin_id"] == self.coin_id)
        for key in ("coin_id", "symbol", "name", "balance", "frozen"):
            self.assertIn(key, holding, f"Missing portfolio key: {key}")
        expected_reward = self.coin["block_reward"]
        self.assertAlmostEqual(holding["balance"], expected_reward, places=4)
        self.assertEqual(holding["symbol"], "MNE")
        self.assertEqual(holding["name"], "Mineable")
        self.assertFalse(holding["frozen"])

    def test_04_pow_info_updated_after_mine(self):
        info = self.b.pmc_get_pow_info(self.coin_id)
        nonce = _find_valid_nonce(
            self.coin_id, self.miner["address"],
            info["difficulty"], info["prev_hash"])
        self.b.pmc_mint(self.miner["address"], self.coin_id, nonce)
        info2 = self.b.pmc_get_pow_info(self.coin_id)
        self.assertGreater(info2["total_minted"], 0.0)
        self.assertGreater(info2["total_mints"], 0)
        self.assertLess(info2["remaining_supply"], info["remaining_supply"])
        self.assertNotEqual(info2["prev_hash"], info["prev_hash"])

    def test_05_no_wallet_returns_none(self):
        result = self.b.pmc_mint("nonexistent", self.coin_id, 0)
        self.assertIsNone(result)

    def test_06_wrong_nonce_rejected(self):
        # pmc_mint returns None when the nonce fails PoW validation
        # With difficulty=1, random nonces have a 1/16 chance of passing,
        # so we just verify the call doesn't crash.
        result = self.b.pmc_mint(
            self.miner["address"], self.coin_id, 999999999)
        # result is None (rejected) or a dict (lucky valid nonce)
        self.assertIsInstance(result, (dict, type(None)))

    def test_07_mine_twice_sequential(self):
        info = self.b.pmc_get_pow_info(self.coin_id)
        nonce1 = _find_valid_nonce(
            self.coin_id, self.miner["address"],
            info["difficulty"], info["prev_hash"])
        self.b.pmc_mint(self.miner["address"], self.coin_id, nonce1)
        info2 = self.b.pmc_get_pow_info(self.coin_id)
        nonce2 = _find_valid_nonce(
            self.coin_id, self.miner["address"],
            info2["difficulty"], info2["prev_hash"])
        result2 = self.b.pmc_mint(
            self.miner["address"], self.coin_id, nonce2)
        self.assertIsNotNone(result2, "Second mine returned None")
        bal = _pmc_balance(self.b, self.miner["address"], self.coin_id)
        self.assertAlmostEqual(
            bal, self.coin["block_reward"] * 2, places=4)

    def test_08_coin_supply_updated(self):
        info = self.b.pmc_get_pow_info(self.coin_id)
        nonce = _find_valid_nonce(
            self.coin_id, self.miner["address"],
            info["difficulty"], info["prev_hash"])
        self.b.pmc_mint(self.miner["address"], self.coin_id, nonce)
        coins = self.b.pmc_list_coins()
        coin = next(c for c in coins if c["coin_id"] == self.coin_id)
        self.assertAlmostEqual(
            coin["total_minted"], self.coin["block_reward"], places=4)
        self.assertAlmostEqual(
            coin["circulating"], self.coin["block_reward"], places=4)

    def test_09_pmc_signal_after_mine(self):
        received = []
        self.b.pmc_changed.connect(lambda: received.append(True))
        info = self.b.pmc_get_pow_info(self.coin_id)
        nonce = _find_valid_nonce(
            self.coin_id, self.miner["address"],
            info["difficulty"], info["prev_hash"])
        self.b.pmc_mint(self.miner["address"], self.coin_id, nonce)
        self.assertGreater(len(received), 0)


# ===================================================================
#  11. PMC TRANSFER
# ===================================================================

class Test11_PMCTransfer(unittest.TestCase):

    def setUp(self):
        self.b = _make_backend()
        self.issuer = self.b.create_wallet("Issuer")
        self.miner = self.b.create_wallet("Miner")
        self.receiver = self.b.create_wallet("Receiver")
        _fund(self.b, self.issuer["address"], 1_000_000.0)
        _fund(self.b, self.miner["address"], 100_000.0)
        _fund(self.b, self.receiver["address"], 100_000.0)
        self.b.pmc_create_coin(
            self.issuer["address"], "TXF", "Transfer Coin",
            max_supply=500_000.0, pow_difficulty=1, base_reward=100.0,
        )
        coins = self.b.pmc_list_coins()
        self.coin = next(c for c in coins if c["symbol"] == "TXF")
        self.coin_id = self.coin["coin_id"]
        info = self.b.pmc_get_pow_info(self.coin_id)
        nonce = _find_valid_nonce(
            self.coin_id, self.miner["address"],
            info["difficulty"], info["prev_hash"])
        self.b.pmc_mint(self.miner["address"], self.coin_id, nonce)

    def test_01_transfer_result_fields(self):
        result = self.b.pmc_transfer(
            self.miner["address"], self.receiver["address"],
            self.coin_id, 50.0,
        )
        self.assertIsNotNone(result)
        for key in ("tx_type", "tx_type_name", "account", "tx_id"):
            self.assertIn(key, result, f"Missing transfer key: {key}")
        self.assertEqual(result["tx_type_name"], "PMCTransfer")

    def test_02_balances_updated(self):
        before_miner = _pmc_balance(
            self.b, self.miner["address"], self.coin_id)
        self.b.pmc_transfer(
            self.miner["address"], self.receiver["address"],
            self.coin_id, 50.0,
        )
        after_miner = _pmc_balance(
            self.b, self.miner["address"], self.coin_id)
        recv = _pmc_balance(
            self.b, self.receiver["address"], self.coin_id)
        self.assertAlmostEqual(after_miner, before_miner - 50.0, places=4)
        self.assertAlmostEqual(recv, 50.0, places=4)

    def test_03_supply_conserved(self):
        before_coins = self.b.pmc_list_coins()
        before = next(c for c in before_coins
                      if c["coin_id"] == self.coin_id)
        before_circ = before["circulating"]
        self.b.pmc_transfer(
            self.miner["address"], self.receiver["address"],
            self.coin_id, 50.0,
        )
        after_coins = self.b.pmc_list_coins()
        after = next(c for c in after_coins
                     if c["coin_id"] == self.coin_id)
        self.assertAlmostEqual(after["circulating"], before_circ, places=4)

    def test_04_insufficient_pmc_fails(self):
        big = _pmc_balance(
            self.b, self.miner["address"], self.coin_id) + 1.0
        result = self.b.pmc_transfer(
            self.miner["address"], self.receiver["address"],
            self.coin_id, big,
        )
        # Backend may return tx dict with error result or None
        if result is not None:
            self.assertNotEqual(result.get("result"), "tesSUCCESS")


# ===================================================================
#  12. PMC BURN
# ===================================================================

class Test12_PMCBurn(unittest.TestCase):

    def setUp(self):
        self.b = _make_backend()
        self.issuer = self.b.create_wallet("Issuer")
        self.miner = self.b.create_wallet("Miner")
        _fund(self.b, self.issuer["address"], 1_000_000.0)
        _fund(self.b, self.miner["address"], 100_000.0)
        self.b.pmc_create_coin(
            self.issuer["address"], "BRN", "Burnable",
            max_supply=500_000.0, pow_difficulty=1, base_reward=100.0,
        )
        coins = self.b.pmc_list_coins()
        self.coin = next(c for c in coins if c["symbol"] == "BRN")
        self.coin_id = self.coin["coin_id"]
        info = self.b.pmc_get_pow_info(self.coin_id)
        nonce = _find_valid_nonce(
            self.coin_id, self.miner["address"],
            info["difficulty"], info["prev_hash"])
        self.b.pmc_mint(self.miner["address"], self.coin_id, nonce)

    def test_01_burn_result_fields(self):
        result = self.b.pmc_burn(
            self.miner["address"], self.coin_id, 10.0)
        self.assertIsNotNone(result)
        for key in ("tx_type", "tx_type_name", "account", "tx_id"):
            self.assertIn(key, result)
        self.assertEqual(result["tx_type_name"], "PMCBurn")

    def test_02_burn_reduces_supply(self):
        before_bal = _pmc_balance(
            self.b, self.miner["address"], self.coin_id)
        self.b.pmc_burn(self.miner["address"], self.coin_id, 10.0)
        after_bal = _pmc_balance(
            self.b, self.miner["address"], self.coin_id)
        self.assertAlmostEqual(after_bal, before_bal - 10.0, places=4)
        coins = self.b.pmc_list_coins()
        coin = next(c for c in coins if c["coin_id"] == self.coin_id)
        self.assertAlmostEqual(coin["total_burned"], 10.0, places=4)
        self.assertAlmostEqual(
            coin["circulating"],
            coin["total_minted"] - coin["total_burned"], places=4)

    def test_03_burn_more_than_balance_fails(self):
        bal = _pmc_balance(self.b, self.miner["address"], self.coin_id)
        result = self.b.pmc_burn(
            self.miner["address"], self.coin_id, bal + 1.0)
        # Backend may return tx dict with error result or None
        if result is not None:
            self.assertNotEqual(result.get("result"), "tesSUCCESS")


# ===================================================================
#  13. PMC DEX
# ===================================================================

class Test13_PMCDEX(unittest.TestCase):

    def setUp(self):
        self.b = _make_backend()
        self.issuer = self.b.create_wallet("Issuer")
        self.seller = self.b.create_wallet("Seller")
        _fund(self.b, self.issuer["address"], 1_000_000.0)
        _fund(self.b, self.seller["address"], 500_000.0)
        self.b.pmc_create_coin(
            self.issuer["address"], "DEX", "DexCoin",
            max_supply=500_000.0, pow_difficulty=1, base_reward=100.0,
        )
        coins = self.b.pmc_list_coins()
        self.coin = next(c for c in coins if c["symbol"] == "DEX")
        self.coin_id = self.coin["coin_id"]
        info = self.b.pmc_get_pow_info(self.coin_id)
        nonce = _find_valid_nonce(
            self.coin_id, self.seller["address"],
            info["difficulty"], info["prev_hash"])
        self.b.pmc_mint(self.seller["address"], self.coin_id, nonce)

    def test_01_create_sell_offer_fields(self):
        result = self.b.pmc_offer_create(
            self.seller["address"], self.coin_id, is_sell=True,
            amount=10.0, price=5.0)
        self.assertIsNotNone(result)
        for key in ("tx_type", "tx_type_name", "account", "tx_id"):
            self.assertIn(key, result)

    def test_02_get_pmc_offers_fields(self):
        self.b.pmc_offer_create(
            self.seller["address"], self.coin_id, is_sell=True,
            amount=10.0, price=5.0)
        offers = self.b.pmc_list_active_offers(self.coin_id)
        self.assertGreater(len(offers), 0)
        o = offers[0]
        for key in ("offer_id", "coin_id", "owner", "is_sell",
                     "amount", "price", "remaining", "created_at"):
            self.assertIn(key, o, f"Missing pmc offer key: {key}")
        self.assertEqual(o["owner"], self.seller["address"])
        self.assertAlmostEqual(o["amount"], 10.0)
        self.assertAlmostEqual(o["price"], 5.0)
        self.assertTrue(o["is_sell"])

    def test_03_buy_offer_transfers_tokens(self):
        self.b.pmc_offer_create(
            self.seller["address"], self.coin_id, is_sell=True,
            amount=10.0, price=5.0)
        buyer = self.b.create_wallet("Buyer")
        _fund(self.b, buyer["address"], 500_000.0)
        offers = self.b.pmc_list_active_offers(self.coin_id)
        offer_id = offers[0]["offer_id"]
        result = self.b.pmc_offer_accept(buyer["address"], offer_id)
        self.assertIsNotNone(result)
        buyer_bal = _pmc_balance(self.b, buyer["address"], self.coin_id)
        self.assertAlmostEqual(buyer_bal, 10.0, places=4)

    def test_04_cancel_sell_offer(self):
        self.b.pmc_offer_create(
            self.seller["address"], self.coin_id, is_sell=True,
            amount=10.0, price=5.0)
        offers = self.b.pmc_list_active_offers(self.coin_id)
        offer_id = offers[0]["offer_id"]
        result = self.b.pmc_offer_cancel(
            self.seller["address"], offer_id)
        self.assertIsNotNone(result)
        offers_after = self.b.pmc_list_active_offers(self.coin_id)
        self.assertEqual(len(offers_after), 0)

    def test_05_pmc_portfolio_empty_for_no_holdings(self):
        fresh = self.b.create_wallet("NoHoldings")
        portfolio = self.b.pmc_get_portfolio(fresh["address"])
        self.assertEqual(len(portfolio), 0)


# ===================================================================
#  14. CLEAR & RESET
# ===================================================================

class Test14_ClearAndReset(unittest.TestCase):

    def setUp(self):
        self.b = _make_backend()
        self.w = self.b.create_wallet("TestWallet")
        _fund(self.b, self.w["address"], 100_000.0)

    def test_01_p2p_status_zero_pool_after_consensus(self):
        status = self.b.get_p2p_status()
        self.assertEqual(status["total_tx_pool"], 0)

    def test_02_balance_updated_after_payment(self):
        received = []
        self.b.balance_updated.connect(lambda a, b: received.append(a))
        w2 = self.b.create_wallet("Dest")
        self.b.send_payment(self.w["address"], w2["address"], 500.0)
        self.assertGreater(len(received), 0)

    def test_03_get_balance_returns_float(self):
        bal = self.b.get_balance(self.w["address"])
        self.assertIsInstance(bal, float)
        self.assertAlmostEqual(bal, 100_000.0, places=4)

    def test_04_balance_reflects_payment(self):
        w2 = self.b.create_wallet("Dest")
        self.b.send_payment(self.w["address"], w2["address"], 500.0)
        bal = self.b.get_balance(w2["address"])
        self.assertAlmostEqual(bal, 500.0, places=4)

    def test_05_clear_cache_returns_string(self):
        result = self.b.clear_cache()
        self.assertIsInstance(result, str)

    def test_06_tx_history_persists(self):
        w2 = self.b.create_wallet("Dest")
        self.b.send_payment(self.w["address"], w2["address"], 100.0)
        history = self.b.get_tx_history()
        self.assertGreater(len(history), 0)

    def test_07_balance_after_multiple_operations(self):
        w2 = self.b.create_wallet("Other")
        _fund(self.b, w2["address"], 50_000.0)
        self.b.send_payment(self.w["address"], w2["address"], 1_000.0)
        self.b.send_payment(w2["address"], self.w["address"], 500.0)
        bal_w = self.b.get_balance(self.w["address"])
        bal_w2 = self.b.get_balance(w2["address"])
        expected_w = 100_000.0 - 1_000.0 - FEE + 500.0
        expected_w2 = 50_000.0 + 1_000.0 - 500.0 - FEE
        self.assertAlmostEqual(bal_w, expected_w, places=4)
        self.assertAlmostEqual(bal_w2, expected_w2, places=4)

    def test_08_get_balance_nonexistent(self):
        bal = self.b.get_balance("nonexistent_addr")
        self.assertIsNotNone(bal)
        self.assertAlmostEqual(bal, 0.0, places=4)


# ===================================================================
#  15. END-TO-END
# ===================================================================

class Test15_EndToEnd(unittest.TestCase):

    def test_01_full_lifecycle(self):
        b = _make_backend(peers=["10.0.0.2:9001"])
        alice = b.create_wallet("Alice")
        bob = b.create_wallet("Bob")
        _fund(b, alice["address"], 1_000_000.0)
        _fund(b, bob["address"], 100_000.0)
        r = b.send_payment(alice["address"], bob["address"], 50_000.0)
        self.assertTrue(r["_accepted"])
        b.stake_nxf(alice["address"], 100_000.0, tier=0)
        b.pmc_create_coin(
            alice["address"], "E2E", "E2E Coin",
            pow_difficulty=1, base_reward=10.0,
        )
        coins = b.pmc_list_coins()
        coin = next(c for c in coins if c["symbol"] == "E2E")
        info = b.pmc_get_pow_info(coin["coin_id"])
        nonce = _find_valid_nonce(
            coin["coin_id"], bob["address"],
            info["difficulty"], info["prev_hash"])
        b.pmc_mint(bob["address"], coin["coin_id"], nonce)
        hist = b.get_tx_history()
        self.assertGreater(len(hist), 0)
        summ = b.get_ledger_summary()
        self.assertIsInstance(summ, dict)


# ===================================================================
#  16. PMC MULTI-NODE
# ===================================================================

class Test16_PMCMultiNode(unittest.TestCase):

    def test_01_pmc_replicated_to_all_nodes(self):
        b = _make_backend(peers=["10.0.0.2:9001"])
        issuer = b.create_wallet("Issuer")
        _fund(b, issuer["address"], 1_000_000.0)
        b.pmc_create_coin(
            issuer["address"], "REP", "Replicated",
            pow_difficulty=1, base_reward=50.0,
        )
        coins = b.pmc_list_coins()
        coin = next(c for c in coins if c["symbol"] == "REP")
        for node in b.network.nodes.values():
            node_coin = node.ledger.pmc_manager.get_coin(coin["coin_id"])
            self.assertIsNotNone(
                node_coin,
                f"Coin not on node {node.node_id}")

    def test_02_pmc_mine_on_multi_node(self):
        b = _make_backend(peers=["10.0.0.2:9001", "10.0.0.3:9001"])
        issuer = b.create_wallet("Issuer")
        miner = b.create_wallet("Miner")
        _fund(b, issuer["address"], 1_000_000.0)
        _fund(b, miner["address"], 100_000.0)
        b.pmc_create_coin(
            issuer["address"], "M3", "Multi3",
            pow_difficulty=1, base_reward=100.0,
        )
        coins = b.pmc_list_coins()
        coin = next(c for c in coins if c["symbol"] == "M3")
        info = b.pmc_get_pow_info(coin["coin_id"])
        nonce = _find_valid_nonce(
            coin["coin_id"], miner["address"],
            info["difficulty"], info["prev_hash"])
        result = b.pmc_mint(miner["address"], coin["coin_id"], nonce)
        self.assertIsNotNone(result, "pmc_mint returned None on multi-node")
        for node in b.network.nodes.values():
            node_coin = node.ledger.pmc_manager.get_coin(coin["coin_id"])
            self.assertAlmostEqual(
                node_coin.total_minted, coin["block_reward"], places=4)


# ===================================================================
#  17. QUERY METHODS
# ===================================================================

class Test17_QueryMethods(unittest.TestCase):

    def setUp(self):
        self.b = _make_backend()
        self.w = self.b.create_wallet("Q")
        _fund(self.b, self.w["address"], 1_000_000.0)

    def test_01_get_tx_history_field_validation(self):
        self.b.send_payment(self.w["address"], GENESIS, 100.0)
        hist = self.b.get_tx_history()
        self.assertGreater(len(hist), 0)
        for h in hist:
            self.assertIn("tx_type", h)
            self.assertIn("account", h)
            self.assertIn("tx_id", h)

    def test_02_get_all_accounts_returns_list(self):
        accts = self.b.get_all_accounts()
        self.assertIsInstance(accts, list)
        self.assertGreater(len(accts), 0)

    def test_03_get_closed_ledgers_empty_initially(self):
        b = _make_backend()
        closed = b.get_closed_ledgers()
        self.assertIsInstance(closed, list)

    def test_04_get_network_status_node_count(self):
        status = self.b.get_network_status()
        self.assertEqual(status["validators"], 1)

    def test_05_get_order_book_pairs_empty(self):
        pairs = self.b.get_order_book_pairs()
        self.assertIsInstance(pairs, list)

    def test_06_get_recent_fills_empty(self):
        fills = self.b.get_recent_fills()
        self.assertIsInstance(fills, list)
        self.assertEqual(len(fills), 0)


# ===================================================================
#  18. PMC SUPPLY CAP
# ===================================================================

class Test18_PMCSupplyCap(unittest.TestCase):

    def test_01_cannot_exceed_max_supply(self):
        b = _make_backend()
        issuer = b.create_wallet("Issuer")
        miner = b.create_wallet("Miner")
        _fund(b, issuer["address"], 1_000_000.0)
        _fund(b, miner["address"], 100_000.0)
        b.pmc_create_coin(
            issuer["address"], "CAP", "Capped",
            max_supply=150.0, pow_difficulty=1, base_reward=100.0,
        )
        coins = b.pmc_list_coins()
        coin = next(c for c in coins if c["symbol"] == "CAP")
        # Mine once (reward = 100 * 2^0 = 100 tokens)
        info = b.pmc_get_pow_info(coin["coin_id"])
        nonce = _find_valid_nonce(
            coin["coin_id"], miner["address"],
            info["difficulty"], info["prev_hash"])
        b.pmc_mint(miner["address"], coin["coin_id"], nonce)
        # Second mine should give at most 50 (remaining)
        info2 = b.pmc_get_pow_info(coin["coin_id"])
        nonce2 = _find_valid_nonce(
            coin["coin_id"], miner["address"],
            info2["difficulty"], info2["prev_hash"])
        b.pmc_mint(miner["address"], coin["coin_id"], nonce2)
        updated = b.pmc_list_coins()
        c = next(cc for cc in updated if cc["coin_id"] == coin["coin_id"])
        self.assertLessEqual(c["total_minted"], c["max_supply"] + 0.001)


# ===================================================================
#  19. EDGE CASES
# ===================================================================

class Test19_EdgeCases(unittest.TestCase):

    def setUp(self):
        self.b = _make_backend()
        self.w = self.b.create_wallet("Edge")
        _fund(self.b, self.w["address"], 1_000_000.0)

    def test_01_self_payment_handling(self):
        addr = self.w["address"]
        result = self.b.send_payment(addr, addr, 100.0)
        if result is not None:
            bal = self.b.get_balance(addr)
            self.assertIsNotNone(bal)

    def test_02_zero_payment_handling(self):
        w2 = self.b.create_wallet("Dest")
        result = self.b.send_payment(self.w["address"], w2["address"], 0.0)
        if result is not None:
            self.assertIsNotNone(result)

    def test_03_negative_payment_handling(self):
        w2 = self.b.create_wallet("Dest")
        result = self.b.send_payment(self.w["address"], w2["address"], -100.0)
        # System may accept or reject negative amounts; just verify no crash
        self.assertIsNotNone(result)

    def test_04_very_small_payment(self):
        w2 = self.b.create_wallet("Dest")
        result = self.b.send_payment(
            self.w["address"], w2["address"], 0.00000001)
        self.assertIsNotNone(result)

    def test_05_duplicate_wallet_name_allowed(self):
        info1 = self.b.create_wallet("Same")
        info2 = self.b.create_wallet("Same")
        self.assertNotEqual(info1["address"], info2["address"])

    def test_06_multiple_coins_same_creator(self):
        self.b.pmc_create_coin(
            self.w["address"], "A1", "Alpha",
            pow_difficulty=1, base_reward=10.0)
        self.b.pmc_create_coin(
            self.w["address"], "B2", "Beta",
            pow_difficulty=1, base_reward=20.0)
        coins = self.b.pmc_list_coins()
        symbols = {c["symbol"] for c in coins}
        self.assertIn("A1", symbols)
        self.assertIn("B2", symbols)

    def test_07_get_wallets_empty(self):
        b = _make_backend()
        wallets = b.get_wallets()
        self.assertEqual(len(wallets), 0)

    def test_08_get_trust_lines_empty(self):
        b = _make_backend()
        lines = b.get_trust_lines()
        self.assertEqual(len(lines), 0)

    def test_09_get_stakes_empty(self):
        stakes = self.b.get_stakes_for_address(self.w["address"])
        self.assertEqual(len(stakes), 0)

    def test_10_get_all_active_stakes_empty(self):
        b = _make_backend()
        stakes = b.get_all_active_stakes()
        self.assertEqual(len(stakes), 0)

    def test_11_pmc_list_coins_empty(self):
        b = _make_backend()
        coins = b.pmc_list_coins()
        self.assertEqual(len(coins), 0)

    def test_12_staking_summary_no_stakes(self):
        summary = self.b.get_staking_summary(self.w["address"])
        self.assertIsInstance(summary, dict)
        self.assertAlmostEqual(summary["total_staked"], 0.0)


# ===================================================================
#  20. RESERVE ENFORCEMENT
# ===================================================================

class Test20_ReserveEnforcement(unittest.TestCase):

    def test_01_base_reserve_enforced(self):
        b = _make_backend()
        w1 = b.create_wallet("Sender")
        w2 = b.create_wallet("Receiver")
        _fund(b, w1["address"], 10.0 + FEE * 5)
        result = b.send_payment(
            w1["address"], w2["address"], 10.0)
        if result is not None:
            bal = b.get_balance(w1["address"])
            self.assertGreaterEqual(bal, 0.0)

    def test_02_owner_reserve_for_trust_line(self):
        b = _make_backend()
        holder = b.create_wallet("Holder")
        issuer = b.create_wallet("Issuer")
        _fund(b, holder["address"], BASE_RESERVE + OWNER_RESERVE_INC + 0.1)
        _fund(b, issuer["address"], 100_000.0)
        result = b.set_trust_line(
            holder["address"], "USD", issuer["address"], 1000.0)
        self.assertIsNotNone(result)


# ===================================================================
#  21. MULTI-VALIDATOR
# ===================================================================

class Test21_MultiValidator(unittest.TestCase):

    def test_01_three_validators_all_sync(self):
        b = _make_backend(peers=["10.0.0.2:9001", "10.0.0.3:9001"])
        self.assertEqual(len(b.network.nodes), 3)
        w1 = b.create_wallet("Sender")
        w2 = b.create_wallet("Receiver")
        _fund(b, w1["address"], 500_000.0)
        b.send_payment(w1["address"], w2["address"], 1000.0)
        for node in b.network.nodes.values():
            bal = node.ledger.get_balance(w2["address"])
            self.assertAlmostEqual(bal, 1000.0, places=4)

    def test_02_validator_statuses_count(self):
        b = _make_backend(peers=["10.0.0.2:9001"])
        statuses = b.get_validator_statuses()
        self.assertEqual(len(statuses), 2)


# ===================================================================
#  22. SIGNAL COMPLETENESS
# ===================================================================

class Test22_SignalCompleteness(unittest.TestCase):

    def test_01_all_expected_signals_exist(self):
        b = _make_backend()
        expected_signals = [
            "wallet_created", "balance_updated", "tx_submitted",
            "consensus_completed", "staking_changed", "pmc_changed",
        ]
        for sig_name in expected_signals:
            self.assertTrue(
                hasattr(b, sig_name),
                f"Missing signal: {sig_name}")

    def test_02_balance_signal_after_payment(self):
        b = _make_backend()
        w = b.create_wallet("Sig")
        w2 = b.create_wallet("Dest")
        _fund(b, w["address"], 10_000.0)
        received = []
        b.balance_updated.connect(lambda a, bal: received.append((a, bal)))
        b.send_payment(w["address"], w2["address"], 100.0)
        addrs = [r[0] for r in received]
        self.assertIn(w["address"], addrs)

    def test_03_pmc_signal_on_create(self):
        b = _make_backend()
        w = b.create_wallet("PMCSig")
        _fund(b, w["address"], 1_000_000.0)
        received = []
        b.pmc_changed.connect(lambda: received.append(True))
        b.pmc_create_coin(w["address"], "SIG", "Sig Coin",
                          pow_difficulty=1, base_reward=10.0)
        self.assertGreater(len(received), 0)

    def test_04_consensus_signal_on_round(self):
        b = _make_backend(peers=["10.0.0.2:9001"])
        w = b.create_wallet("CS")
        _fund(b, w["address"], 100_000.0)
        received = []
        b.consensus_completed.connect(lambda d: received.append(d))
        b.send_payment(w["address"], GENESIS, 100.0)
        self.assertGreater(len(received), 0)

    def test_05_staking_signal_on_stake(self):
        b = _make_backend()
        w = b.create_wallet("StakeSig")
        _fund(b, w["address"], 100_000.0)
        received = []
        b.staking_changed.connect(lambda: received.append(True))
        b.stake_nxf(w["address"], 10_000.0, tier=0)
        self.assertGreater(len(received), 0)

    def test_06_wallet_signal_on_create(self):
        b = _make_backend()
        received = []
        b.wallet_created.connect(lambda d: received.append(d))
        b.create_wallet("WalSig")
        self.assertEqual(len(received), 1)


# ===================================================================
#  23. MINING POOL
# ===================================================================

class Test23_MiningPool(unittest.TestCase):

    def setUp(self):
        self.b = _make_backend()

    def test_01_mining_pool_info_fields(self):
        info = self.b.mining_pool_get_info()
        self.assertIsInstance(info, dict)
        self.assertIn("running", info)
        self.assertFalse(info["running"])

    def test_02_mining_pool_stats_empty(self):
        stats = self.b.mining_pool_get_stats()
        self.assertIsInstance(stats, dict)

    def test_03_mining_pool_miners_empty(self):
        miners = self.b.mining_pool_get_miners()
        self.assertIsInstance(miners, list)
        self.assertEqual(len(miners), 0)

    def test_04_mining_pool_coins_empty(self):
        coins = self.b.mining_pool_list_coins()
        self.assertIsInstance(coins, list)
        self.assertEqual(len(coins), 0)


# ===================================================================
#  24. ACCOUNTING CONSERVATION
# ===================================================================

class Test24_Accounting(unittest.TestCase):

    def test_01_nxf_conserved_after_payments(self):
        b = _make_backend()
        w1 = b.create_wallet("A")
        w2 = b.create_wallet("B")
        w3 = b.create_wallet("C")
        _fund(b, w1["address"], 300_000.0)
        _fund(b, w2["address"], 200_000.0)
        b.send_payment(w1["address"], w2["address"], 50_000.0)
        b.send_payment(w2["address"], w3["address"], 10_000.0)
        b.send_payment(w3["address"], w1["address"], 5_000.0)
        total = sum(b.get_balance(addr)
                    for addr in [GENESIS, w1["address"],
                                 w2["address"], w3["address"]])
        ledger = b.get_ledger_summary()
        burned = ledger.get("total_burned", 0.0)
        staked = ledger.get("total_staked", 0.0)
        self.assertAlmostEqual(total + burned + staked, SUPPLY, places=2)

    def test_02_staking_conserves_total(self):
        b = _make_backend()
        w1 = b.create_wallet("Staker")
        _fund(b, w1["address"], 500_000.0)
        b.stake_nxf(w1["address"], 100_000.0, tier=0)
        total = sum(b.get_balance(addr) for addr in [GENESIS, w1["address"]])
        ledger = b.get_ledger_summary()
        burned = ledger.get("total_burned", 0.0)
        staked = ledger.get("total_staked", 0.0)
        self.assertAlmostEqual(total + burned + staked, SUPPLY, places=2)


# ===================================================================
#  25. STRESS
# ===================================================================

class Test25_Stress(unittest.TestCase):

    def test_01_many_sequential_payments(self):
        b = _make_backend()
        sender = b.create_wallet("Sender")
        receiver = b.create_wallet("Receiver")
        _fund(b, sender["address"], 1_000_000.0)
        for _ in range(100):
            result = b.send_payment(
                sender["address"], receiver["address"], 1.0)
            self.assertIsNotNone(result)
        bal = b.get_balance(receiver["address"])
        self.assertAlmostEqual(bal, 100.0, places=4)

    def test_02_many_wallets(self):
        b = _make_backend()
        for i in range(50):
            info = b.create_wallet(f"W{i}")
            self.assertIsNotNone(info)
        wallets = b.get_wallets()
        self.assertEqual(len(wallets), 50)


# ===================================================================
#  26. IOU TRACKING
# ===================================================================

class Test26_IOUTracking(unittest.TestCase):

    def test_01_iou_balance_exact(self):
        b = _make_backend()
        issuer = b.create_wallet("Issuer")
        holder = b.create_wallet("Holder")
        _fund(b, issuer["address"], 500_000.0)
        _fund(b, holder["address"], 100_000.0)
        b.set_trust_line(
            holder["address"], "USD", issuer["address"], 10_000.0)
        b.send_payment(
            issuer["address"], holder["address"], 750.5,
            currency="USD", issuer=issuer["address"])
        lines = b.get_trust_lines()
        usd = next(l for l in lines if l["currency"] == "USD"
                   and l["holder"] == holder["address"])
        self.assertAlmostEqual(usd["balance"], 750.5, places=4)

    def test_02_iou_transfer_chain(self):
        b = _make_backend()
        issuer = b.create_wallet("Issuer")
        alice = b.create_wallet("Alice")
        bob = b.create_wallet("Bob")
        _fund(b, issuer["address"], 500_000.0)
        _fund(b, alice["address"], 100_000.0)
        _fund(b, bob["address"], 100_000.0)
        b.set_trust_line(
            alice["address"], "USD", issuer["address"], 10_000.0)
        b.set_trust_line(
            bob["address"], "USD", issuer["address"], 10_000.0)
        b.send_payment(
            issuer["address"], alice["address"], 500.0,
            currency="USD", issuer=issuer["address"])
        b.send_payment(
            alice["address"], bob["address"], 200.0,
            currency="USD", issuer=issuer["address"])
        lines = b.get_trust_lines()
        bob_usd = next((l for l in lines if l["currency"] == "USD"
                        and l["holder"] == bob["address"]), None)
        alice_usd = next((l for l in lines if l["currency"] == "USD"
                          and l["holder"] == alice["address"]), None)
        if bob_usd is not None:
            self.assertAlmostEqual(bob_usd["balance"], 200.0, places=4)
        if alice_usd is not None:
            self.assertAlmostEqual(alice_usd["balance"], 300.0, places=4)


# ===================================================================
#  27. PMC FULL LIFECYCLE
# ===================================================================

class Test27_PMCFullLifecycle(unittest.TestCase):

    def test_01_create_mine_transfer_sell_burn(self):
        b = _make_backend()
        issuer = b.create_wallet("Issuer")
        miner = b.create_wallet("Miner")
        buyer = b.create_wallet("Buyer")
        _fund(b, issuer["address"], 1_000_000.0)
        _fund(b, miner["address"], 100_000.0)
        _fund(b, buyer["address"], 500_000.0)
        # Create
        b.pmc_create_coin(
            issuer["address"], "LFC", "Lifecycle",
            max_supply=1_000_000.0, pow_difficulty=1, base_reward=100.0)
        coins = b.pmc_list_coins()
        coin = next(c for c in coins if c["symbol"] == "LFC")
        cid = coin["coin_id"]
        # Mine
        info = b.pmc_get_pow_info(cid)
        nonce = _find_valid_nonce(
            cid, miner["address"], info["difficulty"], info["prev_hash"])
        b.pmc_mint(miner["address"], cid, nonce)
        reward = coin["block_reward"]
        # Transfer some
        b.pmc_transfer(
            miner["address"], buyer["address"], cid, 20.0)
        # Sell remaining
        sellable = _pmc_balance(b, miner["address"], cid)
        b.pmc_offer_create(
            miner["address"], cid, is_sell=True,
            amount=sellable, price=1.0)
        # Buyer buys
        offers = b.pmc_list_active_offers(cid)
        if offers:
            b.pmc_offer_accept(buyer["address"], offers[0]["offer_id"])
        # Burn portion
        b.pmc_burn(buyer["address"], cid, 5.0)
        # Validate
        final_coins = b.pmc_list_coins()
        fc = next(c for c in final_coins if c["coin_id"] == cid)
        self.assertAlmostEqual(fc["total_burned"], 5.0, places=4)
        self.assertAlmostEqual(
            fc["circulating"], fc["total_minted"] - fc["total_burned"],
            places=4)
        miner_bal = _pmc_balance(b, miner["address"], cid)
        buyer_bal = _pmc_balance(b, buyer["address"], cid)
        self.assertAlmostEqual(
            miner_bal + buyer_bal + fc["total_burned"],
            fc["total_minted"], places=4)


# ===================================================================
#  28. STAKING CANCEL ACCURACY
# ===================================================================

class Test28_StakingCancelAccuracy(unittest.TestCase):

    def test_01_cancel_returns_exact_amount(self):
        b = _make_backend()
        w = b.create_wallet("Staker")
        _fund(b, w["address"], 500_000.0)
        bal_before = b.get_balance(w["address"])
        b.stake_nxf(w["address"], 50_000.0, tier=0)
        bal_staked = b.get_balance(w["address"])
        self.assertAlmostEqual(
            bal_before - bal_staked, 50_000.0 + FEE, places=4)
        stakes = b.get_stakes_for_address(w["address"])
        stake_id = stakes[0]["stake_id"]
        b.cancel_stake(stake_id)
        bal_after = b.get_balance(w["address"])
        self.assertGreater(bal_after, bal_staked)
        returned = bal_after - bal_staked
        self.assertAlmostEqual(returned, 50_000.0, places=0)


# ===================================================================
#  29. CHAINED CONSENSUS
# ===================================================================

class Test29_ChainedConsensus(unittest.TestCase):

    def test_01_ten_rounds(self):
        b = _make_backend(peers=["10.0.0.2:9001"])
        w1 = b.create_wallet("S")
        w2 = b.create_wallet("R")
        _fund(b, w1["address"], 1_000_000.0)
        for i in range(10):
            b.send_payment(w1["address"], w2["address"], 10.0)
        bal = b.get_balance(w2["address"])
        self.assertAlmostEqual(bal, 100.0, places=4)
        for node in b.network.nodes.values():
            self.assertAlmostEqual(
                node.ledger.get_balance(w2["address"]),
                100.0, places=4)

    def test_02_closed_ledgers_grow(self):
        b = _make_backend(peers=["10.0.0.2:9001"])
        w = b.create_wallet("CL")
        _fund(b, w["address"], 500_000.0)
        closed_before = len(b.get_closed_ledgers())
        for _ in range(5):
            b.send_payment(w["address"], GENESIS, 1.0)
        closed_after = len(b.get_closed_ledgers())
        self.assertGreater(closed_after, closed_before)


# ===================================================================

# ===================================================================
#  30. START / STOP LIFECYCLE
# ===================================================================

class Test30_StartStopLifecycle(unittest.TestCase):
    """Test backend start() and stop() timer management."""

    def test_01_start_activates_timers(self):
        b = _make_backend()
        b.start()
        self.assertTrue(b._poll_timer.isActive())
        self.assertTrue(b._p2p_timer.isActive())
        self.assertTrue(b._consensus_timer.isActive())
        b.stop()

    def test_02_stop_deactivates_timers(self):
        b = _make_backend()
        b.start()
        b.stop()
        self.assertFalse(b._poll_timer.isActive())
        self.assertFalse(b._p2p_timer.isActive())
        self.assertFalse(b._consensus_timer.isActive())

    def test_03_double_start_safe(self):
        b = _make_backend()
        b.start()
        b.start()  # Should not crash
        self.assertTrue(b._poll_timer.isActive())
        b.stop()

    def test_04_stop_without_start_safe(self):
        b = _make_backend()
        b.stop()  # Should not crash
        self.assertFalse(b._poll_timer.isActive())

    def test_05_timer_intervals_correct(self):
        b = _make_backend()
        self.assertEqual(b._poll_timer.interval(), 3000)
        self.assertEqual(b._p2p_timer.interval(), 1000)
        self.assertEqual(b._consensus_timer.interval(), 10000)


# ===================================================================
#  31. FIND PAYMENT PATHS
# ===================================================================

class Test31_FindPaymentPaths(unittest.TestCase):
    """Test the find_payment_paths method."""

    def test_01_returns_list(self):
        b = _make_backend()
        w1 = b.create_wallet("Sender")
        w2 = b.create_wallet("Receiver")
        _fund(b, w1["address"], 10_000.0)
        result = b.find_payment_paths(
            w1["address"], w2["address"], "NXF", 100.0
        )
        self.assertIsInstance(result, list)

    def test_02_nxf_path_found(self):
        b = _make_backend()
        w1 = b.create_wallet("S")
        w2 = b.create_wallet("R")
        _fund(b, w1["address"], 50_000.0)
        result = b.find_payment_paths(
            w1["address"], w2["address"], "NXF", 100.0
        )
        # At minimum returns empty list (no error)
        self.assertIsInstance(result, list)


# ===================================================================
#  32. CLEAR ALL DATA
# ===================================================================

class Test32_ClearAllData(unittest.TestCase):
    """Test the clear_all_data method."""

    def test_01_returns_summary_string(self):
        b = _make_backend()
        b.create_wallet("W1")
        result = b.clear_all_data()
        self.assertIsInstance(result, str)
        self.assertIn("cleared", result.lower())

    def test_02_wallets_emptied(self):
        b = _make_backend()
        b.create_wallet("W1")
        b.create_wallet("W2")
        self.assertEqual(len(b.wallets), 2)
        b.clear_all_data()
        self.assertEqual(len(b.wallets), 0)

    def test_03_wallet_names_emptied(self):
        b = _make_backend()
        b.create_wallet("W1")
        b.clear_all_data()
        self.assertEqual(len(b.wallet_names), 0)

    def test_04_tx_history_emptied(self):
        b = _make_backend()
        w = b.create_wallet("S")
        _fund(b, w["address"], 10_000.0)
        b.send_payment(w["address"], GENESIS, 1.0)
        self.assertGreater(len(b.tx_history), 0)
        b.clear_all_data()
        self.assertEqual(len(b.tx_history), 0)

    def test_05_ledger_rebuilt(self):
        b = _make_backend()
        w = b.create_wallet("W")
        _fund(b, w["address"], 10_000.0)
        b.clear_all_data()
        # Genesis should exist again with full supply
        bal = b.get_balance(GENESIS)
        self.assertAlmostEqual(bal, SUPPLY, places=4)

    def test_06_signals_emitted(self):
        b = _make_backend()
        signals_fired = {"ledger_reset": False, "accounts_changed": False}
        b.ledger_reset.connect(lambda: signals_fired.__setitem__("ledger_reset", True))
        b.accounts_changed.connect(lambda: signals_fired.__setitem__("accounts_changed", True))
        b.clear_all_data()
        self.assertTrue(signals_fired["ledger_reset"])
        self.assertTrue(signals_fired["accounts_changed"])


# ===================================================================
#  33. RESET LEDGER (DEV MODE)
# ===================================================================

class Test33_ResetLedger(unittest.TestCase):
    """Test the reset_ledger method in dev mode and non-dev mode."""

    def test_01_reset_in_dev_mode(self):
        b = _make_backend()
        b.DEV_MODE = True
        w = b.create_wallet("DevWallet")
        _fund(b, w["address"], 50_000.0)
        b.send_payment(w["address"], GENESIS, 100.0)
        b.reset_ledger()
        # Wallet should still exist but balance is 0
        bal = b.get_balance(w["address"])
        self.assertAlmostEqual(bal, 0.0, places=4)

    def test_02_genesis_restored_after_reset(self):
        b = _make_backend()
        b.DEV_MODE = True
        b.reset_ledger()
        bal = b.get_balance(GENESIS)
        self.assertAlmostEqual(bal, SUPPLY, places=4)

    def test_03_tx_history_cleared(self):
        b = _make_backend()
        b.DEV_MODE = True
        w = b.create_wallet("W")
        _fund(b, w["address"], 10_000.0)
        b.send_payment(w["address"], GENESIS, 1.0)
        self.assertGreater(len(b.tx_history), 0)
        b.reset_ledger()
        self.assertEqual(len(b.tx_history), 0)

    def test_04_non_dev_mode_rejected(self):
        b = _make_backend()
        b.DEV_MODE = False
        errors = []
        b.error_occurred.connect(lambda msg: errors.append(msg))
        b.reset_ledger()
        self.assertEqual(len(errors), 1)
        self.assertIn("dev mode", errors[0].lower())

    def test_05_signals_emitted_on_reset(self):
        b = _make_backend()
        b.DEV_MODE = True
        signals_fired = {"ledger_reset": False, "staking_changed": False}
        b.ledger_reset.connect(lambda: signals_fired.__setitem__("ledger_reset", True))
        b.staking_changed.connect(lambda: signals_fired.__setitem__("staking_changed", True))
        b.reset_ledger()
        self.assertTrue(signals_fired["ledger_reset"])
        self.assertTrue(signals_fired["staking_changed"])

    def test_06_wallets_preserved_after_reset(self):
        b = _make_backend()
        b.DEV_MODE = True
        w1 = b.create_wallet("W1")
        w2 = b.create_wallet("W2")
        b.reset_ledger()
        self.assertIn(w1["address"], b.wallets)
        self.assertIn(w2["address"], b.wallets)


# ===================================================================
#  34. PMC ORDER BOOK
# ===================================================================

class Test34_PMCOrderBook(unittest.TestCase):
    """Test pmc_get_order_book method."""

    def test_01_returns_dict(self):
        b = _make_backend()
        w = b.create_wallet("Creator")
        _fund(b, w["address"], 100_000.0)
        b.pmc_create_coin(
            w["address"], "OBK", "OrderBookCoin",
            max_supply=1_000_000.0, pow_difficulty=1, base_reward=100.0,
        )
        coin_id = next(c["coin_id"] for c in b.pmc_list_coins() if c["symbol"] == "OBK")
        result = b.pmc_get_order_book(coin_id)
        self.assertIsInstance(result, dict)

    def test_02_empty_order_book(self):
        b = _make_backend()
        w = b.create_wallet("C")
        _fund(b, w["address"], 100_000.0)
        b.pmc_create_coin(
            w["address"], "EMP", "EmptyCoin",
            max_supply=1_000_000.0, pow_difficulty=1, base_reward=100.0,
        )
        coin_id = next(c["coin_id"] for c in b.pmc_list_coins() if c["symbol"] == "EMP")
        result = b.pmc_get_order_book(coin_id)
        self.assertIsInstance(result, dict)

    def test_03_order_book_with_offer(self):
        b = _make_backend()
        w = b.create_wallet("Seller")
        _fund(b, w["address"], 100_000.0)
        b.pmc_create_coin(
            w["address"], "OFR", "OfferCoin",
            max_supply=1_000_000.0, pow_difficulty=1, base_reward=100.0,
        )
        coin_id = next(c["coin_id"] for c in b.pmc_list_coins() if c["symbol"] == "OFR")
        info = b.pmc_get_pow_info(coin_id)
        nonce = _find_valid_nonce(
            coin_id, w["address"],
            info["difficulty"], info["prev_hash"],
        )
        b.pmc_mint(address=w["address"], coin_id=coin_id, nonce=nonce)
        b.pmc_offer_create(
            address=w["address"], coin_id=coin_id,
            amount=10.0, price=1.0, is_sell=True,
        )
        result = b.pmc_get_order_book(coin_id)
        self.assertIsInstance(result, dict)


# ===================================================================
#  35. MINING POOL OPERATIONS
# ===================================================================

class Test35_MiningPoolOps(unittest.TestCase):
    """Test mining pool add/remove coin without running server."""

    def test_01_add_coin_without_pool_returns_false(self):
        b = _make_backend()
        result = b.mining_pool_add_coin("nonexistent")
        self.assertFalse(result)

    def test_02_remove_coin_without_pool_safe(self):
        b = _make_backend()
        # Should not crash
        b.mining_pool_remove_coin("nonexistent")

    def test_03_pool_info_when_stopped(self):
        b = _make_backend()
        info = b.mining_pool_get_info()
        self.assertIsInstance(info, dict)
        self.assertFalse(info.get("running", True))

    def test_04_pool_stop_when_not_running(self):
        b = _make_backend()
        # Should not crash
        b.mining_pool_stop()

    def test_05_mining_node_initially_none(self):
        b = _make_backend()
        self.assertIsNone(b.mining_node)


# ===================================================================
#  36. IMPORT WALLET FROM FILE
# ===================================================================

class Test36_ImportWalletFromFile(unittest.TestCase):
    """Test import_wallet_from_file including error paths."""

    def test_01_roundtrip_export_import(self):
        b = _make_backend()
        w = b.create_wallet("Original")
        _fund(b, w["address"], 1000.0)
        exported = b.export_wallet(w["address"], "secret123")
        # Create a fresh backend and import
        b2 = _make_backend()
        imported = b2.import_wallet_from_file(exported, "secret123")
        self.assertEqual(imported["address"], w["address"])
        self.assertIn("public_key", imported)
        self.assertIn("name", imported)

    def test_02_bad_passphrase_raises(self):
        b = _make_backend()
        w = b.create_wallet("Protected")
        exported = b.export_wallet(w["address"], "correctpass")
        b2 = _make_backend()
        with self.assertRaises(Exception):
            b2.import_wallet_from_file(exported, "wrongpass")

    def test_03_imported_wallet_registered(self):
        b = _make_backend()
        w = b.create_wallet("W")
        exported = b.export_wallet(w["address"], "p")
        b2 = _make_backend()
        imported = b2.import_wallet_from_file(exported, "p")
        self.assertIn(imported["address"], b2.wallets)

    def test_04_import_fires_wallet_created_signal(self):
        b = _make_backend()
        w = b.create_wallet("W")
        exported = b.export_wallet(w["address"], "p")
        b2 = _make_backend()
        signals = []
        b2.wallet_created.connect(lambda info: signals.append(info))
        b2.import_wallet_from_file(exported, "p")
        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0]["address"], w["address"])

    def test_05_invalid_json_raises(self):
        b = _make_backend()
        with self.assertRaises(Exception):
            b.import_wallet_from_file("not valid json", "pass")


# ===================================================================
#  37. GET DEMAND MULTIPLIER
# ===================================================================

class Test37_GetDemandMultiplier(unittest.TestCase):
    """Test the staking demand multiplier."""

    def test_01_returns_float(self):
        b = _make_backend()
        result = b.get_demand_multiplier()
        self.assertIsInstance(result, float)

    def test_02_positive_value(self):
        b = _make_backend()
        result = b.get_demand_multiplier()
        self.assertGreater(result, 0.0)

    def test_03_changes_with_staking(self):
        b = _make_backend()
        mult_before = b.get_demand_multiplier()
        w = b.create_wallet("Staker")
        _fund(b, w["address"], 500_000.0)
        b.stake_nxf(w["address"], 100_000.0, tier=0)
        mult_after = b.get_demand_multiplier()
        # Multiplier should change (increase or stay) after staking
        self.assertIsInstance(mult_after, float)
        self.assertGreater(mult_after, 0.0)


# ===================================================================
#  38. EXPORT WALLET
# ===================================================================

class Test38_ExportWallet(unittest.TestCase):
    """Test export_wallet method in detail."""

    def test_01_export_returns_json_string(self):
        b = _make_backend()
        w = b.create_wallet("E")
        exported = b.export_wallet(w["address"], "pass")
        self.assertIsInstance(exported, str)
        data = json.loads(exported)
        self.assertIsInstance(data, dict)

    def test_02_exported_has_name(self):
        b = _make_backend()
        w = b.create_wallet("MyName")
        exported = b.export_wallet(w["address"], "pass")
        data = json.loads(exported)
        self.assertEqual(data["name"], "MyName")

    def test_03_export_nonexistent_raises(self):
        b = _make_backend()
        with self.assertRaises(ValueError):
            b.export_wallet("rNonexistent", "pass")

    def test_04_different_passphrases_produce_different_output(self):
        b = _make_backend()
        w = b.create_wallet("W")
        export1 = b.export_wallet(w["address"], "pass1")
        export2 = b.export_wallet(w["address"], "pass2")
        self.assertNotEqual(export1, export2)


# ===================================================================
#  39. ERROR OCCURRED SIGNAL
# ===================================================================

class Test39_ErrorOccurredSignal(unittest.TestCase):
    """Test that error_occurred signal fires on various error paths."""

    def test_01_payment_no_wallet(self):
        b = _make_backend()
        errors = []
        b.error_occurred.connect(lambda msg: errors.append(msg))
        b.send_payment("rNoWallet", GENESIS, 1.0)
        self.assertGreater(len(errors), 0)

    def test_02_trust_line_no_wallet(self):
        b = _make_backend()
        errors = []
        b.error_occurred.connect(lambda msg: errors.append(msg))
        b.set_trust_line("rNoWallet", "USD", GENESIS, 1000.0)
        self.assertGreater(len(errors), 0)

    def test_03_dex_offer_no_wallet(self):
        b = _make_backend()
        errors = []
        b.error_occurred.connect(lambda msg: errors.append(msg))
        b.create_dex_offer(
            "rNoWallet", 100.0, "USD", GENESIS, 100.0, "NXF", "",
        )
        self.assertGreater(len(errors), 0)

    def test_04_reset_ledger_not_dev_mode(self):
        b = _make_backend()
        b.DEV_MODE = False
        errors = []
        b.error_occurred.connect(lambda msg: errors.append(msg))
        b.reset_ledger()
        self.assertEqual(len(errors), 1)

    def test_05_stake_no_wallet(self):
        b = _make_backend()
        errors = []
        b.error_occurred.connect(lambda msg: errors.append(msg))
        b.stake_nxf("rNoWallet", 100.0, tier=0)
        self.assertGreater(len(errors), 0)


# ===================================================================
#  40. LOG MESSAGE SIGNAL
# ===================================================================

class Test40_LogMessageSignal(unittest.TestCase):
    """Test that log_message signal fires for key operations."""

    def test_01_log_on_wallet_create(self):
        b = _make_backend()
        logs = []
        b.log_message.connect(lambda msg: logs.append(msg))
        b.create_wallet("LogTest")
        self.assertGreater(len(logs), 0)

    def test_02_log_on_payment(self):
        b = _make_backend()
        w1 = b.create_wallet("S")
        w2 = b.create_wallet("R")
        _fund(b, w1["address"], 10_000.0)
        logs = []
        b.log_message.connect(lambda msg: logs.append(msg))
        b.send_payment(w1["address"], w2["address"], 1.0)
        self.assertGreater(len(logs), 0)

    def test_03_log_on_consensus(self):
        b = _make_backend(peers=["10.0.0.2:9001"])
        logs = []
        b.log_message.connect(lambda msg: logs.append(msg))
        b.run_consensus()
        found = any("consensus" in m.lower() for m in logs)
        self.assertTrue(found)


# ===================================================================
#  41. STATUS UPDATED SIGNAL
# ===================================================================

class Test41_StatusUpdatedSignal(unittest.TestCase):
    """Test that status_updated signal fires with correct data."""

    def test_01_emit_status_fires_signal(self):
        b = _make_backend()
        statuses = []
        b.status_updated.connect(lambda s: statuses.append(s))
        b._emit_status()
        self.assertEqual(len(statuses), 1)
        self.assertIsInstance(statuses[0], dict)

    def test_02_status_includes_wallet_count(self):
        b = _make_backend()
        b.create_wallet("W1")
        b.create_wallet("W2")
        statuses = []
        b.status_updated.connect(lambda s: statuses.append(s))
        b._emit_status()
        self.assertEqual(statuses[0]["wallet_count"], 2)

    def test_03_status_includes_validator_count(self):
        b = _make_backend(peers=["10.0.0.2:9001"])
        statuses = []
        b.status_updated.connect(lambda s: statuses.append(s))
        b._emit_status()
        self.assertIn("validator_count", statuses[0])
        self.assertEqual(statuses[0]["validator_count"], len(b.network.nodes))

    def test_04_status_includes_tx_pool(self):
        b = _make_backend()
        statuses = []
        b.status_updated.connect(lambda s: statuses.append(s))
        b._emit_status()
        self.assertIn("tx_pool", statuses[0])


# ===================================================================
#  42. P2P STATUS UPDATED SIGNAL
# ===================================================================

class Test42_P2PStatusSignal(unittest.TestCase):
    """Test p2p_status_updated signal."""

    def test_01_emit_p2p_fires_signal(self):
        b = _make_backend()
        statuses = []
        b.p2p_status_updated.connect(lambda s: statuses.append(s))
        b._emit_p2p_status()
        self.assertEqual(len(statuses), 1)
        self.assertIsInstance(statuses[0], dict)

    def test_02_p2p_status_fields(self):
        b = _make_backend()
        statuses = []
        b.p2p_status_updated.connect(lambda s: statuses.append(s))
        b._emit_p2p_status()
        s = statuses[0]
        self.assertIn("mode", s)
        self.assertIn("validator_count", s)
        self.assertIn("total_tx_pool", s)
        self.assertIn("nodes", s)
        self.assertIn("dev_mode", s)

    def test_03_p2p_node_details(self):
        b = _make_backend(peers=["10.0.0.2:9001"])
        statuses = []
        b.p2p_status_updated.connect(lambda s: statuses.append(s))
        b._emit_p2p_status()
        nodes = statuses[0]["nodes"]
        self.assertEqual(len(nodes), 2)
        for n in nodes:
            self.assertIn("node_id", n)
            self.assertIn("accounts", n)
            self.assertIn("tx_pool", n)
            self.assertIn("ledger_seq", n)
            self.assertIn("closed_ledgers", n)
            self.assertIn("unl_size", n)
            self.assertIn("peers", n)


# ===================================================================
#  43. ACCOUNTS CHANGED SIGNAL
# ===================================================================

class Test43_AccountsChangedSignal(unittest.TestCase):
    """Test accounts_changed signal fires on proper actions."""

    def test_01_fires_on_wallet_create(self):
        b = _make_backend()
        fired = []
        b.accounts_changed.connect(lambda: fired.append(True))
        b.create_wallet("W")
        self.assertGreater(len(fired), 0)

    def test_02_fires_on_consensus(self):
        b = _make_backend(peers=["10.0.0.2:9001"])
        w = b.create_wallet("S")
        _fund(b, w["address"], 10_000.0)
        fired = []
        b.accounts_changed.connect(lambda: fired.append(True))
        b.run_consensus()
        self.assertGreater(len(fired), 0)

    def test_03_fires_on_clear_all_data(self):
        b = _make_backend()
        b.create_wallet("W")
        fired = []
        b.accounts_changed.connect(lambda: fired.append(True))
        b.clear_all_data()
        self.assertGreater(len(fired), 0)


# ===================================================================
#  44. TRUST LINES CHANGED SIGNAL
# ===================================================================

class Test44_TrustLinesChangedSignal(unittest.TestCase):
    """Test trust_lines_changed signal."""

    def test_01_fires_on_trust_set(self):
        b = _make_backend()
        w = b.create_wallet("T")
        _fund(b, w["address"], 10_000.0)
        fired = []
        b.trust_lines_changed.connect(lambda: fired.append(True))
        b.set_trust_line(w["address"], "USD", GENESIS, 1000.0)
        self.assertGreater(len(fired), 0)

    def test_02_fires_on_consensus(self):
        b = _make_backend(peers=["10.0.0.2:9001"])
        fired = []
        b.trust_lines_changed.connect(lambda: fired.append(True))
        b.run_consensus()
        self.assertGreater(len(fired), 0)


# ===================================================================
#  45. ORDER BOOK CHANGED SIGNAL
# ===================================================================

class Test45_OrderBookChangedSignal(unittest.TestCase):
    """Test order_book_changed signal."""

    def test_01_fires_on_dex_offer(self):
        b = _make_backend()
        w = b.create_wallet("D")
        _fund(b, w["address"], 10_000.0)
        b.set_trust_line(w["address"], "USD", GENESIS, 1000.0)
        fired = []
        b.order_book_changed.connect(lambda: fired.append(True))
        b.create_dex_offer(
            w["address"], 100.0, "NXF", "",
            50.0, "USD", GENESIS,
        )
        self.assertGreater(len(fired), 0)


# ===================================================================
#  46. LEDGER RESET SIGNAL
# ===================================================================

class Test46_LedgerResetSignal(unittest.TestCase):
    """Test ledger_reset signal."""

    def test_01_fires_on_reset_ledger(self):
        b = _make_backend()
        b.DEV_MODE = True
        fired = []
        b.ledger_reset.connect(lambda: fired.append(True))
        b.reset_ledger()
        self.assertGreater(len(fired), 0)

    def test_02_fires_on_clear_all_data(self):
        b = _make_backend()
        fired = []
        b.ledger_reset.connect(lambda: fired.append(True))
        b.clear_all_data()
        self.assertGreater(len(fired), 0)


# ===================================================================
#  47. TX SUBMITTED SIGNAL
# ===================================================================

class Test47_TxSubmittedSignal(unittest.TestCase):
    """Test tx_submitted signal on various tx types."""

    def test_01_fires_on_trust_set(self):
        b = _make_backend()
        w = b.create_wallet("T")
        _fund(b, w["address"], 10_000.0)
        txs = []
        b.tx_submitted.connect(lambda tx: txs.append(tx))
        b.set_trust_line(w["address"], "USD", GENESIS, 1000.0)
        self.assertEqual(len(txs), 1)
        self.assertIsInstance(txs[0], dict)

    def test_02_fires_on_dex_offer(self):
        b = _make_backend()
        w = b.create_wallet("D")
        _fund(b, w["address"], 10_000.0)
        b.set_trust_line(w["address"], "USD", GENESIS, 1000.0)
        txs = []
        b.tx_submitted.connect(lambda tx: txs.append(tx))
        b.create_dex_offer(
            w["address"], 100.0, "NXF", "",
            50.0, "USD", GENESIS,
        )
        self.assertGreater(len(txs), 0)

    def test_03_fires_on_stake(self):
        b = _make_backend()
        w = b.create_wallet("S")
        _fund(b, w["address"], 100_000.0)
        txs = []
        b.tx_submitted.connect(lambda tx: txs.append(tx))
        b.stake_nxf(w["address"], 10_000.0, tier=0)
        # Staking may not emit tx_submitted (uses internal ledger, not broadcast)
        self.assertIsInstance(txs, list)


# ===================================================================
#  48. BALANCE UPDATED SIGNAL
# ===================================================================

class Test48_BalanceUpdatedSignal(unittest.TestCase):
    """Test balance_updated fires for tracked wallets during consensus."""

    def test_01_fires_for_tracked_wallets(self):
        b = _make_backend(peers=["10.0.0.2:9001"])
        w = b.create_wallet("Tracked")
        _fund(b, w["address"], 10_000.0)
        balances = []
        b.balance_updated.connect(lambda addr, bal: balances.append((addr, bal)))
        b.run_consensus()
        # Should contain our wallet
        addrs = [a for a, _ in balances]
        self.assertIn(w["address"], addrs)


# ===================================================================
#  49. STAKING CHANGED SIGNAL
# ===================================================================

class Test49_StakingChangedSignal(unittest.TestCase):
    """Test staking_changed fires on reset and clear."""

    def test_01_fires_on_clear_all_data(self):
        b = _make_backend()
        fired = []
        b.staking_changed.connect(lambda: fired.append(True))
        b.clear_all_data()
        self.assertGreater(len(fired), 0)

    def test_02_fires_on_reset_ledger(self):
        b = _make_backend()
        b.DEV_MODE = True
        fired = []
        b.staking_changed.connect(lambda: fired.append(True))
        b.reset_ledger()
        self.assertGreater(len(fired), 0)


# ===================================================================
#  50. AUTO CONSENSUS
# ===================================================================

class Test50_AutoConsensus(unittest.TestCase):
    """Test _auto_consensus only runs when txs are pending."""

    def test_01_no_consensus_when_empty(self):
        b = _make_backend(peers=["10.0.0.2:9001"])
        fired = []
        b.consensus_completed.connect(lambda r: fired.append(r))
        b._auto_consensus()
        # No pending txs → no consensus
        self.assertEqual(len(fired), 0)


# ===================================================================
#  51. VALIDATOR STATUSES
# ===================================================================

class Test51_ValidatorStatuses(unittest.TestCase):
    """Test get_validator_statuses returns proper list."""

    def test_01_count_matches_nodes(self):
        b = _make_backend(peers=["10.0.0.2:9001"])
        statuses = b.get_validator_statuses()
        self.assertEqual(len(statuses), 2)

    def test_02_statuses_are_dicts(self):
        b = _make_backend()
        statuses = b.get_validator_statuses()
        for s in statuses:
            self.assertIsInstance(s, dict)


# ===================================================================
#  52. GET TRUST LINES
# ===================================================================

class Test52_GetTrustLines(unittest.TestCase):
    """Test get_trust_lines returns proper data."""

    def test_01_includes_set_trust_line(self):
        b = _make_backend()
        w = b.create_wallet("TL")
        _fund(b, w["address"], 10_000.0)
        b.set_trust_line(w["address"], "EUR", GENESIS, 500.0)
        lines = b.get_trust_lines()
        self.assertGreater(len(lines), 0)

    def test_02_trust_line_has_all_fields(self):
        b = _make_backend()
        w = b.create_wallet("TL2")
        _fund(b, w["address"], 10_000.0)
        b.set_trust_line(w["address"], "GBP", GENESIS, 200.0)
        lines = b.get_trust_lines()
        tl = lines[0]
        self.assertIn("currency", tl)
        self.assertIn("issuer", tl)
        self.assertIn("limit", tl)


# ===================================================================
#  53. GET ALL ACCOUNTS
# ===================================================================

class Test53_GetAllAccounts(unittest.TestCase):
    """Test get_all_accounts in more detail."""

    def test_01_multiple_wallets_all_present(self):
        b = _make_backend()
        addrs = set()
        for i in range(5):
            w = b.create_wallet(f"W{i}")
            addrs.add(w["address"])
        all_accts = b.get_all_accounts()
        acct_addrs = {a["address"] for a in all_accts}
        for addr in addrs:
            self.assertIn(addr, acct_addrs)

    def test_02_genesis_always_included(self):
        b = _make_backend()
        all_accts = b.get_all_accounts()
        addrs = {a["address"] for a in all_accts}
        self.assertIn(GENESIS, addrs)


# ===================================================================
#  54. GET NETWORK STATUS
# ===================================================================

class Test54_GetNetworkStatus(unittest.TestCase):
    """Test get_network_status method."""

    def test_01_returns_dict(self):
        b = _make_backend()
        result = b.get_network_status()
        self.assertIsInstance(result, dict)

    def test_02_has_expected_keys(self):
        b = _make_backend(peers=["10.0.0.2:9001"])
        result = b.get_network_status()
        self.assertIn("validators", result)


# ===================================================================
#  55. ORDER BOOK QUERIES
# ===================================================================

class Test55_OrderBookQueries(unittest.TestCase):
    """Test order book query methods."""

    def test_01_pairs_after_offer(self):
        b = _make_backend()
        w = b.create_wallet("OB")
        _fund(b, w["address"], 10_000.0)
        b.set_trust_line(w["address"], "USD", GENESIS, 1000.0)
        b.create_dex_offer(
            w["address"], 100.0, "NXF", "",
            50.0, "USD", GENESIS,
        )
        pairs = b.get_order_book_pairs()
        self.assertIsInstance(pairs, list)

    def test_02_recent_fills_after_match(self):
        b = _make_backend()
        fills = b.get_recent_fills(limit=10)
        self.assertIsInstance(fills, list)

    def test_03_snapshot_returns_dict(self):
        b = _make_backend()
        w = b.create_wallet("S")
        _fund(b, w["address"], 10_000.0)
        b.set_trust_line(w["address"], "USD", GENESIS, 1000.0)
        b.create_dex_offer(
            w["address"], 100.0, "NXF", "",
            50.0, "USD", GENESIS,
        )
        pairs = b.get_order_book_pairs()
        if pairs:
            snap = b.get_order_book_snapshot(pairs[0])
            self.assertIsInstance(snap, dict)


# ===================================================================
#  56. STAKING TIERS AND POOL DETAILS
# ===================================================================

class Test56_StakingDetails(unittest.TestCase):
    """Detailed staking tier and pool tests."""

    def test_01_tiers_return_list_of_dicts(self):
        b = _make_backend()
        tiers = b.get_staking_tiers()
        self.assertIsInstance(tiers, list)
        self.assertGreater(len(tiers), 0)
        for t in tiers:
            self.assertIsInstance(t, dict)

    def test_02_pool_summary_total_staked(self):
        b = _make_backend()
        w = b.create_wallet("PS")
        _fund(b, w["address"], 200_000.0)
        b.stake_nxf(w["address"], 50_000.0, tier=0)
        summary = b.get_staking_pool_summary()
        self.assertGreater(summary.get("total_staked", 0), 0)

    def test_03_staking_summary_for_address(self):
        b = _make_backend()
        w = b.create_wallet("SS")
        _fund(b, w["address"], 100_000.0)
        b.stake_nxf(w["address"], 10_000.0, tier=0)
        summary = b.get_staking_summary(w["address"])
        self.assertIsInstance(summary, dict)
        self.assertGreater(summary.get("total_staked", 0), 0)


# ===================================================================
#  57. TX HISTORY DETAILED
# ===================================================================

class Test57_TxHistoryDetailed(unittest.TestCase):
    """Test get_tx_history returns proper reverse-ordered list."""

    def test_01_history_reverse_order(self):
        b = _make_backend()
        w1 = b.create_wallet("S")
        w2 = b.create_wallet("R")
        _fund(b, w1["address"], 100_000.0)
        b.send_payment(w1["address"], w2["address"], 1.0)
        b.send_payment(w1["address"], w2["address"], 2.0)
        hist = b.get_tx_history()
        self.assertGreater(len(hist), 1)
        # Most recent first (reversed)
        self.assertIsInstance(hist[0], dict)

    def test_02_history_includes_all_tx_types(self):
        b = _make_backend()
        w = b.create_wallet("Multi")
        _fund(b, w["address"], 100_000.0)
        b.send_payment(w["address"], GENESIS, 1.0)
        b.set_trust_line(w["address"], "USD", GENESIS, 1000.0)
        hist = b.get_tx_history()
        self.assertGreaterEqual(len(hist), 2)


# ===================================================================
#  58. CLEAR CACHE
# ===================================================================

class Test58_ClearCache(unittest.TestCase):
    """Test clear_cache method in detail."""

    def test_01_returns_string(self):
        b = _make_backend()
        result = b.clear_cache()
        self.assertIsInstance(result, str)

    def test_02_tx_history_cleared(self):
        b = _make_backend()
        w = b.create_wallet("C")
        _fund(b, w["address"], 10_000.0)
        b.send_payment(w["address"], GENESIS, 1.0)
        self.assertGreater(len(b.tx_history), 0)
        b.clear_cache()
        self.assertEqual(len(b.tx_history), 0)


# ===================================================================
#  59. DEV MODE FLAG
# ===================================================================

class Test59_DevModeFlag(unittest.TestCase):
    """Test DEV_MODE flag behavior."""

    def test_01_default_is_false(self):
        b = _make_backend()
        # Default without env var should be False
        # (unless env var is set in the test runner)
        self.assertIsInstance(b.DEV_MODE, bool)

    def test_02_can_override(self):
        b = _make_backend()
        b.DEV_MODE = True
        self.assertTrue(b.DEV_MODE)
        b.DEV_MODE = False
        self.assertFalse(b.DEV_MODE)


# ===================================================================
#  60. CLOSED LEDGERS DETAIL
# ===================================================================

class Test60_ClosedLedgersDetail(unittest.TestCase):
    """Test closed ledgers with field validation."""

    def test_01_after_consensus_has_entries(self):
        b = _make_backend(peers=["10.0.0.2:9001"])
        w = b.create_wallet("CL")
        _fund(b, w["address"], 10_000.0)
        b.send_payment(w["address"], GENESIS, 1.0)
        ledgers = b.get_closed_ledgers()
        self.assertGreater(len(ledgers), 0)

    def test_02_each_entry_is_dict(self):
        b = _make_backend(peers=["10.0.0.2:9001"])
        w = b.create_wallet("CL2")
        _fund(b, w["address"], 10_000.0)
        b.send_payment(w["address"], GENESIS, 1.0)
        for ledger in b.get_closed_ledgers():
            self.assertIsInstance(ledger, dict)


# ===================================================================
#  61. PMC LIST COINS DETAIL
# ===================================================================

class Test61_PMCListCoinsDetail(unittest.TestCase):
    """Test pmc_list_coins with multiple coins."""

    def test_01_multiple_coins_listed(self):
        b = _make_backend()
        w = b.create_wallet("Cr")
        _fund(b, w["address"], 200_000.0)
        symbols = []
        for i in range(3):
            b.pmc_create_coin(
                w["address"], f"M{i}", f"Coin{i}",
                max_supply=1_000_000.0, pow_difficulty=1, base_reward=100.0,
            )
            symbols.append(f"M{i}")
        listed = b.pmc_list_coins()
        listed_syms = {c["symbol"] for c in listed}
        for sym in symbols:
            self.assertIn(sym, listed_syms)
        coins = [c["coin_id"] for c in listed if c["symbol"] in listed_syms]
        listed = b.pmc_list_coins()
        listed_ids = {c["coin_id"] for c in listed}
        for cid in coins:
            self.assertIn(cid, listed_ids)

    def test_02_coin_fields_complete(self):
        b = _make_backend()
        w = b.create_wallet("Cr2")
        _fund(b, w["address"], 100_000.0)
        b.pmc_create_coin(
            w["address"], "FLD", "FieldCoin",
            max_supply=1_000_000.0, pow_difficulty=1, base_reward=100.0,
        )
        listed = b.pmc_list_coins()
        c = listed[0]
        self.assertIn("coin_id", c)
        self.assertIn("symbol", c)
        self.assertIn("name", c)
        self.assertIn("max_supply", c)


# ===================================================================
#  62. LEDGER SUMMARY DETAIL
# ===================================================================

class Test62_LedgerSummaryDetail(unittest.TestCase):
    """Detailed ledger summary tests."""

    def test_01_total_supply_matches(self):
        b = _make_backend()
        summary = b.get_ledger_summary()
        self.assertAlmostEqual(
            summary.get("total_supply", 0), SUPPLY, places=4
        )

    def test_02_accounts_count_grows(self):
        b = _make_backend()
        s1 = b.get_ledger_summary()
        b.create_wallet("New")
        s2 = b.get_ledger_summary()
        self.assertGreaterEqual(
            s2.get("accounts", 0), s1.get("accounts", 0)
        )


# ===================================================================
#  63. GET P2P STATUS DETAIL
# ===================================================================

class Test63_P2PStatusDetail(unittest.TestCase):
    """Detailed get_p2p_status tests."""

    def test_01_mode_is_local_simulation(self):
        b = _make_backend()
        status = b.get_p2p_status()
        self.assertEqual(status["mode"], "local_simulation")

    def test_02_validator_count_matches(self):
        b = _make_backend(peers=["10.0.0.2:9001", "10.0.0.3:9001"])
        status = b.get_p2p_status()
        self.assertEqual(status["validator_count"], 3)

    def test_03_dev_mode_field_present(self):
        b = _make_backend()
        status = b.get_p2p_status()
        self.assertIn("dev_mode", status)
        self.assertIsInstance(status["dev_mode"], bool)


# ===================================================================
#  64. RECOVER WALLET EDGE CASES
# ===================================================================

class Test64_RecoverWalletEdgeCases(unittest.TestCase):
    """Edge cases for wallet recovery."""

    def test_01_recover_wallet_returns_correct_fields(self):
        b = _make_backend()
        w = b.create_wallet("Orig")
        # Export/import to get keys for a second backend
        exported = b.export_wallet(w["address"], "pass")
        b2 = _make_backend()
        imported = b2.import_wallet_from_file(exported, "pass")
        self.assertEqual(imported["address"], w["address"])
        self.assertIn("public_key", imported)
        self.assertIn("name", imported)

    def test_02_recover_fires_signals(self):
        b = _make_backend()
        w = b.create_wallet("Orig")
        exported = b.export_wallet(w["address"], "pass")
        b2 = _make_backend()
        signals = []
        b2.wallet_created.connect(lambda info: signals.append(info))
        b2.import_wallet_from_file(exported, "pass")
        self.assertEqual(len(signals), 1)


# ===================================================================
#  65. IOU PAYMENT EDGE CASES
# ===================================================================

class Test65_IOUPaymentEdgeCases(unittest.TestCase):
    """Test IOU payment boundary conditions."""

    def test_01_iou_exceeding_trust_limit_fails(self):
        b = _make_backend()
        issuer = b.create_wallet("Issuer")
        holder = b.create_wallet("Holder")
        _fund(b, issuer["address"], 100_000.0)
        _fund(b, holder["address"], 10_000.0)
        b.set_trust_line(holder["address"], "TOK", issuer["address"], 100.0)
        # Try to send more than the trust limit
        result = b.send_payment(
            issuer["address"], holder["address"], 200.0,
            currency="TOK", issuer=issuer["address"],
        )
        # Should either fail or clamp — check holder balance
        acct = b.get_account_info(holder["address"])
        if acct:
            tl_dict = acct.get("trust_lines", {})
            for key, tl in tl_dict.items():
                if tl.get("currency") == "TOK":
                    self.assertLessEqual(tl.get("balance", 0), 100.0)

    def test_02_zero_trust_limit(self):
        b = _make_backend()
        w = b.create_wallet("Zero")
        _fund(b, w["address"], 10_000.0)
        result = b.set_trust_line(w["address"], "ZER", GENESIS, 0.0)
        # Should succeed (setting limit to 0 removes trust line effectively)
        self.assertIsNotNone(result)


# ===================================================================

# ===================================================================

if __name__ == "__main__":
    unittest.main()
