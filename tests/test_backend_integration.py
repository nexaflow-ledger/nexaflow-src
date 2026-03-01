"""
Integration tests for nexaflow_gui.backend.NodeBackend.

These tests exercise full user-facing flows that cross component
boundaries:  backend → broadcast → consensus → ledger apply.

The sequence-drift bug (wallet.sequence gets ahead of
ledger_account.sequence when multiple TXs are sent without consensus)
was never caught because the entire NodeBackend had zero test coverage
and all existing network tests use sequence=0 which bypasses the
sequence check.
"""

from __future__ import annotations

import json
import math
import os
import random
import unittest
from unittest.mock import patch

from nexaflow_core.config import load_config, NexaFlowConfig
from nexaflow_core.network import Network
from nexaflow_core.transaction import create_payment
from nexaflow_core.wallet import Wallet


# NodeBackend.__init__ requires a QObject parent infrastructure.
# We mock the PyQt6 timer/signal machinery so the tests run headlessly.
_qt_available = True
try:
    from PyQt6.QtWidgets import QApplication
except ImportError:
    _qt_available = False

# Create a single QApplication for the entire module (required by Qt)
if _qt_available:
    _app = QApplication.instance() or QApplication([])

from nexaflow_gui.backend import NodeBackend


# ---------------------------------------------------------------------------
#  Helpers
# ---------------------------------------------------------------------------

def _make_backend(genesis_addr: str = "rGenesis",
                  supply: float = 10_000_000.0,
                  peers: list[str] | None = None) -> NodeBackend:
    """Create a NodeBackend with a controlled config (no nexaflow.toml)."""
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


# ===================================================================
#  A.  NodeBackend initialisation
# ===================================================================

class TestBackendInit(unittest.TestCase):
    """A. Verify NodeBackend builds the right validator topology."""

    def test_single_node_no_peers(self):
        b = _make_backend()
        self.assertEqual(len(b._validators), 1)
        self.assertEqual(b._validators[0], "test-node")
        self.assertIn("test-node", b.network.nodes)

    def test_peers_become_validators(self):
        b = _make_backend(peers=["192.168.1.2:9001", "node3.example.com:9001"])
        # 1 (self) + 2 peers = 3 validators
        self.assertEqual(len(b._validators), 3)
        self.assertEqual(b._validators[0], "test-node")
        # IP → validator-N, hostname → hostname
        self.assertEqual(b._validators[1], "validator-2")
        self.assertEqual(b._validators[2], "node3.example.com")

    def test_genesis_from_config(self):
        b = _make_backend(genesis_addr="rCustomGenesis")
        ledger = b._primary_node.ledger
        self.assertEqual(ledger.genesis_account, "rCustomGenesis")
        self.assertEqual(ledger.get_balance("rCustomGenesis"), 10_000_000.0)


# ===================================================================
#  B.  Multi-TX send_payment (the sequence-drift bug)
# ===================================================================

class TestMultiTxPayment(unittest.TestCase):
    """B + N.  Sending multiple payments in succession must work."""

    def setUp(self):
        self.b = _make_backend()
        self.w1 = self.b.create_wallet("Sender")
        self.addr1 = self.w1["address"]
        self.w2 = self.b.create_wallet("Receiver")
        self.addr2 = self.w2["address"]
        _fund(self.b, self.addr1, 1_000_000.0)

    def test_three_successive_payments_accepted(self):
        """Regression: this failed with 'Expected seq 1, got 3'."""
        for i in range(3):
            result = self.b.send_payment(self.addr1, self.addr2, 100.0)
            self.assertIsNotNone(result, f"Payment {i+1} returned None")
            self.assertTrue(result["_accepted"], f"Payment {i+1} rejected")

    def test_balances_correct_after_multi_payment(self):
        n = 5
        amt = 200.0
        for _ in range(n):
            self.b.send_payment(self.addr1, self.addr2, amt)
        sender_bal = self.b.get_balance(self.addr1)
        recv_bal = self.b.get_balance(self.addr2)
        # Receiver gets exactly n * amt
        self.assertAlmostEqual(recv_bal, n * amt, places=4)
        # Sender loses n * amt + fees
        self.assertLess(sender_bal, 1_000_000.0 - n * amt)

    def test_sequence_stays_in_sync(self):
        """wallet sequence == ledger account sequence after each TX."""
        for i in range(3):
            self.b.send_payment(self.addr1, self.addr2, 50.0)
            acc = self.b._primary_node.ledger.get_account(self.addr1)
            # After _apply_immediately the ledger seq should have advanced
            self.assertEqual(
                acc.sequence, i + 2,  # starts at 1, after first TX → 2
                f"Ledger seq mismatch after TX {i+1}",
            )


# ===================================================================
#  C.  Trust-line flow through backend
# ===================================================================

class TestTrustLineBackend(unittest.TestCase):
    """C.  set_trust_line via backend."""

    def setUp(self):
        self.b = _make_backend()
        self.w = self.b.create_wallet("Holder")
        self.addr = self.w["address"]
        _fund(self.b, self.addr, 10_000.0)

    def test_trust_line_created_on_ledger(self):
        result = self.b.set_trust_line(self.addr, "USD", "rGenesis", 5000.0)
        self.assertIsNotNone(result)
        tl = self.b._primary_node.ledger.get_trust_line(
            self.addr, "USD", "rGenesis"
        )
        self.assertIsNotNone(tl)
        self.assertEqual(tl.limit, 5000.0)

    def test_trust_line_then_payment_sequence_ok(self):
        self.b.set_trust_line(self.addr, "USD", "rGenesis", 5000.0)
        # Follow-up NXF payment should not fail with bad sequence
        w2 = self.b.create_wallet("Other")
        result = self.b.send_payment(self.addr, w2["address"], 100.0)
        self.assertIsNotNone(result)
        self.assertTrue(result["_accepted"])


# ===================================================================
#  D.  DEX offer through backend
# ===================================================================

class TestDexOfferBackend(unittest.TestCase):
    """D.  create_dex_offer via backend."""

    def setUp(self):
        self.b = _make_backend()
        self.w = self.b.create_wallet("Trader")
        self.addr = self.w["address"]
        _fund(self.b, self.addr, 50_000.0)

    def test_offer_creates_tx(self):
        result = self.b.create_dex_offer(
            self.addr,
            pays_amount=100.0, pays_currency="NXF", pays_issuer="",
            gets_amount=50.0, gets_currency="USD", gets_issuer="rGenesis",
        )
        self.assertIsNotNone(result)

    def test_offer_then_payment_sequence_ok(self):
        self.b.create_dex_offer(
            self.addr,
            pays_amount=10.0, pays_currency="NXF", pays_issuer="",
            gets_amount=5.0, gets_currency="USD", gets_issuer="rGenesis",
        )
        w2 = self.b.create_wallet("Dest")
        result = self.b.send_payment(self.addr, w2["address"], 100.0)
        self.assertIsNotNone(result)
        self.assertTrue(result["_accepted"])


# ===================================================================
#  E.  Staking through backend
# ===================================================================

class TestStakingBackend(unittest.TestCase):
    """E.  stake_nxf and cancel_stake via backend."""

    def setUp(self):
        self.b = _make_backend()
        self.w = self.b.create_wallet("Staker")
        self.addr = self.w["address"]
        _fund(self.b, self.addr, 500_000.0)

    def test_stake_reduces_balance(self):
        before = self.b.get_balance(self.addr)
        result = self.b.stake_nxf(self.addr, 10_000.0, tier=0)
        self.assertIsNotNone(result)
        after = self.b.get_balance(self.addr)
        self.assertLess(after, before)

    def test_stake_then_payment_sequence_ok(self):
        self.b.stake_nxf(self.addr, 10_000.0, tier=0)
        w2 = self.b.create_wallet("Dest")
        result = self.b.send_payment(self.addr, w2["address"], 100.0)
        self.assertIsNotNone(result)
        self.assertTrue(result["_accepted"])


# ===================================================================
#  F.  clear_cache / clear_all_data
# ===================================================================

class TestClearOperations(unittest.TestCase):
    """F.  Cache and full data clear."""

    def setUp(self):
        self.b = _make_backend()
        self.w = self.b.create_wallet("Alice")
        self.addr = self.w["address"]
        _fund(self.b, self.addr, 10_000.0)
        w2 = self.b.create_wallet("Bob")
        self.b.send_payment(self.addr, w2["address"], 500.0)

    def test_clear_cache_preserves_wallets_and_ledger(self):
        # Should have tx_history from the payment
        self.assertGreater(len(self.b.tx_history), 0)
        self.b.clear_cache()
        # Wallets and ledger intact
        self.assertIn(self.addr, self.b.wallets)
        self.assertGreater(self.b.get_balance(self.addr), 0)
        # tx_history cleared
        self.assertEqual(len(self.b.tx_history), 0)

    def test_clear_all_data_wipes_everything(self):
        self.b.clear_all_data()
        self.assertEqual(len(self.b.wallets), 0)
        self.assertEqual(len(self.b.tx_history), 0)
        # Genesis is still there but wallets are gone
        self.assertIn("rGenesis", self.b._primary_node.ledger.accounts)

    def test_create_wallet_works_after_clear_all(self):
        self.b.clear_all_data()
        new = self.b.create_wallet("NewWallet")
        self.assertIn(new["address"], self.b.wallets)


# ===================================================================
#  G.  Wallet recovery from keys
# ===================================================================

class TestWalletRecovery(unittest.TestCase):
    """G.  recover_wallet_from_keys validation."""

    def setUp(self):
        self.b = _make_backend()
        # Create a reference wallet to get valid keys
        self.ref = Wallet.create()

    def test_recovery_with_valid_keys(self):
        info = self.b.recover_wallet_from_keys(
            public_key=self.ref.public_key.hex(),
            private_key=self.ref.private_key.hex(),
        )
        self.assertEqual(info["address"], self.ref.address)
        self.assertIn(self.ref.address, self.b.wallets)

    def test_recovery_with_mismatched_keys_raises(self):
        other = Wallet.create()
        with self.assertRaises(ValueError):
            self.b.recover_wallet_from_keys(
                public_key=self.ref.public_key.hex(),
                private_key=other.private_key.hex(),
            )

    def test_recovered_wallet_can_send(self):
        _fund(self.b, self.ref.address, 50_000.0)
        self.b.recover_wallet_from_keys(
            public_key=self.ref.public_key.hex(),
            private_key=self.ref.private_key.hex(),
        )
        w2 = self.b.create_wallet("Dest")
        result = self.b.send_payment(self.ref.address, w2["address"], 100.0)
        self.assertIsNotNone(result)
        self.assertTrue(result["_accepted"])


# ===================================================================
#  H + T.  Wallet export → import round-trip
# ===================================================================

class TestWalletExportImport(unittest.TestCase):
    """H + T.  Export, import, and verify the wallet works."""

    def setUp(self):
        self.b = _make_backend()
        self.w = self.b.create_wallet("Original")
        self.addr = self.w["address"]
        _fund(self.b, self.addr, 50_000.0)

    def test_round_trip(self):
        exported = self.b.export_wallet(self.addr, "pass123")
        # Remove from backend to prove re-import works
        del self.b.wallets[self.addr]
        info = self.b.import_wallet_from_file(exported, "pass123")
        self.assertEqual(info["address"], self.addr)

    def test_imported_wallet_can_send(self):
        exported = self.b.export_wallet(self.addr, "pass123")
        del self.b.wallets[self.addr]
        self.b.import_wallet_from_file(exported, "pass123")
        w2 = self.b.create_wallet("Dest")
        result = self.b.send_payment(self.addr, w2["address"], 100.0)
        self.assertIsNotNone(result)
        self.assertTrue(result["_accepted"])


# ===================================================================
#  I.  Consensus → balance update
# ===================================================================

class TestConsensusBalanceUpdate(unittest.TestCase):
    """I.  Running consensus updates balances visible to the backend."""

    def setUp(self):
        self.b = _make_backend()
        self.w1 = self.b.create_wallet("Sender")
        self.w2 = self.b.create_wallet("Receiver")
        self.addr1 = self.w1["address"]
        self.addr2 = self.w2["address"]
        _fund(self.b, self.addr1, 100_000.0)

    def test_balance_reflects_payment(self):
        self.b.send_payment(self.addr1, self.addr2, 5000.0)
        self.assertAlmostEqual(self.b.get_balance(self.addr2), 5000.0, places=4)


# ===================================================================
#  J.  Network.fund_account
# ===================================================================

class TestNetworkFundAccount(unittest.TestCase):
    """J.  fund_account across all nodes."""

    def test_all_nodes_funded(self):
        b = _make_backend(peers=["192.168.1.2:9001"])
        w = b.create_wallet("Funded")
        _fund(b, w["address"], 5000.0)
        for node in b.network.nodes.values():
            bal = node.ledger.get_balance(w["address"])
            self.assertAlmostEqual(bal, 5000.0, places=4)


# ===================================================================
#  K.  Multi-TX consensus from same sender (network level)
# ===================================================================

class TestMultiTxConsensusNetwork(unittest.TestCase):
    """K.  Network-level multi-TX consensus with real sequences."""

    def test_three_txs_applied_in_one_round(self):
        net = Network(total_supply=1_000_000.0, genesis_accounts={"rGen": 1_000_000.0})
        net.add_validator("v1")
        net.add_validator("v2")
        net.add_validator("v3")

        w = Wallet.from_seed("sender-seed")
        for node in net.nodes.values():
            node.ledger.create_account(w.address, 100_000.0)
            node.ledger.create_account("rDest", 0.0)

        # Send 3 TXs with auto-incrementing sequence
        for i in range(3):
            acc = net.nodes["v1"].ledger.get_account(w.address)
            tx = create_payment(w.address, "rDest", 100.0, sequence=acc.sequence)
            w.sign_transaction(tx)
            net.broadcast_transaction(tx)
            # Need to apply between each, since sequence must advance
            net.run_consensus_round()

        bal = net.nodes["v1"].ledger.get_balance("rDest")
        self.assertAlmostEqual(bal, 300.0, places=4)


# ===================================================================
#  L.  Config genesis → ledger creation
# ===================================================================

class TestGenesisConfig(unittest.TestCase):
    """L.  Custom genesis accounts from config."""

    def test_single_genesis_account(self):
        net = Network(
            total_supply=5000.0,
            genesis_accounts={"rAlice": 5000.0},
        )
        node = net.add_validator("v1")
        self.assertEqual(node.ledger.genesis_account, "rAlice")
        self.assertAlmostEqual(node.ledger.get_balance("rAlice"), 5000.0)

    def test_multiple_genesis_accounts(self):
        net = Network(
            total_supply=3000.0,
            genesis_accounts={"rAlice": 3000.0, "rBob": 200.0},
        )
        node = net.add_validator("v1")
        self.assertEqual(node.ledger.genesis_account, "rAlice")
        self.assertAlmostEqual(node.ledger.get_balance("rAlice"), 3000.0)
        self.assertAlmostEqual(node.ledger.get_balance("rBob"), 200.0)

    def test_empty_genesis_uses_default(self):
        net = Network(total_supply=10_000.0, genesis_accounts={})
        node = net.add_validator("v1")
        self.assertEqual(node.ledger.genesis_account, "nGenesisNXF")


# ===================================================================
#  M.  _build_validator_list derivation
# ===================================================================

class TestValidatorListDerivation(unittest.TestCase):
    """M.  Peer addresses → validator IDs."""

    def test_empty_peers(self):
        b = _make_backend(peers=[])
        self.assertEqual(b._validators, ["test-node"])

    def test_ip_peers(self):
        b = _make_backend(peers=["192.168.1.2:9001", "10.0.0.5:9002"])
        self.assertEqual(b._validators[1], "validator-2")
        self.assertEqual(b._validators[2], "validator-3")

    def test_hostname_peers(self):
        b = _make_backend(peers=["node2.example.com:9001", "node3.lan:9002"])
        self.assertEqual(b._validators[1], "node2.example.com")
        self.assertEqual(b._validators[2], "node3.lan")

    def test_localhost_peer(self):
        b = _make_backend(peers=["localhost:9002"])
        self.assertEqual(b._validators[1], "validator-2")


# ===================================================================
#  O.  Chained consensus rounds
# ===================================================================

class TestChainedConsensusRounds(unittest.TestCase):
    """O.  Round 1 TX → round 2 TX from same sender."""

    def test_second_round_accepted(self):
        b = _make_backend()
        w1 = b.create_wallet("Sender")
        w2 = b.create_wallet("Recv")
        _fund(b, w1["address"], 100_000.0)

        # Round 1
        r1 = b.send_payment(w1["address"], w2["address"], 500.0)
        self.assertTrue(r1["_accepted"])

        # Explicit consensus (should be no-op since _apply_immediately ran)
        b.run_consensus()

        # Round 2
        r2 = b.send_payment(w1["address"], w2["address"], 700.0)
        self.assertIsNotNone(r2)
        self.assertTrue(r2["_accepted"])

        self.assertAlmostEqual(b.get_balance(w2["address"]), 1200.0, places=4)


# ===================================================================
#  P.  reset_ledger (dev mode)
# ===================================================================

class TestResetLedger(unittest.TestCase):
    """P.  Dev-mode ledger reset."""

    def test_reset_not_allowed_without_dev_mode(self):
        b = _make_backend()
        b.DEV_MODE = False
        b.reset_ledger()
        # Should be a no-op; wallets still present
        # (error_occurred signal fires but doesn't raise)

    def test_reset_clears_tx_history(self):
        b = _make_backend()
        b.DEV_MODE = True
        w1 = b.create_wallet("A")
        w2 = b.create_wallet("B")
        _fund(b, w1["address"], 10_000.0)
        b.send_payment(w1["address"], w2["address"], 100.0)
        self.assertGreater(len(b.tx_history), 0)
        b.reset_ledger()
        self.assertEqual(len(b.tx_history), 0)

    def test_wallets_re_registered_after_reset(self):
        b = _make_backend()
        b.DEV_MODE = True
        w = b.create_wallet("Keep")
        addr = w["address"]
        _fund(b, addr, 5000.0)
        b.reset_ledger()
        # Wallet still tracked
        self.assertIn(addr, b.wallets)
        # But balance is zero (fresh ledger)
        self.assertAlmostEqual(b.get_balance(addr), 0.0)


# ===================================================================
#  Q.  IOU payment end-to-end
# ===================================================================

class TestIOUPaymentEndToEnd(unittest.TestCase):
    """Q.  IOU payment requires trust line → payment → consensus."""

    def setUp(self):
        self.b = _make_backend()
        self.issuer = self.b.create_wallet("Issuer")
        self.holder = self.b.create_wallet("Holder")
        _fund(self.b, self.issuer["address"], 100_000.0)
        _fund(self.b, self.holder["address"], 100_000.0)

    def test_iou_after_trust_line(self):
        # Holder trusts Issuer for USD
        self.b.set_trust_line(
            self.holder["address"], "USD", self.issuer["address"], 10_000.0
        )
        # Issuer sends USD to Holder
        result = self.b.send_payment(
            self.issuer["address"],
            self.holder["address"],
            500.0,
            currency="USD",
            issuer=self.issuer["address"],
        )
        self.assertIsNotNone(result)
        self.assertTrue(result["_accepted"])


# ===================================================================
#  S.  Signal emissions
# ===================================================================

class TestSignalEmissions(unittest.TestCase):
    """S.  Verify key signals fire during operations."""

    def test_tx_submitted_signal_fires(self):
        b = _make_backend()
        w1 = b.create_wallet("Sender")
        w2 = b.create_wallet("Recv")
        _fund(b, w1["address"], 50_000.0)

        received = []
        b.tx_submitted.connect(lambda d: received.append(d))
        b.send_payment(w1["address"], w2["address"], 100.0)
        self.assertEqual(len(received), 1)
        self.assertIn("tx_id", received[0])

    def test_wallet_created_signal_fires(self):
        b = _make_backend()
        received = []
        b.wallet_created.connect(lambda d: received.append(d))
        b.create_wallet("Test")
        self.assertEqual(len(received), 1)
        self.assertIn("address", received[0])

    def test_consensus_completed_signal_fires(self):
        b = _make_backend()
        w1 = b.create_wallet("Sender")
        w2 = b.create_wallet("Recv")
        _fund(b, w1["address"], 50_000.0)

        received = []
        b.consensus_completed.connect(lambda d: received.append(d))
        b.send_payment(w1["address"], w2["address"], 100.0)
        # _apply_immediately calls run_consensus, which fires the signal
        self.assertGreater(len(received), 0)


# ===================================================================
#  STRESS — 100 random back-and-forth transactions
# ===================================================================

DEFAULT_FEE = 0.00001


class TestStress100RandomTransactions(unittest.TestCase):
    """Send 100 random payments between wallets, verify full correctness."""

    SUPPLY = 100_000_000.0
    NUM_TX = 100
    SEED = 42  # deterministic reproducibility

    def setUp(self):
        self.b = _make_backend(supply=self.SUPPLY)
        self.w_alice = self.b.create_wallet("Alice")
        self.w_bob = self.b.create_wallet("Bob")
        self.addr_a = self.w_alice["address"]
        self.addr_b = self.w_bob["address"]
        # Fund both wallets generously
        _fund(self.b, self.addr_a, 25_000_000.0)
        _fund(self.b, self.addr_b, 25_000_000.0)

    def test_100_random_payments_all_accepted(self):
        """Every TX must be accepted — no sequence or balance failures."""
        rng = random.Random(self.SEED)
        for i in range(self.NUM_TX):
            if rng.random() < 0.5:
                src, dst = self.addr_a, self.addr_b
            else:
                src, dst = self.addr_b, self.addr_a
            amt = round(rng.uniform(1.0, 50_000.0), 8)
            result = self.b.send_payment(src, dst, amt)
            self.assertIsNotNone(result, f"TX {i+1} returned None")
            self.assertTrue(
                result["_accepted"],
                f"TX {i+1} rejected: {result}",
            )

    def test_100_random_balances_exact(self):
        """Balances must match accounting: initial - sent + received - fees."""
        rng = random.Random(self.SEED)
        sent_a = 0.0   # total NXF Alice sent (not counting fees)
        recv_a = 0.0   # total NXF Alice received
        sent_b = 0.0
        recv_b = 0.0
        fees_a = 0.0   # total fees paid by Alice
        fees_b = 0.0

        for _ in range(self.NUM_TX):
            if rng.random() < 0.5:
                src, dst = "a", "b"
            else:
                src, dst = "b", "a"
            amt = round(rng.uniform(1.0, 50_000.0), 8)
            src_addr = self.addr_a if src == "a" else self.addr_b
            dst_addr = self.addr_b if src == "a" else self.addr_a
            result = self.b.send_payment(src_addr, dst_addr, amt)
            self.assertTrue(result["_accepted"])

            if src == "a":
                sent_a += amt
                fees_a += DEFAULT_FEE
                recv_b += amt
            else:
                sent_b += amt
                fees_b += DEFAULT_FEE
                recv_a += amt

        expected_a = 25_000_000.0 - sent_a + recv_a - fees_a
        expected_b = 25_000_000.0 - sent_b + recv_b - fees_b
        actual_a = self.b.get_balance(self.addr_a)
        actual_b = self.b.get_balance(self.addr_b)

        self.assertAlmostEqual(actual_a, expected_a, places=5,
                               msg="Alice balance mismatch")
        self.assertAlmostEqual(actual_b, expected_b, places=5,
                               msg="Bob balance mismatch")

    def test_100_random_sequence_always_in_sync(self):
        """After every single TX the ledger seq must match expectations."""
        rng = random.Random(self.SEED)
        seq_a = 1  # account sequences start at 1
        seq_b = 1
        for i in range(self.NUM_TX):
            if rng.random() < 0.5:
                src_addr, dst_addr = self.addr_a, self.addr_b
                seq_a += 1
                expected_src_seq = seq_a
                addr_key = self.addr_a
            else:
                src_addr, dst_addr = self.addr_b, self.addr_a
                seq_b += 1
                expected_src_seq = seq_b
                addr_key = self.addr_b
            amt = round(rng.uniform(1.0, 50_000.0), 8)
            self.b.send_payment(src_addr, dst_addr, amt)
            acc = self.b._primary_node.ledger.get_account(addr_key)
            self.assertEqual(
                acc.sequence, expected_src_seq,
                f"Sequence mismatch on TX {i+1} for {addr_key[:12]}…",
            )

    def test_100_random_total_supply_conservation(self):
        """total_supply must decrease by exactly the sum of burned fees."""
        rng = random.Random(self.SEED)
        ledger = self.b._primary_node.ledger
        initial_supply = ledger.total_supply

        total_fees = 0.0
        for _ in range(self.NUM_TX):
            if rng.random() < 0.5:
                src, dst = self.addr_a, self.addr_b
            else:
                src, dst = self.addr_b, self.addr_a
            amt = round(rng.uniform(1.0, 50_000.0), 8)
            self.b.send_payment(src, dst, amt)
            total_fees += DEFAULT_FEE

        # total_supply should have shrunk by exactly the burned fees
        self.assertAlmostEqual(
            ledger.total_supply, initial_supply - total_fees, places=5,
            msg="Supply conservation violated",
        )
        self.assertAlmostEqual(
            ledger.total_burned, total_fees, places=5,
            msg="total_burned does not match expected fees",
        )

    def test_100_random_all_validators_agree(self):
        """Every validator node must have identical balances after all TXs."""
        b = _make_backend(
            supply=self.SUPPLY,
            peers=["10.0.0.2:9001", "10.0.0.3:9001"],
        )
        w1 = b.create_wallet("Alice")
        w2 = b.create_wallet("Bob")
        a1, a2 = w1["address"], w2["address"]
        _fund(b, a1, 25_000_000.0)
        _fund(b, a2, 25_000_000.0)

        rng = random.Random(self.SEED)
        for _ in range(self.NUM_TX):
            if rng.random() < 0.5:
                src, dst = a1, a2
            else:
                src, dst = a2, a1
            amt = round(rng.uniform(1.0, 50_000.0), 8)
            b.send_payment(src, dst, amt)

        # All 3 validators must agree on balances
        nodes = list(b.network.nodes.values())
        ref_bal_a = nodes[0].ledger.get_balance(a1)
        ref_bal_b = nodes[0].ledger.get_balance(a2)
        for node in nodes[1:]:
            self.assertAlmostEqual(
                node.ledger.get_balance(a1), ref_bal_a, places=5,
                msg=f"{node.node_id} disagrees on Alice balance",
            )
            self.assertAlmostEqual(
                node.ledger.get_balance(a2), ref_bal_b, places=5,
                msg=f"{node.node_id} disagrees on Bob balance",
            )


# ===================================================================
#  STRESS — Multi-wallet random mesh (5 wallets, 100 TXs)
# ===================================================================

class TestStressMultiWalletMesh(unittest.TestCase):
    """5 wallets sending random payments to each other — 100 TXs."""

    NUM_WALLETS = 5
    NUM_TX = 100
    SUPPLY = 500_000_000.0
    FUND_EACH = 50_000_000.0
    SEED = 99

    def setUp(self):
        self.b = _make_backend(supply=self.SUPPLY)
        self.wallets: list[str] = []
        for i in range(self.NUM_WALLETS):
            w = self.b.create_wallet(f"W{i}")
            self.wallets.append(w["address"])
            _fund(self.b, w["address"], self.FUND_EACH)

    def test_mesh_all_accepted(self):
        rng = random.Random(self.SEED)
        for i in range(self.NUM_TX):
            src = rng.choice(self.wallets)
            dst = rng.choice([w for w in self.wallets if w != src])
            amt = round(rng.uniform(1.0, 10_000.0), 8)
            result = self.b.send_payment(src, dst, amt)
            self.assertIsNotNone(result, f"TX {i+1} None")
            self.assertTrue(result["_accepted"], f"TX {i+1} rejected")

    def test_mesh_balances_consistent(self):
        """Sum of all balances + burned fees == original funded total."""
        rng = random.Random(self.SEED)
        ledger = self.b._primary_node.ledger
        original_total = self.FUND_EACH * self.NUM_WALLETS

        for _ in range(self.NUM_TX):
            src = rng.choice(self.wallets)
            dst = rng.choice([w for w in self.wallets if w != src])
            amt = round(rng.uniform(1.0, 10_000.0), 8)
            self.b.send_payment(src, dst, amt)

        # Sum wallet balances
        total_bal = sum(
            self.b.get_balance(addr) for addr in self.wallets
        )
        # Accounting identity: initial funded amount == balances + fees burned
        # (only fees from our 100 TXs — genesis still holds the rest of supply
        # but we compare against just the wallets we funded)
        burned_in_wallets = self.NUM_TX * DEFAULT_FEE
        self.assertAlmostEqual(
            total_bal + burned_in_wallets, original_total,
            places=4,
            msg="Balance + fee conservation broken across mesh",
        )

    def test_mesh_sequences_correct(self):
        """Each wallet's ledger sequence == 1 + number of TXs it sent."""
        rng = random.Random(self.SEED)
        send_counts: dict[str, int] = {addr: 0 for addr in self.wallets}

        for _ in range(self.NUM_TX):
            src = rng.choice(self.wallets)
            dst = rng.choice([w for w in self.wallets if w != src])
            amt = round(rng.uniform(1.0, 10_000.0), 8)
            self.b.send_payment(src, dst, amt)
            send_counts[src] += 1

        for addr in self.wallets:
            acc = self.b._primary_node.ledger.get_account(addr)
            expected = 1 + send_counts[addr]
            self.assertEqual(
                acc.sequence, expected,
                f"{addr[:12]}… seq {acc.sequence} != expected {expected}",
            )

    def test_mesh_no_negative_balances(self):
        rng = random.Random(self.SEED)
        for _ in range(self.NUM_TX):
            src = rng.choice(self.wallets)
            dst = rng.choice([w for w in self.wallets if w != src])
            amt = round(rng.uniform(1.0, 10_000.0), 8)
            self.b.send_payment(src, dst, amt)

        for addr in self.wallets:
            bal = self.b.get_balance(addr)
            self.assertGreaterEqual(bal, 0.0, f"{addr[:12]}… has negative balance: {bal}")


# ===================================================================
#  STRESS — Mixed operation pipeline (payments + trust + offers + staking)
# ===================================================================

class TestStressMixedOperations(unittest.TestCase):
    """Interleave payments, trust lines, DEX offers, and staking.

    Verifies that sequences stay correct when different TX types
    are interleaved from the same wallet.
    """

    SUPPLY = 200_000_000.0
    SEED = 77

    def setUp(self):
        self.b = _make_backend(supply=self.SUPPLY)
        self.alice = self.b.create_wallet("Alice")["address"]
        self.bob = self.b.create_wallet("Bob")["address"]
        self.carol = self.b.create_wallet("Carol")["address"]
        _fund(self.b, self.alice, 50_000_000.0)
        _fund(self.b, self.bob, 50_000_000.0)
        _fund(self.b, self.carol, 50_000_000.0)

    def test_interleaved_operations_sequence_correct(self):
        """Mix of operations from Alice — sequence must stay in sync."""
        # 1. Payment
        r = self.b.send_payment(self.alice, self.bob, 1000.0)
        self.assertTrue(r["_accepted"])
        self._check_seq(self.alice, 2)

        # 2. Trust line
        r = self.b.set_trust_line(self.alice, "USD", self.bob, 50000.0)
        self.assertIsNotNone(r)
        self._check_seq(self.alice, 3)

        # 3. Another payment
        r = self.b.send_payment(self.alice, self.carol, 2000.0)
        self.assertTrue(r["_accepted"])
        self._check_seq(self.alice, 4)

        # 4. DEX offer
        r = self.b.create_dex_offer(
            self.alice,
            pays_amount=500.0, pays_currency="NXF", pays_issuer="",
            gets_amount=250.0, gets_currency="USD", gets_issuer=self.bob,
        )
        self.assertIsNotNone(r)
        self._check_seq(self.alice, 5)

        # 5. Staking
        r = self.b.stake_nxf(self.alice, 10_000.0, tier=0)
        self.assertIsNotNone(r)
        self._check_seq(self.alice, 6)

        # 6. Two more payments
        for i in range(2):
            r = self.b.send_payment(self.alice, self.bob, 500.0)
            self.assertTrue(r["_accepted"])
        self._check_seq(self.alice, 8)

    def test_three_wallets_interleaved_50_ops(self):
        """50 random operations across 3 wallets with mixed TX types."""
        rng = random.Random(self.SEED)
        addrs = [self.alice, self.bob, self.carol]
        send_counts = {a: 0 for a in addrs}

        for i in range(50):
            src = rng.choice(addrs)
            others = [a for a in addrs if a != src]
            dst = rng.choice(others)

            op = rng.choice(["payment", "payment", "payment", "trust", "offer"])
            if op == "payment":
                amt = round(rng.uniform(10.0, 5000.0), 8)
                r = self.b.send_payment(src, dst, amt)
                self.assertIsNotNone(r, f"Op {i+1} ({op}) None")
                self.assertTrue(r["_accepted"], f"Op {i+1} ({op}) rejected")
                send_counts[src] += 1
            elif op == "trust":
                r = self.b.set_trust_line(src, "EUR", dst, 100_000.0)
                self.assertIsNotNone(r, f"Op {i+1} ({op}) None")
                send_counts[src] += 1
            elif op == "offer":
                r = self.b.create_dex_offer(
                    src,
                    pays_amount=100.0, pays_currency="NXF", pays_issuer="",
                    gets_amount=50.0, gets_currency="EUR", gets_issuer=dst,
                )
                self.assertIsNotNone(r, f"Op {i+1} ({op}) None")
                send_counts[src] += 1

        # Verify sequences
        for addr in addrs:
            acc = self.b._primary_node.ledger.get_account(addr)
            expected = 1 + send_counts[addr]
            self.assertEqual(
                acc.sequence, expected,
                f"{addr[:12]}… seq {acc.sequence} != {expected} "
                f"after {send_counts[addr]} sends",
            )

    def _check_seq(self, addr: str, expected: int):
        acc = self.b._primary_node.ledger.get_account(addr)
        self.assertEqual(acc.sequence, expected,
                         f"seq {acc.sequence} != {expected} for {addr[:12]}…")


# ===================================================================
#  STRESS — Rapid bidirectional ping-pong
# ===================================================================

class TestStressBidirectionalPingPong(unittest.TestCase):
    """Alice and Bob alternate sending 1 NXF to each other 100 times.

    This is the worst case for sequence tracking — every other TX
    is from a different sender.
    """

    NUM_TX = 100
    SUPPLY = 10_000_000.0

    def setUp(self):
        self.b = _make_backend(supply=self.SUPPLY)
        self.alice = self.b.create_wallet("Alice")["address"]
        self.bob = self.b.create_wallet("Bob")["address"]
        _fund(self.b, self.alice, 1_000_000.0)
        _fund(self.b, self.bob, 1_000_000.0)

    def test_alternating_sends_all_accepted(self):
        for i in range(self.NUM_TX):
            if i % 2 == 0:
                src, dst = self.alice, self.bob
            else:
                src, dst = self.bob, self.alice
            r = self.b.send_payment(src, dst, 1.0)
            self.assertIsNotNone(r, f"TX {i+1} None")
            self.assertTrue(r["_accepted"], f"TX {i+1} rejected")

    def test_alternating_balances_exact(self):
        for i in range(self.NUM_TX):
            if i % 2 == 0:
                src, dst = self.alice, self.bob
            else:
                src, dst = self.bob, self.alice
            self.b.send_payment(src, dst, 1.0)

        # Each sent 50 payments of 1.0 NXF, paid 50 * fee
        alice_expected = 1_000_000.0 - 50.0 + 50.0 - 50 * DEFAULT_FEE
        bob_expected = 1_000_000.0 - 50.0 + 50.0 - 50 * DEFAULT_FEE
        self.assertAlmostEqual(
            self.b.get_balance(self.alice), alice_expected, places=5,
        )
        self.assertAlmostEqual(
            self.b.get_balance(self.bob), bob_expected, places=5,
        )

    def test_alternating_sequences(self):
        for i in range(self.NUM_TX):
            if i % 2 == 0:
                src, dst = self.alice, self.bob
            else:
                src, dst = self.bob, self.alice
            self.b.send_payment(src, dst, 1.0)

        alice_acc = self.b._primary_node.ledger.get_account(self.alice)
        bob_acc = self.b._primary_node.ledger.get_account(self.bob)
        # Each sent 50 TXs → seq = 1 + 50 = 51
        self.assertEqual(alice_acc.sequence, 51)
        self.assertEqual(bob_acc.sequence, 51)

    def test_alternating_ledger_closes(self):
        """Each TX triggers consensus → 100 ledger closes."""
        for i in range(self.NUM_TX):
            if i % 2 == 0:
                src, dst = self.alice, self.bob
            else:
                src, dst = self.bob, self.alice
            self.b.send_payment(src, dst, 1.0)

        ledger = self.b._primary_node.ledger
        # current_sequence should be >= 1 + NUM_TX (one close per consensus)
        self.assertGreaterEqual(ledger.current_sequence, 1 + self.NUM_TX)


# ===================================================================
#  STRESS — Large burst from single sender
# ===================================================================

class TestStressSingleSenderBurst(unittest.TestCase):
    """One wallet fires 100 payments to different recipients.

    Tests the exact pattern that triggered the original sequence bug.
    """

    NUM_TX = 100
    SUPPLY = 100_000_000.0

    def setUp(self):
        self.b = _make_backend(supply=self.SUPPLY)
        self.sender = self.b.create_wallet("Sender")["address"]
        _fund(self.b, self.sender, 50_000_000.0)
        self.receivers: list[str] = []
        for i in range(10):
            w = self.b.create_wallet(f"Recv{i}")
            self.receivers.append(w["address"])

    def test_burst_all_accepted(self):
        rng = random.Random(123)
        for i in range(self.NUM_TX):
            dst = rng.choice(self.receivers)
            r = self.b.send_payment(self.sender, dst, 100.0)
            self.assertIsNotNone(r, f"TX {i+1} None")
            self.assertTrue(r["_accepted"], f"TX {i+1} rejected")

    def test_burst_sender_sequence(self):
        rng = random.Random(123)
        for _ in range(self.NUM_TX):
            dst = rng.choice(self.receivers)
            self.b.send_payment(self.sender, dst, 100.0)

        acc = self.b._primary_node.ledger.get_account(self.sender)
        self.assertEqual(acc.sequence, 1 + self.NUM_TX)

    def test_burst_receiver_totals(self):
        """Sum of receiver balances == total sent."""
        rng = random.Random(123)
        for _ in range(self.NUM_TX):
            dst = rng.choice(self.receivers)
            self.b.send_payment(self.sender, dst, 100.0)

        total_recv = sum(self.b.get_balance(a) for a in self.receivers)
        self.assertAlmostEqual(total_recv, self.NUM_TX * 100.0, places=4)

    def test_burst_supply_conservation(self):
        rng = random.Random(123)
        ledger = self.b._primary_node.ledger
        for _ in range(self.NUM_TX):
            dst = rng.choice(self.receivers)
            self.b.send_payment(self.sender, dst, 100.0)

        # All account balances + genesis account + burned == initial supply
        all_bals = sum(
            acc.balance for acc in ledger.accounts.values()
        )
        self.assertAlmostEqual(
            all_bals + ledger.total_burned, ledger.initial_supply,
            places=4,
            msg="Global supply conservation violated after burst",
        )


# ===================================================================
#  STRESS — Edge-case amounts (very small and very large)
# ===================================================================

class TestStressEdgeCaseAmounts(unittest.TestCase):
    """Payments with extreme amounts — dust and near-balance-depleting."""

    SUPPLY = 100_000_000_000.0

    def setUp(self):
        self.b = _make_backend(supply=self.SUPPLY)
        self.alice = self.b.create_wallet("Alice")["address"]
        self.bob = self.b.create_wallet("Bob")["address"]

    def test_dust_payments(self):
        """50 payments of the minimum meaningful amount (0.00001)."""
        _fund(self.b, self.alice, 100_000.0)
        for i in range(50):
            r = self.b.send_payment(self.alice, self.bob, 0.00001)
            self.assertIsNotNone(r, f"Dust TX {i+1} None")
            self.assertTrue(r["_accepted"], f"Dust TX {i+1} rejected")
        self.assertAlmostEqual(
            self.b.get_balance(self.bob), 50 * 0.00001, places=8,
        )

    def test_large_payment(self):
        """Single payment of a very large amount."""
        _fund(self.b, self.alice, 10_000_000_000.0)
        r = self.b.send_payment(self.alice, self.bob, 9_999_999_000.0)
        self.assertIsNotNone(r)
        self.assertTrue(r["_accepted"])
        self.assertAlmostEqual(
            self.b.get_balance(self.bob), 9_999_999_000.0, places=4,
        )

    def test_mixed_dust_and_large(self):
        """Alternate between dust and large amounts."""
        _fund(self.b, self.alice, 50_000_000.0)
        _fund(self.b, self.bob, 50_000_000.0)

        rng = random.Random(55)
        for i in range(40):
            if i % 2 == 0:
                src, dst = self.alice, self.bob
            else:
                src, dst = self.bob, self.alice
            if rng.random() < 0.5:
                amt = round(rng.uniform(0.00001, 0.001), 8)
            else:
                amt = round(rng.uniform(100_000.0, 1_000_000.0), 8)
            r = self.b.send_payment(src, dst, amt)
            self.assertIsNotNone(r, f"TX {i+1} None")
            self.assertTrue(r["_accepted"], f"TX {i+1} rejected")

        # Conservation check
        ledger = self.b._primary_node.ledger
        all_bals = sum(acc.balance for acc in ledger.accounts.values())
        self.assertAlmostEqual(
            all_bals + ledger.total_burned, ledger.initial_supply,
            places=3,
        )


# ===================================================================
#  STRESS — Rapid wallet creation + immediate use
# ===================================================================

class TestStressWalletCreationAndUse(unittest.TestCase):
    """Create wallets and use them immediately — 20 wallets, 100 TXs."""

    NUM_WALLETS = 20
    NUM_TX = 100
    SUPPLY = 500_000_000.0
    SEED = 2026

    def test_create_use_cycle(self):
        b = _make_backend(supply=self.SUPPLY)
        wallets: list[str] = []

        # Create 20 wallets and fund from genesis
        for i in range(self.NUM_WALLETS):
            w = b.create_wallet(f"W{i}")
            wallets.append(w["address"])
            _fund(b, w["address"], 10_000_000.0)

        rng = random.Random(self.SEED)
        accepted = 0
        for i in range(self.NUM_TX):
            src = rng.choice(wallets)
            dst = rng.choice([w for w in wallets if w != src])
            amt = round(rng.uniform(1.0, 1000.0), 8)
            r = b.send_payment(src, dst, amt)
            if r and r["_accepted"]:
                accepted += 1

        self.assertEqual(accepted, self.NUM_TX, "Not all TXs accepted")

        # No wallet should have negative balance
        for addr in wallets:
            self.assertGreaterEqual(b.get_balance(addr), 0.0)

        # Global conservation
        ledger = b._primary_node.ledger
        all_bals = sum(acc.balance for acc in ledger.accounts.values())
        self.assertAlmostEqual(
            all_bals + ledger.total_burned, ledger.initial_supply,
            places=3,
        )


if __name__ == "__main__":
    unittest.main()
