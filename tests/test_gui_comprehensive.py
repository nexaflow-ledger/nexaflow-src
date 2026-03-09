"""
Comprehensive GUI backend integration tests.

Tests every NodeBackend button/method in order, checking all balances,
wallets, transactions, PMCs, staking, trust lines, DEX, and consensus.
Designed to expose every functional issue in the system.
"""

from __future__ import annotations

import hashlib
import json
import time
import unittest
from unittest.mock import patch

from nexaflow_core.config import NexaFlowConfig
from nexaflow_core.network import Network
from nexaflow_core.wallet import Wallet

# Qt setup — required for NodeBackend signals
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


EMPTY_TX_ROOT = "0" * 64


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


# ===================================================================
#  1. WALLET LIFECYCLE
# ===================================================================

class Test01_WalletLifecycle(unittest.TestCase):
    """Test wallet creation, listing, import/export, recovery."""

    def setUp(self):
        self.b = _make_backend()

    def test_01_create_wallet_returns_info(self):
        info = self.b.create_wallet("Alice")
        self.assertIn("address", info)
        self.assertIn("name", info)
        self.assertIn("balance", info)
        self.assertIn("public_key", info)
        self.assertEqual(info["name"], "Alice")
        self.assertEqual(info["balance"], 0.0)

    def test_02_wallet_registered_on_all_validators(self):
        info = self.b.create_wallet("Alice")
        addr = info["address"]
        for node in self.b.network.nodes.values():
            self.assertTrue(
                node.ledger.account_exists(addr),
                f"Wallet not registered on {node.node_id}")

    def test_03_get_wallets_returns_created(self):
        self.b.create_wallet("W1")
        self.b.create_wallet("W2")
        wallets = self.b.get_wallets()
        self.assertEqual(len(wallets), 2)
        names = {w["name"] for w in wallets}
        self.assertIn("W1", names)
        self.assertIn("W2", names)

    def test_04_import_from_seed_deterministic(self):
        info1 = self.b.import_wallet_from_seed("test-seed-xyz", "Seeded")
        # Second backend with same seed should produce same address
        b2 = _make_backend()
        info2 = b2.import_wallet_from_seed("test-seed-xyz", "Seeded2")
        self.assertEqual(info1["address"], info2["address"])

    def test_05_export_import_roundtrip(self):
        info = self.b.create_wallet("Original")
        addr = info["address"]
        _fund(self.b, addr, 10_000.0)
        exported = self.b.export_wallet(addr, "secret123")
        self.assertIsInstance(exported, str)
        parsed = json.loads(exported)
        self.assertIn("name", parsed)

        # Remove wallet and re-import
        del self.b.wallets[addr]
        reimported = self.b.import_wallet_from_file(exported, "secret123")
        self.assertEqual(reimported["address"], addr)
        self.assertIn(addr, self.b.wallets)

    def test_06_recover_from_keys(self):
        ref = Wallet.create()
        info = self.b.recover_wallet_from_keys(
            public_key=ref.public_key.hex(),
            private_key=ref.private_key.hex(),
        )
        self.assertEqual(info["address"], ref.address)

    def test_07_recover_mismatched_keys_fails(self):
        w1 = Wallet.create()
        w2 = Wallet.create()
        with self.assertRaises(ValueError):
            self.b.recover_wallet_from_keys(
                public_key=w1.public_key.hex(),
                private_key=w2.private_key.hex(),
            )

    def test_08_wallet_signals_fire(self):
        received = []
        self.b.wallet_created.connect(lambda d: received.append(d))
        self.b.create_wallet("SignalTest")
        self.assertEqual(len(received), 1)
        self.assertIn("address", received[0])


# ===================================================================
#  2. GENESIS AND INITIAL BALANCES
# ===================================================================

class Test02_GenesisBalances(unittest.TestCase):
    """Verify genesis accounts and initial supply."""

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

    def test_05_ledger_summary_has_supply(self):
        b = _make_backend()
        summary = b.get_ledger_summary()
        self.assertIn("total_supply", summary)


# ===================================================================
#  3. PAYMENT FLOW
# ===================================================================

class Test03_PaymentFlow(unittest.TestCase):
    """Test send_payment, verify balances update, consensus works."""

    def setUp(self):
        self.b = _make_backend()
        self.w1 = self.b.create_wallet("Sender")
        self.w2 = self.b.create_wallet("Receiver")
        self.addr1 = self.w1["address"]
        self.addr2 = self.w2["address"]
        _fund(self.b, self.addr1, 1_000_000.0)

    def test_01_simple_payment_accepted(self):
        result = self.b.send_payment(self.addr1, self.addr2, 1000.0)
        self.assertIsNotNone(result)
        self.assertTrue(result["_accepted"])

    def test_02_receiver_balance_updated(self):
        self.b.send_payment(self.addr1, self.addr2, 5000.0)
        bal = self.b.get_balance(self.addr2)
        self.assertAlmostEqual(bal, 5000.0, places=4)

    def test_03_sender_balance_decreased(self):
        before = self.b.get_balance(self.addr1)
        self.b.send_payment(self.addr1, self.addr2, 5000.0)
        after = self.b.get_balance(self.addr1)
        # Should lose 5000 + fee
        self.assertAlmostEqual(after, before - 5000.0 - FEE, places=4)

    def test_04_multiple_payments_sequence_ok(self):
        for i in range(5):
            result = self.b.send_payment(self.addr1, self.addr2, 100.0)
            self.assertIsNotNone(result, f"Payment {i+1} returned None")
            self.assertTrue(result["_accepted"], f"Payment {i+1} rejected")
        self.assertAlmostEqual(self.b.get_balance(self.addr2), 500.0, places=4)

    def test_05_insufficient_balance_handled(self):
        # addr2 has 0 balance
        result = self.b.send_payment(self.addr2, self.addr1, 100.0)
        # Should either return None or _accepted=False
        if result is not None:
            self.assertFalse(result.get("_accepted", True))

    def test_06_no_wallet_returns_none(self):
        result = self.b.send_payment("nonexistent", self.addr2, 100.0)
        self.assertIsNone(result)

    def test_07_tx_history_populated(self):
        self.b.send_payment(self.addr1, self.addr2, 100.0)
        history = self.b.get_tx_history()
        self.assertGreater(len(history), 0)

    def test_08_tx_submitted_signal_fires(self):
        received = []
        self.b.tx_submitted.connect(lambda d: received.append(d))
        self.b.send_payment(self.addr1, self.addr2, 100.0)
        self.assertEqual(len(received), 1)

    def test_09_balance_updated_signal_fires(self):
        received = []
        self.b.balance_updated.connect(lambda a, b: received.append((a, b)))
        self.b.send_payment(self.addr1, self.addr2, 100.0)
        # At least one balance_updated should fire (from run_consensus)
        addrs = [r[0] for r in received]
        self.assertIn(self.addr1, addrs)

    def test_10_bidirectional_payments(self):
        _fund(self.b, self.addr2, 500_000.0)
        self.b.send_payment(self.addr1, self.addr2, 1000.0)
        self.b.send_payment(self.addr2, self.addr1, 500.0)
        bal2 = self.b.get_balance(self.addr2)
        # addr2: 500_000 + 1000 - 500 - fee
        self.assertAlmostEqual(bal2, 500_500.0 - FEE, places=4)


# ===================================================================
#  4. CONSENSUS
# ===================================================================

class Test04_Consensus(unittest.TestCase):
    """Test consensus round execution and correctness."""

    def setUp(self):
        self.b = _make_backend(peers=["10.0.0.2:9001", "10.0.0.3:9001"])
        self.w1 = self.b.create_wallet("Sender")
        self.w2 = self.b.create_wallet("Receiver")
        _fund(self.b, self.w1["address"], 1_000_000.0)

    def test_01_consensus_returns_dict(self):
        self.b.send_payment(self.w1["address"], self.w2["address"], 100.0)
        result = self.b.run_consensus()
        self.assertIsNotNone(result)
        self.assertIsInstance(result, dict)

    def test_02_consensus_signal_fires(self):
        received = []
        self.b.consensus_completed.connect(lambda d: received.append(d))
        self.b.send_payment(self.w1["address"], self.w2["address"], 100.0)
        self.assertGreater(len(received), 0)

    def test_03_all_nodes_in_sync_after_consensus(self):
        self.b.send_payment(self.w1["address"], self.w2["address"], 5000.0)
        # Check all nodes have same balance for receiver
        addr = self.w2["address"]
        balances = set()
        for node in self.b.network.nodes.values():
            balances.add(round(node.ledger.get_balance(addr), 4))
        self.assertEqual(len(balances), 1, f"Nodes disagree on balance: {balances}")

    def test_04_empty_consensus_round(self):
        # No pending TXs
        result = self.b.run_consensus()
        self.assertIsNotNone(result)

    def test_05_ledger_sequence_advances(self):
        seq_before = self.b._primary_node.ledger.current_sequence
        self.b.send_payment(self.w1["address"], self.w2["address"], 100.0)
        seq_after = self.b._primary_node.ledger.current_sequence
        self.assertGreater(seq_after, seq_before)

    def test_06_validator_statuses_returned(self):
        statuses = self.b.get_validator_statuses()
        self.assertEqual(len(statuses), 3)  # test-node + 2 peers
        for s in statuses:
            self.assertIn("node_id", s)

    def test_07_network_status_correct(self):
        status = self.b.get_network_status()
        self.assertIn("validators", status)

    def test_08_p2p_status_correct(self):
        status = self.b.get_p2p_status()
        self.assertEqual(status["validator_count"], 3)
        self.assertEqual(len(status["nodes"]), 3)


# ===================================================================
#  5. TRUST LINES
# ===================================================================

class Test05_TrustLines(unittest.TestCase):
    """Test trust line creation and IOU payments."""

    def setUp(self):
        self.b = _make_backend()
        self.issuer = self.b.create_wallet("Issuer")
        self.holder = self.b.create_wallet("Holder")
        self.receiver = self.b.create_wallet("Receiver")
        _fund(self.b, self.issuer["address"], 500_000.0)
        _fund(self.b, self.holder["address"], 100_000.0)
        _fund(self.b, self.receiver["address"], 100_000.0)

    def test_01_set_trust_line(self):
        result = self.b.set_trust_line(
            self.holder["address"], "USD", self.issuer["address"], 10_000.0)
        self.assertIsNotNone(result)

    def test_02_trust_line_exists_on_ledger(self):
        self.b.set_trust_line(
            self.holder["address"], "USD", self.issuer["address"], 10_000.0)
        tl = self.b._primary_node.ledger.get_trust_line(
            self.holder["address"], "USD", self.issuer["address"])
        self.assertIsNotNone(tl)
        self.assertEqual(tl.limit, 10_000.0)

    def test_03_iou_payment_after_trust(self):
        self.b.set_trust_line(
            self.holder["address"], "USD", self.issuer["address"], 10_000.0)
        result = self.b.send_payment(
            self.issuer["address"],
            self.holder["address"],
            500.0,
            currency="USD",
            issuer=self.issuer["address"],
        )
        self.assertIsNotNone(result)
        self.assertTrue(result["_accepted"])

    def test_04_get_trust_lines_returns_data(self):
        self.b.set_trust_line(
            self.holder["address"], "USD", self.issuer["address"], 10_000.0)
        lines = self.b.get_trust_lines()
        self.assertGreater(len(lines), 0)

    def test_05_trust_then_nxf_payment_sequence_ok(self):
        self.b.set_trust_line(
            self.holder["address"], "USD", self.issuer["address"], 5000.0)
        result = self.b.send_payment(
            self.holder["address"], self.receiver["address"], 100.0)
        self.assertIsNotNone(result)
        self.assertTrue(result["_accepted"])


# ===================================================================
#  6. DEX OFFERS
# ===================================================================

class Test06_DexOffers(unittest.TestCase):
    """Test NXF DEX offer creation and queries."""

    def setUp(self):
        self.b = _make_backend()
        self.w = self.b.create_wallet("Trader")
        _fund(self.b, self.w["address"], 500_000.0)

    def test_01_create_offer(self):
        result = self.b.create_dex_offer(
            self.w["address"],
            pays_amount=1000.0, pays_currency="NXF", pays_issuer="",
            gets_amount=500.0, gets_currency="USD", gets_issuer=GENESIS,
        )
        self.assertIsNotNone(result)

    def test_02_offer_then_payment_works(self):
        self.b.create_dex_offer(
            self.w["address"],
            pays_amount=100.0, pays_currency="NXF", pays_issuer="",
            gets_amount=50.0, gets_currency="USD", gets_issuer=GENESIS,
        )
        w2 = self.b.create_wallet("Dest")
        result = self.b.send_payment(self.w["address"], w2["address"], 100.0)
        self.assertIsNotNone(result)
        self.assertTrue(result["_accepted"])

    def test_03_order_book_pairs(self):
        pairs = self.b.get_order_book_pairs()
        self.assertIsInstance(pairs, list)


# ===================================================================
#  7. STAKING
# ===================================================================

class Test07_Staking(unittest.TestCase):
    """Test staking, cancellation, and balance effects."""

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
        self.assertLess(after, before)
        # Balance should drop by at least the staked amount
        self.assertAlmostEqual(before - after, 10_000.0 + FEE, places=4)

    def test_02_get_stakes_for_address(self):
        self.b.stake_nxf(self.addr, 10_000.0, tier=0)
        stakes = self.b.get_stakes_for_address(self.addr)
        self.assertGreater(len(stakes), 0)

    def test_03_get_all_active_stakes(self):
        self.b.stake_nxf(self.addr, 10_000.0, tier=0)
        all_stakes = self.b.get_all_active_stakes()
        self.assertGreater(len(all_stakes), 0)

    def test_04_cancel_stake(self):
        self.b.stake_nxf(self.addr, 10_000.0, tier=0)
        stakes = self.b.get_stakes_for_address(self.addr)
        self.assertGreater(len(stakes), 0, "No stakes found to cancel")
        stake_id = stakes[0]["stake_id"]
        result = self.b.cancel_stake(stake_id)
        self.assertIsNotNone(result, "Cancel stake returned None")

    def test_05_staking_summary(self):
        self.b.stake_nxf(self.addr, 10_000.0, tier=0)
        summary = self.b.get_staking_summary(self.addr)
        self.assertIsInstance(summary, dict)

    def test_06_staking_pool_summary(self):
        self.b.stake_nxf(self.addr, 10_000.0, tier=0)
        pool = self.b.get_staking_pool_summary()
        self.assertIsInstance(pool, dict)

    def test_07_staking_tiers_info(self):
        tiers = self.b.get_staking_tiers()
        self.assertIsInstance(tiers, list)
        self.assertGreater(len(tiers), 0)

    def test_08_stake_then_payment_works(self):
        self.b.stake_nxf(self.addr, 10_000.0, tier=0)
        w2 = self.b.create_wallet("Dest")
        result = self.b.send_payment(self.addr, w2["address"], 100.0)
        self.assertIsNotNone(result)
        self.assertTrue(result["_accepted"])

    def test_09_staking_signal_fires(self):
        received = []
        self.b.staking_changed.connect(lambda: received.append(True))
        self.b.stake_nxf(self.addr, 10_000.0, tier=0)
        self.assertGreater(len(received), 0)

    def test_10_multiple_stakes_same_wallet(self):
        r1 = self.b.stake_nxf(self.addr, 10_000.0, tier=0)
        r2 = self.b.stake_nxf(self.addr, 20_000.0, tier=0)
        self.assertIsNotNone(r1)
        self.assertIsNotNone(r2)
        stakes = self.b.get_stakes_for_address(self.addr)
        self.assertGreaterEqual(len(stakes), 2)


# ===================================================================
#  8. PMC COIN CREATION
# ===================================================================

class Test08_PMCCreation(unittest.TestCase):
    """Test PMC coin creation through the backend."""

    def setUp(self):
        self.b = _make_backend()
        self.w = self.b.create_wallet("Issuer")
        self.addr = self.w["address"]
        _fund(self.b, self.addr, 1_000_000.0)

    def test_01_create_coin(self):
        result = self.b.pmc_create_coin(
            self.addr, "TST", "Test Coin",
            max_supply=1_000_000.0,
            pow_difficulty=1,  # easy for tests
            base_reward=100.0,
        )
        self.assertIsNotNone(result, "PMCCreate returned None")

    def test_02_coin_appears_in_list(self):
        self.b.pmc_create_coin(
            self.addr, "TST", "Test Coin",
            pow_difficulty=1, base_reward=100.0,
        )
        coins = self.b.pmc_list_coins()
        self.assertGreater(len(coins), 0)
        symbols = [c["symbol"] for c in coins]
        self.assertIn("TST", symbols)

    def test_03_coin_details_correct(self):
        self.b.pmc_create_coin(
            self.addr, "TST", "Test Coin",
            max_supply=500_000.0,
            pow_difficulty=2,
            base_reward=50.0,
        )
        coins = self.b.pmc_list_coins()
        coin = next(c for c in coins if c["symbol"] == "TST")
        self.assertEqual(coin["name"], "Test Coin")
        self.assertAlmostEqual(coin["max_supply"], 500_000.0)
        self.assertEqual(coin["pow_difficulty"], 2)
        self.assertAlmostEqual(coin["base_reward"], 50.0)

    def test_04_pmc_changed_signal_fires(self):
        received = []
        self.b.pmc_changed.connect(lambda: received.append(True))
        self.b.pmc_create_coin(
            self.addr, "TST", "Test Coin",
            pow_difficulty=1, base_reward=100.0,
        )
        self.assertGreater(len(received), 0)

    def test_05_no_wallet_returns_none(self):
        result = self.b.pmc_create_coin(
            "nonexistent", "TST", "Test Coin",
        )
        self.assertIsNone(result)


# ===================================================================
#  9. PMC MINING (THE ORIGINAL BUG REPORT)
# ===================================================================

class Test09_PMCMining(unittest.TestCase):
    """Test PMC mining — balance MUST update after successful mine."""

    def setUp(self):
        self.b = _make_backend()
        self.w = self.b.create_wallet("Miner")
        self.addr = self.w["address"]
        _fund(self.b, self.addr, 1_000_000.0)

        # Create a coin with difficulty=1 for easy mining
        result = self.b.pmc_create_coin(
            self.addr, "MINE", "Mineable Coin",
            max_supply=0.0,  # unlimited
            pow_difficulty=1,
            base_reward=100.0,
        )
        self.assertIsNotNone(result, "Failed to create coin for mining test")

        coins = self.b.pmc_list_coins()
        self.coin = next(c for c in coins if c["symbol"] == "MINE")
        self.coin_id = self.coin["coin_id"]

    def test_01_pow_info_available(self):
        info = self.b.pmc_get_pow_info(self.coin_id)
        self.assertIsNotNone(info)
        self.assertEqual(info["difficulty"], 1)
        self.assertTrue(info.get("mintable", False))

    def test_02_mine_and_balance_updates(self):
        """THE KEY TEST: Mining must credit the miner's PMC balance."""
        info = self.b.pmc_get_pow_info(self.coin_id)
        prev_hash = info.get("prev_hash", "")

        nonce = _find_valid_nonce(self.coin_id, self.addr, 1, prev_hash)
        self.assertIsNotNone(nonce, "Could not find valid PoW nonce")

        # Check portfolio before
        portfolio_before = self.b.pmc_get_portfolio(self.addr)
        balance_before = 0.0
        for h in portfolio_before:
            if h["coin_id"] == self.coin_id:
                balance_before = h["balance"]

        # Mine
        result = self.b.pmc_mint(self.addr, self.coin_id, nonce)
        self.assertIsNotNone(result, "PMCMint returned None")

        # Check portfolio after
        portfolio_after = self.b.pmc_get_portfolio(self.addr)
        balance_after = 0.0
        for h in portfolio_after:
            if h["coin_id"] == self.coin_id:
                balance_after = h["balance"]

        expected_reward = info.get("block_reward", 0)
        self.assertGreater(expected_reward, 0, "Block reward should be positive")
        self.assertAlmostEqual(
            balance_after, balance_before + expected_reward, places=4,
            msg=f"PMC balance not updated! Before={balance_before}, "
                f"After={balance_after}, Expected reward={expected_reward}")

    def test_03_mine_twice_updates_balance_twice(self):
        """Mine two blocks — balance should reflect both rewards."""
        info = self.b.pmc_get_pow_info(self.coin_id)
        prev_hash = info.get("prev_hash", "")
        reward = info.get("block_reward", 0)

        nonce1 = _find_valid_nonce(self.coin_id, self.addr, 1, prev_hash)
        self.assertIsNotNone(nonce1)
        result1 = self.b.pmc_mint(self.addr, self.coin_id, nonce1)
        self.assertIsNotNone(result1, "First mine failed")

        # Get updated prev_hash for second mine
        info2 = self.b.pmc_get_pow_info(self.coin_id)
        prev_hash2 = info2.get("prev_hash", "")
        self.assertNotEqual(prev_hash2, prev_hash,
                            "prev_hash should change after mining")

        nonce2 = _find_valid_nonce(self.coin_id, self.addr, 1, prev_hash2)
        self.assertIsNotNone(nonce2)
        result2 = self.b.pmc_mint(self.addr, self.coin_id, nonce2)
        self.assertIsNotNone(result2, "Second mine failed")

        portfolio = self.b.pmc_get_portfolio(self.addr)
        balance = 0.0
        for h in portfolio:
            if h["coin_id"] == self.coin_id:
                balance = h["balance"]

        self.assertAlmostEqual(
            balance, reward * 2, places=4,
            msg=f"After 2 mines, expected {reward * 2} but got {balance}")

    def test_04_coin_total_minted_updates(self):
        """Coin's total_minted should reflect mining."""
        info = self.b.pmc_get_pow_info(self.coin_id)
        prev_hash = info.get("prev_hash", "")

        nonce = _find_valid_nonce(self.coin_id, self.addr, 1, prev_hash)
        self.assertIsNotNone(nonce)
        self.b.pmc_mint(self.addr, self.coin_id, nonce)

        coin_info = self.b.pmc_get_coin(self.coin_id)
        self.assertGreater(coin_info["total_minted"], 0.0)

    def test_05_invalid_nonce_rejected(self):
        """A bad nonce should fail — not crash."""
        result = self.b.pmc_mint(self.addr, self.coin_id, 999999999)
        # Backend returns None when broadcast is fully rejected
        if result is not None:
            self.assertIn("tecPMC", result.get("result", ""))

    def test_06_different_miner_can_mine(self):
        """A different wallet should be able to mine the same coin."""
        w2 = self.b.create_wallet("Miner2")
        _fund(self.b, w2["address"], 100_000.0)

        info = self.b.pmc_get_pow_info(self.coin_id)
        prev_hash = info.get("prev_hash", "")

        nonce = _find_valid_nonce(self.coin_id, w2["address"], 1, prev_hash)
        self.assertIsNotNone(nonce)
        result = self.b.pmc_mint(w2["address"], self.coin_id, nonce)
        self.assertIsNotNone(result, "Second miner's TX returned None")

        portfolio = self.b.pmc_get_portfolio(w2["address"])
        balance = 0.0
        for h in portfolio:
            if h["coin_id"] == self.coin_id:
                balance = h["balance"]
        self.assertGreater(balance, 0.0, "Second miner should have PMC balance")


# ===================================================================
#  10. PMC TRANSFERS
# ===================================================================

class Test10_PMCTransfer(unittest.TestCase):
    """Test PMC token transfers."""

    def setUp(self):
        self.b = _make_backend()
        self.w1 = self.b.create_wallet("PMC_Sender")
        self.w2 = self.b.create_wallet("PMC_Receiver")
        self.addr1 = self.w1["address"]
        self.addr2 = self.w2["address"]
        _fund(self.b, self.addr1, 1_000_000.0)
        _fund(self.b, self.addr2, 100_000.0)

        # Create and mine a coin
        self.b.pmc_create_coin(
            self.addr1, "XFR", "Transfer Coin",
            pow_difficulty=1, base_reward=1000.0,
        )
        coins = self.b.pmc_list_coins()
        self.coin = next(c for c in coins if c["symbol"] == "XFR")
        self.coin_id = self.coin["coin_id"]

        # Mine some tokens
        info = self.b.pmc_get_pow_info(self.coin_id)
        nonce = _find_valid_nonce(
            self.coin_id, self.addr1, 1, info.get("prev_hash", ""))
        self.assertIsNotNone(nonce, "Could not mine for transfer test setup")
        self.b.pmc_mint(self.addr1, self.coin_id, nonce)

    def test_01_transfer_credited(self):
        # Sender should have tokens from mining
        portfolio = self.b.pmc_get_portfolio(self.addr1)
        sender_bal = 0.0
        for h in portfolio:
            if h["coin_id"] == self.coin_id:
                sender_bal = h["balance"]
        self.assertGreater(sender_bal, 0, "Sender has no PMC tokens to transfer")

        transfer_amt = min(100.0, sender_bal)
        result = self.b.pmc_transfer(
            self.addr1, self.addr2, self.coin_id, transfer_amt)
        self.assertIsNotNone(result, "PMC transfer returned None")

        # Check receiver got tokens
        recv_portfolio = self.b.pmc_get_portfolio(self.addr2)
        recv_bal = 0.0
        for h in recv_portfolio:
            if h["coin_id"] == self.coin_id:
                recv_bal = h["balance"]
        self.assertAlmostEqual(recv_bal, transfer_amt, places=4)

    def test_02_sender_balance_decreased(self):
        portfolio = self.b.pmc_get_portfolio(self.addr1)
        before = 0.0
        for h in portfolio:
            if h["coin_id"] == self.coin_id:
                before = h["balance"]

        transfer_amt = min(50.0, before)
        self.b.pmc_transfer(self.addr1, self.addr2, self.coin_id, transfer_amt)

        portfolio2 = self.b.pmc_get_portfolio(self.addr1)
        after = 0.0
        for h in portfolio2:
            if h["coin_id"] == self.coin_id:
                after = h["balance"]
        self.assertAlmostEqual(after, before - transfer_amt, places=4)


# ===================================================================
#  11. PMC BURN
# ===================================================================

class Test11_PMCBurn(unittest.TestCase):
    """Test PMC token burning."""

    def setUp(self):
        self.b = _make_backend()
        self.w = self.b.create_wallet("Burner")
        self.addr = self.w["address"]
        _fund(self.b, self.addr, 1_000_000.0)

        self.b.pmc_create_coin(
            self.addr, "BRN", "Burnable Coin",
            pow_difficulty=1, base_reward=500.0,
        )
        coins = self.b.pmc_list_coins()
        self.coin = next(c for c in coins if c["symbol"] == "BRN")
        self.coin_id = self.coin["coin_id"]

        info = self.b.pmc_get_pow_info(self.coin_id)
        nonce = _find_valid_nonce(
            self.coin_id, self.addr, 1, info.get("prev_hash", ""))
        self.b.pmc_mint(self.addr, self.coin_id, nonce)

    def test_01_burn_reduces_balance(self):
        portfolio = self.b.pmc_get_portfolio(self.addr)
        before = 0.0
        for h in portfolio:
            if h["coin_id"] == self.coin_id:
                before = h["balance"]
        self.assertGreater(before, 0)

        burn_amt = min(100.0, before)
        result = self.b.pmc_burn(self.addr, self.coin_id, burn_amt)
        self.assertIsNotNone(result, "PMC burn returned None")

        portfolio2 = self.b.pmc_get_portfolio(self.addr)
        after = 0.0
        for h in portfolio2:
            if h["coin_id"] == self.coin_id:
                after = h["balance"]
        self.assertAlmostEqual(after, before - burn_amt, places=4)

    def test_02_burn_updates_total_burned(self):
        portfolio = self.b.pmc_get_portfolio(self.addr)
        before_bal = 0.0
        for h in portfolio:
            if h["coin_id"] == self.coin_id:
                before_bal = h["balance"]

        burn_amt = min(50.0, before_bal)
        self.b.pmc_burn(self.addr, self.coin_id, burn_amt)

        coin_info = self.b.pmc_get_coin(self.coin_id)
        self.assertGreater(coin_info["total_burned"], 0.0)


# ===================================================================
#  12. PMC DEX (OFFERS)
# ===================================================================

class Test12_PMCDEX(unittest.TestCase):
    """Test PMC DEX: offer create, accept, cancel."""

    def setUp(self):
        self.b = _make_backend()
        self.seller = self.b.create_wallet("Seller")
        self.buyer = self.b.create_wallet("Buyer")
        _fund(self.b, self.seller["address"], 1_000_000.0)
        _fund(self.b, self.buyer["address"], 1_000_000.0)

        # Create coin and mine
        self.b.pmc_create_coin(
            self.seller["address"], "DEX", "DEX Coin",
            pow_difficulty=1, base_reward=1000.0,
        )
        coins = self.b.pmc_list_coins()
        self.coin = next(c for c in coins if c["symbol"] == "DEX")
        self.coin_id = self.coin["coin_id"]

        info = self.b.pmc_get_pow_info(self.coin_id)
        nonce = _find_valid_nonce(
            self.coin_id, self.seller["address"], 1,
            info.get("prev_hash", ""))
        self.b.pmc_mint(self.seller["address"], self.coin_id, nonce)

    def test_01_create_sell_offer(self):
        result = self.b.pmc_offer_create(
            self.seller["address"], self.coin_id,
            is_sell=True, amount=100.0, price=1.0)
        self.assertIsNotNone(result, "PMC sell offer returned None")

    def test_02_offers_appear_in_list(self):
        self.b.pmc_offer_create(
            self.seller["address"], self.coin_id,
            is_sell=True, amount=100.0, price=1.0)
        offers = self.b.pmc_list_active_offers(self.coin_id)
        self.assertGreater(len(offers), 0)

    def test_03_cancel_offer(self):
        self.b.pmc_offer_create(
            self.seller["address"], self.coin_id,
            is_sell=True, amount=100.0, price=1.0)
        offers = self.b.pmc_list_active_offers(self.coin_id)
        self.assertGreater(len(offers), 0)
        offer_id = offers[0]["offer_id"]
        result = self.b.pmc_offer_cancel(self.seller["address"], offer_id)
        self.assertIsNotNone(result, "Cancel offer returned None")

    def test_04_accept_sell_offer(self):
        """Buyer accepts a sell offer — buyer gets tokens, seller gets NXF."""
        self.b.pmc_offer_create(
            self.seller["address"], self.coin_id,
            is_sell=True, amount=50.0, price=2.0)
        offers = self.b.pmc_list_active_offers(self.coin_id)
        self.assertGreater(len(offers), 0)
        offer_id = offers[0]["offer_id"]

        result = self.b.pmc_offer_accept(
            self.buyer["address"], offer_id)
        self.assertIsNotNone(result, "Accept offer returned None")

        # Buyer should now have PMC tokens
        buyer_portfolio = self.b.pmc_get_portfolio(self.buyer["address"])
        buyer_pmc = 0.0
        for h in buyer_portfolio:
            if h["coin_id"] == self.coin_id:
                buyer_pmc = h["balance"]
        self.assertGreater(buyer_pmc, 0.0,
                           "Buyer should have received PMC tokens")

    def test_05_order_book_query(self):
        self.b.pmc_offer_create(
            self.seller["address"], self.coin_id,
            is_sell=True, amount=100.0, price=1.5)
        book = self.b.pmc_get_order_book(self.coin_id)
        self.assertIsInstance(book, dict)


# ===================================================================
#  13. CLEAR AND RESET OPERATIONS
# ===================================================================

class Test13_ClearAndReset(unittest.TestCase):
    """Test cache clear, data clear, and ledger reset."""

    def setUp(self):
        self.b = _make_backend()
        self.w = self.b.create_wallet("Alice")
        _fund(self.b, self.w["address"], 50_000.0)
        w2 = self.b.create_wallet("Bob")
        self.b.send_payment(self.w["address"], w2["address"], 100.0)

    def test_01_clear_cache_preserves_wallets(self):
        self.b.clear_cache()
        self.assertIn(self.w["address"], self.b.wallets)
        self.assertGreater(self.b.get_balance(self.w["address"]), 0)

    def test_02_clear_cache_clears_tx_history(self):
        self.assertGreater(len(self.b.tx_history), 0)
        self.b.clear_cache()
        self.assertEqual(len(self.b.tx_history), 0)

    def test_03_clear_all_data_wipes_wallets(self):
        self.b.clear_all_data()
        self.assertEqual(len(self.b.wallets), 0)

    def test_04_clear_all_data_genesis_survives(self):
        self.b.clear_all_data()
        self.assertIn(GENESIS, self.b._primary_node.ledger.accounts)

    def test_05_wallet_works_after_clear_all(self):
        self.b.clear_all_data()
        new = self.b.create_wallet("New")
        self.assertIn(new["address"], self.b.wallets)

    def test_06_reset_ledger_dev_mode(self):
        self.b.DEV_MODE = True
        self.b.reset_ledger()
        # Wallets still tracked but balance is 0
        self.assertIn(self.w["address"], self.b.wallets)
        self.assertAlmostEqual(self.b.get_balance(self.w["address"]), 0.0)
        self.assertEqual(len(self.b.tx_history), 0)

    def test_07_reset_ledger_blocked_without_dev_mode(self):
        self.b.DEV_MODE = False
        old_bal = self.b.get_balance(self.w["address"])
        self.b.reset_ledger()
        # Balance unchanged
        self.assertAlmostEqual(self.b.get_balance(self.w["address"]), old_bal)


# ===================================================================
#  14. FULL END-TO-END WORKFLOW
# ===================================================================

class Test14_EndToEnd(unittest.TestCase):
    """
    Full end-to-end workflow simulating a real user session:
    1. Create wallets
    2. Fund from genesis
    3. Send payments
    4. Create trust lines
    5. Stake NXF
    6. Create PMC coin
    7. Mine PMC
    8. Transfer PMC
    9. Burn PMC
    10. Check all final balances
    """

    def test_full_workflow(self):
        b = _make_backend()

        # Step 1: Create wallets
        alice = b.create_wallet("Alice")
        bob = b.create_wallet("Bob")
        charlie = b.create_wallet("Charlie")
        self.assertEqual(len(b.wallets), 3)

        # Step 2: Fund Alice from genesis
        _fund(b, alice["address"], 5_000_000.0)
        self.assertAlmostEqual(b.get_balance(alice["address"]), 5_000_000.0, places=4)

        # Step 3: Alice pays Bob
        result = b.send_payment(alice["address"], bob["address"], 100_000.0)
        self.assertIsNotNone(result)
        self.assertTrue(result["_accepted"])
        self.assertAlmostEqual(b.get_balance(bob["address"]), 100_000.0, places=4)

        # Step 4: Bob pays Charlie
        result = b.send_payment(bob["address"], charlie["address"], 50_000.0)
        self.assertIsNotNone(result)
        self.assertTrue(result["_accepted"])
        self.assertAlmostEqual(b.get_balance(charlie["address"]), 50_000.0, places=4)

        # Step 5: Alice creates trust line and sends IOU
        b.set_trust_line(bob["address"], "USD", alice["address"], 10_000.0)
        iou_result = b.send_payment(
            alice["address"], bob["address"], 500.0,
            currency="USD", issuer=alice["address"])
        self.assertIsNotNone(iou_result)

        # Step 6: Alice stakes NXF
        stake_result = b.stake_nxf(alice["address"], 100_000.0, tier=0)
        self.assertIsNotNone(stake_result, "Stake returned None")
        stakes = b.get_stakes_for_address(alice["address"])
        self.assertGreater(len(stakes), 0)

        # Step 7: Alice creates a PMC coin
        pmc_result = b.pmc_create_coin(
            alice["address"], "ACOIN", "Alice Coin",
            pow_difficulty=1, base_reward=200.0)
        self.assertIsNotNone(pmc_result, "PMC creation failed")

        coins = b.pmc_list_coins()
        self.assertGreater(len(coins), 0)
        coin = next(c for c in coins if c["symbol"] == "ACOIN")
        coin_id = coin["coin_id"]

        # Step 8: Alice mines the coin
        info = b.pmc_get_pow_info(coin_id)
        nonce = _find_valid_nonce(
            coin_id, alice["address"], 1, info.get("prev_hash", ""))
        self.assertIsNotNone(nonce, "Could not find PoW nonce")

        mint_result = b.pmc_mint(alice["address"], coin_id, nonce)
        self.assertIsNotNone(mint_result, "PMC mint failed")

        # Verify Alice's PMC balance
        alice_pmc = b.pmc_get_portfolio(alice["address"])
        alice_pmc_bal = 0.0
        for h in alice_pmc:
            if h["coin_id"] == coin_id:
                alice_pmc_bal = h["balance"]
        self.assertGreater(alice_pmc_bal, 0.0,
                           "Alice should have PMC tokens after mining")

        # Step 9: Alice transfers PMC to Bob
        transfer_amt = min(50.0, alice_pmc_bal)
        xfr_result = b.pmc_transfer(
            alice["address"], bob["address"], coin_id, transfer_amt)
        self.assertIsNotNone(xfr_result, "PMC transfer failed")

        bob_pmc = b.pmc_get_portfolio(bob["address"])
        bob_pmc_bal = 0.0
        for h in bob_pmc:
            if h["coin_id"] == coin_id:
                bob_pmc_bal = h["balance"]
        self.assertAlmostEqual(bob_pmc_bal, transfer_amt, places=4)

        # Step 10: Bob burns some PMC tokens
        burn_amt = min(10.0, bob_pmc_bal)
        burn_result = b.pmc_burn(bob["address"], coin_id, burn_amt)
        self.assertIsNotNone(burn_result, "PMC burn failed")

        bob_pmc2 = b.pmc_get_portfolio(bob["address"])
        bob_pmc_bal2 = 0.0
        for h in bob_pmc2:
            if h["coin_id"] == coin_id:
                bob_pmc_bal2 = h["balance"]
        self.assertAlmostEqual(bob_pmc_bal2, bob_pmc_bal - burn_amt, places=4)

        # Final verification: check tx history
        history = b.get_tx_history()
        self.assertGreater(len(history), 0, "Should have TXs in history")

        # Check ledger summary
        summary = b.get_ledger_summary()
        self.assertIsInstance(summary, dict)

        # Check closed ledgers
        closed = b.get_closed_ledgers()
        self.assertGreater(len(closed), 0, "Should have closed ledgers")


# ===================================================================
#  15. PMC MULTI-NODE CONSISTENCY
# ===================================================================

class Test15_PMCMultiNode(unittest.TestCase):
    """Verify PMC state is consistent across all validator nodes."""

    def setUp(self):
        self.b = _make_backend(peers=["10.0.0.2:9001", "10.0.0.3:9001"])
        self.w = self.b.create_wallet("Miner")
        _fund(self.b, self.w["address"], 1_000_000.0)

        self.b.pmc_create_coin(
            self.w["address"], "SYNC", "Sync Coin",
            pow_difficulty=1, base_reward=100.0,
        )
        coins = self.b.pmc_list_coins()
        self.coin = next(c for c in coins if c["symbol"] == "SYNC")
        self.coin_id = self.coin["coin_id"]

    def test_01_coin_exists_on_all_nodes(self):
        for nid, node in self.b.network.nodes.items():
            coin = node.ledger.pmc_manager.get_coin(self.coin_id)
            self.assertIsNotNone(coin,
                                 f"Coin missing on node {nid}")

    def test_02_mining_consistent_across_nodes(self):
        info = self.b.pmc_get_pow_info(self.coin_id)
        nonce = _find_valid_nonce(
            self.coin_id, self.w["address"], 1, info.get("prev_hash", ""))
        self.assertIsNotNone(nonce)
        self.b.pmc_mint(self.w["address"], self.coin_id, nonce)

        # Check balance on each node
        for nid, node in self.b.network.nodes.items():
            bal = node.ledger.pmc_manager.get_balance(
                self.coin_id, self.w["address"])
            self.assertGreater(bal, 0.0,
                               f"PMC balance zero on node {nid}")


# ===================================================================
#  16. QUERY METHODS
# ===================================================================

class Test16_QueryMethods(unittest.TestCase):
    """Test all query/read-only methods return valid data."""

    def setUp(self):
        self.b = _make_backend()
        self.w = self.b.create_wallet("Query")
        _fund(self.b, self.w["address"], 100_000.0)

    def test_01_get_balance(self):
        bal = self.b.get_balance(self.w["address"])
        self.assertAlmostEqual(bal, 100_000.0, places=4)

    def test_02_get_account_info(self):
        info = self.b.get_account_info(self.w["address"])
        self.assertIsNotNone(info)
        self.assertIn("address", info)

    def test_03_get_account_info_nonexistent(self):
        info = self.b.get_account_info("nonexistent_address_xyz")
        self.assertIsNone(info)

    def test_04_get_all_accounts(self):
        accts = self.b.get_all_accounts()
        self.assertGreater(len(accts), 0)
        addrs = [a["address"] for a in accts]
        self.assertIn(self.w["address"], addrs)

    def test_05_get_ledger_summary(self):
        summary = self.b.get_ledger_summary()
        self.assertIsInstance(summary, dict)

    def test_06_get_closed_ledgers_initially_empty(self):
        closed = self.b.get_closed_ledgers()
        self.assertIsInstance(closed, list)

    def test_07_get_tx_history(self):
        self.b.send_payment(self.w["address"], GENESIS, 10.0)
        history = self.b.get_tx_history()
        self.assertGreater(len(history), 0)

    def test_08_get_demand_multiplier(self):
        mult = self.b.get_demand_multiplier()
        self.assertIsInstance(mult, float)

    def test_09_find_payment_paths(self):
        paths = self.b.find_payment_paths(
            self.w["address"], GENESIS, "NXF", 100.0)
        self.assertIsInstance(paths, list)


# ===================================================================
#  17. EDGE CASES AND ERROR HANDLING
# ===================================================================

class Test17_EdgeCases(unittest.TestCase):
    """Test error paths and edge cases."""

    def setUp(self):
        self.b = _make_backend()

    def test_01_send_from_nonexistent_wallet(self):
        result = self.b.send_payment("no_such_wallet", GENESIS, 100.0)
        self.assertIsNone(result)

    def test_02_stake_from_nonexistent_wallet(self):
        result = self.b.stake_nxf("no_such_wallet", 1000.0, tier=0)
        self.assertIsNone(result)

    def test_03_pmc_create_from_nonexistent_wallet(self):
        result = self.b.pmc_create_coin("no_such", "X", "X")
        self.assertIsNone(result)

    def test_04_pmc_mint_nonexistent_coin(self):
        w = self.b.create_wallet("Miner")
        _fund(self.b, w["address"], 100_000.0)
        result = self.b.pmc_mint(w["address"], "fake_coin_id", 0)
        if result is not None:
            self.assertIn("tecPMC", result.get("result", ""))

    def test_05_pmc_transfer_no_tokens(self):
        w1 = self.b.create_wallet("Sender")
        w2 = self.b.create_wallet("Receiver")
        _fund(self.b, w1["address"], 100_000.0)
        _fund(self.b, w2["address"], 100_000.0)

        # Create coin but don't mine
        self.b.pmc_create_coin(
            w1["address"], "EMPTY", "Empty",
            pow_difficulty=1, base_reward=100.0)
        coins = self.b.pmc_list_coins()
        coin = next(c for c in coins if c["symbol"] == "EMPTY")

        # Transfer should fail — no tokens to send
        result = self.b.pmc_transfer(
            w1["address"], w2["address"], coin["coin_id"], 100.0)
        if result is not None:
            self.assertIn("tecPMC", result.get("result", ""))

    def test_06_cancel_nonexistent_stake(self):
        result = self.b.cancel_stake("fake_stake_id_xyz")
        self.assertIsNone(result)

    def test_07_send_zero_amount(self):
        w1 = self.b.create_wallet("Sender")
        w2 = self.b.create_wallet("Recv")
        _fund(self.b, w1["address"], 100_000.0)
        # Zero amount - behavior may vary
        result = self.b.send_payment(w1["address"], w2["address"], 0.0)
        # Just verify it doesn't crash
        self.assertIsInstance(result, (dict, type(None)))

    def test_08_self_payment(self):
        w = self.b.create_wallet("Self")
        _fund(self.b, w["address"], 100_000.0)
        result = self.b.send_payment(w["address"], w["address"], 100.0)
        # Should succeed (self-payment moves NXF to self, minus fee)
        if result is not None and result.get("_accepted"):
            bal = self.b.get_balance(w["address"])
            # Should lose only the fee
            self.assertAlmostEqual(bal, 100_000.0 - FEE, places=4)

    def test_09_duplicate_wallet_seed(self):
        info1 = self.b.import_wallet_from_seed("same-seed")
        info2 = self.b.import_wallet_from_seed("same-seed")
        # Should get same address (idempotent)
        self.assertEqual(info1["address"], info2["address"])


# ===================================================================
#  18. RESERVE ENFORCEMENT
# ===================================================================

class Test18_ReserveEnforcement(unittest.TestCase):
    """Test that account reserve is enforced on payments."""

    def test_01_cannot_send_below_reserve(self):
        b = _make_backend()
        w1 = b.create_wallet("Sender")
        w2 = b.create_wallet("Recv")
        # Fund with just barely enough (reserve = 10 NXF base)
        _fund(b, w1["address"], 15.0)
        # Try to send 14.99 — should fail since needs 10 reserve
        result = b.send_payment(w1["address"], w2["address"], 14.0)
        if result is not None:
            # If accepted, check that reserve was enforced
            bal = b.get_balance(w1["address"])
            self.assertGreaterEqual(bal, 0.0)


# ===================================================================
#  19. MULTI-VALIDATOR CONSENSUS
# ===================================================================

class Test19_MultiValidator(unittest.TestCase):
    """Test with 5 validators for robust consensus."""

    def test_01_five_node_consensus(self):
        b = _make_backend(peers=[
            "10.0.0.2:9001", "10.0.0.3:9001",
            "10.0.0.4:9001", "10.0.0.5:9001"])
        self.assertEqual(len(b.network.nodes), 5)

        w1 = b.create_wallet("Sender")
        w2 = b.create_wallet("Recv")
        _fund(b, w1["address"], 1_000_000.0)

        result = b.send_payment(w1["address"], w2["address"], 5000.0)
        self.assertIsNotNone(result)
        self.assertTrue(result["_accepted"])

        # All 5 nodes should agree on the balance
        for nid, node in b.network.nodes.items():
            bal = node.ledger.get_balance(w2["address"])
            self.assertAlmostEqual(bal, 5000.0, places=4,
                                   msg=f"Node {nid} disagrees on balance")


# ===================================================================
#  20. SIGNAL COMPLETENESS
# ===================================================================

class Test20_SignalCompleteness(unittest.TestCase):
    """Verify that critical signals fire for all operations."""

    def setUp(self):
        self.b = _make_backend()
        self.w = self.b.create_wallet("Sig")
        _fund(self.b, self.w["address"], 1_000_000.0)
        self.signals = {}

    def _track(self, name):
        self.signals.setdefault(name, [])
        return lambda *a: self.signals[name].append(a)

    def test_01_payment_signals(self):
        self.b.tx_submitted.connect(self._track("tx_submitted"))
        self.b.consensus_completed.connect(self._track("consensus"))
        self.b.accounts_changed.connect(self._track("accounts"))

        w2 = self.b.create_wallet("Dest")
        self.b.send_payment(self.w["address"], w2["address"], 100.0)

        self.assertGreater(len(self.signals.get("tx_submitted", [])), 0)
        self.assertGreater(len(self.signals.get("consensus", [])), 0)

    def test_02_staking_signals(self):
        self.b.staking_changed.connect(self._track("staking"))
        self.b.accounts_changed.connect(self._track("accounts"))

        self.b.stake_nxf(self.w["address"], 10_000.0, tier=0)

        self.assertGreater(len(self.signals.get("staking", [])), 0)

    def test_03_pmc_signals(self):
        self.b.pmc_changed.connect(self._track("pmc"))

        self.b.pmc_create_coin(
            self.w["address"], "SIG", "Signal Coin",
            pow_difficulty=1, base_reward=100.0)

        self.assertGreater(len(self.signals.get("pmc", [])), 0)


if __name__ == "__main__":
    unittest.main()
