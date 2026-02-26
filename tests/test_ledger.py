"""
Test suite for nexaflow_core.ledger — Cython-optimized ledger management.

Covers:
  - AccountEntry and TrustLineEntry
  - LedgerHeader hash computation & chaining
  - Ledger account CRUD
  - Trust-line management
  - apply_payment (native NXF + IOU + error paths)
  - apply_trust_set
  - apply_transaction routing
  - close_ledger hash chaining
  - get_balance, get_state_summary
"""

import unittest

from nexaflow_core.ledger import (
    AccountEntry,
    Ledger,
    LedgerHeader,
    TrustLineEntry,
)
from nexaflow_core.transaction import (
    create_payment,
    create_trust_set,
)

# ===================================================================
#  AccountEntry
# ===================================================================


class TestAccountEntry(unittest.TestCase):

    def test_defaults(self):
        acc = AccountEntry("rTest")
        self.assertEqual(acc.address, "rTest")
        self.assertEqual(acc.balance, 0.0)
        self.assertEqual(acc.sequence, 1)
        self.assertEqual(acc.owner_count, 0)
        self.assertFalse(acc.is_gateway)

    def test_initial_balance(self):
        acc = AccountEntry("rRich", 1000.0)
        self.assertEqual(acc.balance, 1000.0)

    def test_to_dict(self):
        acc = AccountEntry("rAcc", 500.0)
        d = acc.to_dict()
        self.assertEqual(d["address"], "rAcc")
        self.assertEqual(d["balance"], 500.0)
        self.assertIn("trust_lines", d)


# ===================================================================
#  TrustLineEntry
# ===================================================================


class TestTrustLineEntry(unittest.TestCase):

    def test_defaults(self):
        tl = TrustLineEntry("USD", "rIssuer", "rHolder", 1000.0)
        self.assertEqual(tl.currency, "USD")
        self.assertEqual(tl.issuer, "rIssuer")
        self.assertEqual(tl.holder, "rHolder")
        self.assertEqual(tl.balance, 0.0)
        self.assertEqual(tl.limit, 1000.0)

    def test_to_dict(self):
        tl = TrustLineEntry("EUR", "rBank", "rUser", 500.0)
        tl.balance = 100.0
        d = tl.to_dict()
        self.assertEqual(d["currency"], "EUR")
        self.assertEqual(d["balance"], 100.0)


# ===================================================================
#  LedgerHeader
# ===================================================================


class TestLedgerHeader(unittest.TestCase):

    def test_defaults(self):
        hdr = LedgerHeader(1)
        self.assertEqual(hdr.sequence, 1)
        self.assertEqual(hdr.parent_hash, "0" * 64)
        self.assertEqual(hdr.hash, "")

    def test_compute_hash_fills(self):
        hdr = LedgerHeader(1)
        hdr.tx_hash = "a" * 64
        hdr.state_hash = "b" * 64
        hdr.total_nxf = 100e9
        hdr.compute_hash()
        self.assertEqual(len(hdr.hash), 64)

    def test_hash_deterministic(self):
        h1 = LedgerHeader(5, "parent")
        h1.close_time = 1000
        h1.tx_hash = "tx"
        h1.state_hash = "st"
        h1.tx_count = 3
        h1.total_nxf = 1e9
        h1.compute_hash()

        h2 = LedgerHeader(5, "parent")
        h2.close_time = 1000
        h2.tx_hash = "tx"
        h2.state_hash = "st"
        h2.tx_count = 3
        h2.total_nxf = 1e9
        h2.compute_hash()

        self.assertEqual(h1.hash, h2.hash)

    def test_different_fields_different_hash(self):
        h1 = LedgerHeader(1)
        h1.close_time = 100
        h1.tx_hash = "a"
        h1.state_hash = "b"
        h1.compute_hash()

        h2 = LedgerHeader(2)
        h2.close_time = 100
        h2.tx_hash = "a"
        h2.state_hash = "b"
        h2.compute_hash()

        self.assertNotEqual(h1.hash, h2.hash)

    def test_to_dict(self):
        hdr = LedgerHeader(10)
        d = hdr.to_dict()
        self.assertEqual(d["sequence"], 10)
        self.assertIn("hash", d)


# ===================================================================
#  Ledger — account management
# ===================================================================


class TestLedgerAccounts(unittest.TestCase):

    def setUp(self):
        self.ledger = Ledger(total_supply=1000.0, genesis_account="rGen")

    def test_genesis_created(self):
        self.assertTrue(self.ledger.account_exists("rGen"))
        self.assertEqual(self.ledger.get_balance("rGen"), 1000.0)

    def test_create_account(self):
        acc = self.ledger.create_account("rAlice", 100.0)
        self.assertEqual(acc.address, "rAlice")
        self.assertEqual(acc.balance, 100.0)

    def test_create_account_idempotent(self):
        self.ledger.create_account("rBob", 50.0)
        acc = self.ledger.create_account("rBob", 999.0)
        # Should return existing, not overwrite
        self.assertEqual(acc.balance, 50.0)

    def test_get_account_nonexistent(self):
        self.assertIsNone(self.ledger.get_account("rNobody"))

    def test_account_exists(self):
        self.assertFalse(self.ledger.account_exists("rNew"))
        self.ledger.create_account("rNew")
        self.assertTrue(self.ledger.account_exists("rNew"))

    def test_get_balance_nonexistent(self):
        self.assertEqual(self.ledger.get_balance("rGhost"), 0.0)


# ===================================================================
#  Ledger — trust-line management
# ===================================================================


class TestLedgerTrustLines(unittest.TestCase):

    def setUp(self):
        self.ledger = Ledger(total_supply=1000.0, genesis_account="rGen")
        self.ledger.create_account("rHolder", 100.0)
        self.ledger.create_account("rIssuer", 100.0)

    def test_set_trust_line(self):
        tl = self.ledger.set_trust_line("rHolder", "USD", "rIssuer", 500.0)
        self.assertIsNotNone(tl)
        self.assertEqual(tl.limit, 500.0)

    def test_get_trust_line(self):
        self.ledger.set_trust_line("rHolder", "USD", "rIssuer", 500.0)
        tl = self.ledger.get_trust_line("rHolder", "USD", "rIssuer")
        self.assertIsNotNone(tl)
        self.assertEqual(tl.currency, "USD")

    def test_get_trust_line_nonexistent(self):
        tl = self.ledger.get_trust_line("rHolder", "BTC", "rNobody")
        self.assertIsNone(tl)

    def test_set_trust_line_updates_limit(self):
        self.ledger.set_trust_line("rHolder", "USD", "rIssuer", 500.0)
        self.ledger.set_trust_line("rHolder", "USD", "rIssuer", 1000.0)
        tl = self.ledger.get_trust_line("rHolder", "USD", "rIssuer")
        self.assertEqual(tl.limit, 1000.0)

    def test_set_trust_line_increments_owner_count(self):
        acc = self.ledger.get_account("rHolder")
        self.assertEqual(acc.owner_count, 0)
        self.ledger.set_trust_line("rHolder", "USD", "rIssuer", 100.0)
        self.assertEqual(acc.owner_count, 1)
        # Updating the same line shouldn't increment again
        self.ledger.set_trust_line("rHolder", "USD", "rIssuer", 200.0)
        self.assertEqual(acc.owner_count, 1)

    def test_set_trust_line_unknown_holder(self):
        result = self.ledger.set_trust_line("rGhost", "USD", "rIssuer", 100.0)
        self.assertIsNone(result)


# ===================================================================
#  Ledger — apply_payment (native NXF)
# ===================================================================


class TestLedgerPaymentNative(unittest.TestCase):

    def setUp(self):
        self.ledger = Ledger(total_supply=10000.0, genesis_account="rGen")
        self.ledger.create_account("rAlice", 500.0)
        self.ledger.create_account("rBob", 100.0)

    def _make_payment(self, src, dst, amount, fee=0.00001, seq=0):
        return create_payment(src, dst, amount, fee=fee, sequence=seq)

    def test_successful_payment(self):
        tx = self._make_payment("rAlice", "rBob", 50.0)
        result = self.ledger.apply_payment(tx)
        self.assertEqual(result, 0)  # tesSUCCESS
        self.assertAlmostEqual(self.ledger.get_balance("rAlice"), 450.0, places=3)
        self.assertAlmostEqual(self.ledger.get_balance("rBob"), 150.0, places=3)

    def test_payment_deducts_fee(self):
        tx = self._make_payment("rAlice", "rBob", 10.0, fee=1.0)
        self.ledger.apply_payment(tx)
        self.assertAlmostEqual(self.ledger.get_balance("rAlice"), 489.0, places=3)

    def test_payment_adds_to_fee_pool(self):
        tx = self._make_payment("rAlice", "rBob", 10.0, fee=5.0)
        self.ledger.apply_payment(tx)
        self.assertAlmostEqual(self.ledger.fee_pool, 5.0, places=3)

    def test_payment_insufficient_funds(self):
        tx = self._make_payment("rAlice", "rBob", 999.0)
        result = self.ledger.apply_payment(tx)
        self.assertEqual(result, 101)  # tecUNFUNDED

    def test_payment_creates_destination(self):
        tx = self._make_payment("rAlice", "rNewGuy", 10.0)
        result = self.ledger.apply_payment(tx)
        self.assertEqual(result, 0)
        self.assertTrue(self.ledger.account_exists("rNewGuy"))
        self.assertAlmostEqual(self.ledger.get_balance("rNewGuy"), 10.0, places=3)

    def test_payment_nonexistent_source(self):
        tx = self._make_payment("rGhost", "rBob", 5.0)
        result = self.ledger.apply_payment(tx)
        self.assertEqual(result, 101)  # tecUNFUNDED

    def test_payment_bad_sequence(self):
        tx = self._make_payment("rAlice", "rBob", 1.0, seq=999)
        result = self.ledger.apply_payment(tx)
        self.assertEqual(result, 105)  # tecBAD_SEQ

    def test_payment_bumps_sequence(self):
        acc = self.ledger.get_account("rAlice")
        old_seq = acc.sequence
        tx = self._make_payment("rAlice", "rBob", 1.0)
        self.ledger.apply_payment(tx)
        self.assertEqual(acc.sequence, old_seq + 1)


# ===================================================================
#  Ledger — apply_payment (IOU)
# ===================================================================


class TestLedgerPaymentIOU(unittest.TestCase):

    def setUp(self):
        self.ledger = Ledger(total_supply=10000.0, genesis_account="rGen")
        self.ledger.create_account("rAlice", 100.0)
        self.ledger.create_account("rBob", 100.0)
        self.ledger.create_account("rGW", 100.0)
        # Set up trust lines
        self.ledger.set_trust_line("rAlice", "USD", "rGW", 1000.0)
        self.ledger.set_trust_line("rBob", "USD", "rGW", 1000.0)
        # Fund Alice with some USD
        tl = self.ledger.get_trust_line("rAlice", "USD", "rGW")
        tl.balance = 500.0

    def test_iou_payment_success(self):
        tx = create_payment("rAlice", "rBob", 100.0, "USD", "rGW")
        result = self.ledger.apply_payment(tx)
        self.assertEqual(result, 0)
        tl_alice = self.ledger.get_trust_line("rAlice", "USD", "rGW")
        tl_bob = self.ledger.get_trust_line("rBob", "USD", "rGW")
        self.assertAlmostEqual(tl_alice.balance, 400.0)
        self.assertAlmostEqual(tl_bob.balance, 100.0)

    def test_iou_payment_no_trust_line_sender(self):
        self.ledger.create_account("rCharlie", 100.0)
        tx = create_payment("rCharlie", "rBob", 50.0, "USD", "rGW")
        result = self.ledger.apply_payment(tx)
        self.assertEqual(result, 103)  # tecNO_LINE

    def test_iou_payment_no_trust_line_receiver(self):
        self.ledger.create_account("rDave", 100.0)
        tx = create_payment("rAlice", "rDave", 50.0, "USD", "rGW")
        result = self.ledger.apply_payment(tx)
        self.assertEqual(result, 103)  # tecNO_LINE

    def test_iou_payment_insufficient_balance(self):
        tx = create_payment("rAlice", "rBob", 999.0, "USD", "rGW")
        result = self.ledger.apply_payment(tx)
        self.assertEqual(result, 101)  # tecUNFUNDED

    def test_iou_payment_exceed_trust_limit(self):
        tx = create_payment("rAlice", "rBob", 500.0, "USD", "rGW")
        result = self.ledger.apply_payment(tx)
        self.assertEqual(result, 0)
        # Bob now has 500, try another that would exceed 1000 limit
        tl_alice = self.ledger.get_trust_line("rAlice", "USD", "rGW")
        tl_alice.balance = 500.0  # refund Alice for test
        tx2 = create_payment("rAlice", "rBob", 501.0, "USD", "rGW")
        result2 = self.ledger.apply_payment(tx2)
        self.assertEqual(result2, 101)  # exceeds trust limit

    def test_iou_payment_fee_deducted_in_native(self):
        old_bal = self.ledger.get_balance("rAlice")
        tx = create_payment("rAlice", "rBob", 10.0, "USD", "rGW", fee=1.0)
        self.ledger.apply_payment(tx)
        self.assertAlmostEqual(self.ledger.get_balance("rAlice"), old_bal - 1.0)


# ===================================================================
#  Ledger — apply_trust_set
# ===================================================================


class TestLedgerTrustSet(unittest.TestCase):

    def setUp(self):
        self.ledger = Ledger(total_supply=10000.0, genesis_account="rGen")
        self.ledger.create_account("rUser", 100.0)

    def test_trust_set_creates_line(self):
        tx = create_trust_set("rUser", "USD", "rBank", 1000.0)
        result = self.ledger.apply_trust_set(tx)
        self.assertEqual(result, 0)
        tl = self.ledger.get_trust_line("rUser", "USD", "rBank")
        self.assertIsNotNone(tl)
        self.assertEqual(tl.limit, 1000.0)

    def test_trust_set_deducts_fee(self):
        old_bal = self.ledger.get_balance("rUser")
        tx = create_trust_set("rUser", "EUR", "rECB", 500.0, fee=0.5)
        self.ledger.apply_trust_set(tx)
        self.assertAlmostEqual(self.ledger.get_balance("rUser"), old_bal - 0.5)

    def test_trust_set_nonexistent_account(self):
        tx = create_trust_set("rGhost", "USD", "rBank", 100.0)
        result = self.ledger.apply_trust_set(tx)
        self.assertEqual(result, 101)  # tecUNFUNDED


# ===================================================================
#  Ledger — apply_transaction routing
# ===================================================================


class TestLedgerApplyTransaction(unittest.TestCase):

    def setUp(self):
        self.ledger = Ledger(total_supply=10000.0, genesis_account="rGen")
        self.ledger.create_account("rAlice", 500.0)

    def test_routes_payment(self):
        tx = create_payment("rAlice", "rBob", 10.0)
        result = self.ledger.apply_transaction(tx)
        self.assertEqual(result, 0)
        self.assertEqual(tx.result_code, 0)

    def test_routes_trust_set(self):
        tx = create_trust_set("rAlice", "USD", "rBank", 100.0)
        result = self.ledger.apply_transaction(tx)
        self.assertEqual(result, 0)

    def test_pending_txns_added_on_success(self):
        self.assertEqual(len(self.ledger.pending_txns), 0)
        tx = create_payment("rAlice", "rBob", 5.0)
        self.ledger.apply_transaction(tx)
        self.assertEqual(len(self.ledger.pending_txns), 1)

    def test_pending_txns_not_added_on_failure(self):
        tx = create_payment("rGhost", "rBob", 5.0)
        self.ledger.apply_transaction(tx)
        self.assertEqual(len(self.ledger.pending_txns), 0)


# ===================================================================
#  Ledger — close_ledger
# ===================================================================


class TestLedgerClose(unittest.TestCase):

    def setUp(self):
        self.ledger = Ledger(total_supply=10000.0, genesis_account="rGen")
        self.ledger.create_account("rAlice", 500.0)

    def test_close_empty_ledger(self):
        header = self.ledger.close_ledger()
        self.assertEqual(header.sequence, 1)
        self.assertEqual(header.tx_count, 0)
        self.assertEqual(len(header.hash), 64)

    def test_close_increments_sequence(self):
        self.assertEqual(self.ledger.current_sequence, 1)
        self.ledger.close_ledger()
        self.assertEqual(self.ledger.current_sequence, 2)

    def test_close_clears_pending_txns(self):
        tx = create_payment("rAlice", "rBob", 5.0)
        self.ledger.apply_transaction(tx)
        self.assertEqual(len(self.ledger.pending_txns), 1)
        self.ledger.close_ledger()
        self.assertEqual(len(self.ledger.pending_txns), 0)

    def test_hash_chain(self):
        h1 = self.ledger.close_ledger()
        h2 = self.ledger.close_ledger()
        self.assertEqual(h2.parent_hash, h1.hash)

    def test_closed_ledgers_archived(self):
        self.ledger.close_ledger()
        self.ledger.close_ledger()
        self.assertEqual(len(self.ledger.closed_ledgers), 2)

    def test_tx_count_in_header(self):
        tx1 = create_payment("rAlice", "rBob", 1.0)
        tx2 = create_payment("rAlice", "rBob", 2.0)
        self.ledger.apply_transaction(tx1)
        self.ledger.apply_transaction(tx2)
        header = self.ledger.close_ledger()
        self.assertEqual(header.tx_count, 2)


# ===================================================================
#  Ledger — get_state_summary
# ===================================================================


class TestLedgerStateSummary(unittest.TestCase):

    def test_summary_fields(self):
        ledger = Ledger(total_supply=1000.0)
        summary = ledger.get_state_summary()
        self.assertIn("ledger_sequence", summary)
        self.assertIn("closed_ledgers", summary)
        self.assertIn("total_accounts", summary)
        self.assertIn("total_supply", summary)
        self.assertIn("fee_pool", summary)

    def test_summary_account_count(self):
        ledger = Ledger(total_supply=1000.0)
        ledger.create_account("rA")
        ledger.create_account("rB")
        s = ledger.get_state_summary()
        # +1 for genesis
        self.assertEqual(s["total_accounts"], 3)


if __name__ == "__main__":
    unittest.main()
