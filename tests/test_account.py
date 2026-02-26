"""
Test suite for nexaflow_core.account — High-level Account abstraction.

Covers:
  - Account.create() and Account.from_seed()
  - send_payment, set_trust, create_offer
  - Transaction history
"""

import unittest

from nexaflow_core.account import Account
from nexaflow_core.transaction import TT_OFFER_CREATE, TT_PAYMENT, TT_TRUST_SET, Amount


class TestAccountCreation(unittest.TestCase):

    def test_create(self):
        acc = Account.create()
        self.assertTrue(acc.address.startswith("r"))
        self.assertEqual(len(acc.tx_history), 0)

    def test_from_seed_deterministic(self):
        a1 = Account.from_seed("account-seed")
        a2 = Account.from_seed("account-seed")
        self.assertEqual(a1.address, a2.address)

    def test_from_seed_different_seeds(self):
        a1 = Account.from_seed("seed_x")
        a2 = Account.from_seed("seed_y")
        self.assertNotEqual(a1.address, a2.address)

    def test_repr(self):
        acc = Account.create()
        self.assertIn("Account(", repr(acc))


class TestAccountTransactions(unittest.TestCase):

    def setUp(self):
        self.acc = Account.create()

    def test_send_payment_returns_signed_tx(self):
        tx = self.acc.send_payment("rDest", 100.0)
        self.assertEqual(tx.tx_type, TT_PAYMENT)
        self.assertEqual(tx.account, self.acc.address)
        self.assertEqual(tx.destination, "rDest")
        self.assertTrue(len(tx.signature) > 0)
        self.assertTrue(len(tx.tx_id) > 0)

    def test_send_payment_iou(self):
        tx = self.acc.send_payment("rDest", 50.0, "USD", "rIssuer")
        self.assertEqual(tx.amount.currency, "USD")

    def test_send_payment_memo(self):
        tx = self.acc.send_payment("rDest", 1.0, memo="hello")
        self.assertEqual(tx.memo, "hello")

    def test_set_trust(self):
        tx = self.acc.set_trust("USD", "rBank", 1000.0)
        self.assertEqual(tx.tx_type, TT_TRUST_SET)
        self.assertIsNotNone(tx.limit_amount)
        self.assertEqual(tx.limit_amount.currency, "USD")
        self.assertTrue(len(tx.signature) > 0)

    def test_create_offer(self):
        pays = Amount(100.0, "USD", "rGW")
        gets = Amount(5.0)
        tx = self.acc.create_offer(pays, gets)
        self.assertEqual(tx.tx_type, TT_OFFER_CREATE)
        self.assertTrue(len(tx.signature) > 0)

    def test_history_tracks_txns(self):
        self.acc.send_payment("rA", 1.0)
        self.acc.send_payment("rB", 2.0)
        self.acc.set_trust("USD", "rBank", 500.0)
        self.assertEqual(len(self.acc.tx_history), 3)

    def test_get_history_returns_dicts(self):
        self.acc.send_payment("rA", 1.0)
        history = self.acc.get_history()
        self.assertIsInstance(history, list)
        self.assertEqual(len(history), 1)
        self.assertIsInstance(history[0], dict)
        self.assertIn("tx_type", history[0])

    def test_sequence_increments(self):
        self.acc.send_payment("rA", 1.0)
        self.acc.send_payment("rB", 2.0)
        self.assertEqual(self.acc.wallet.sequence, 3)


if __name__ == "__main__":
    unittest.main()
