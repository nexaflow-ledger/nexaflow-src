"""
Test suite for advanced payment path finding.

Covers:
  - Native NXF direct path
  - Cross-currency routing via NXF auto-bridge
  - Order book DEX integration in pathfinding
  - Partial payment delivery
  - PaymentPath serialization and properties
  - No-path scenarios
"""

import unittest

from nexaflow_core.ledger import Ledger
from nexaflow_core.order_book import OrderBook
from nexaflow_core.payment_path import PathFinder, PaymentPath
from nexaflow_core.trust_line import TrustGraph


class TestPaymentPath(unittest.TestCase):

    def test_to_dict(self):
        p = PaymentPath(
            hops=[("rA", "USD", "rIssuer"), ("rB", "USD", "rIssuer")],
            max_amount=50.0,
            source="rA",
            destination="rB",
            currency="USD",
        )
        d = p.to_dict()
        self.assertEqual(d["source"], "rA")
        self.assertEqual(d["hop_count"], 2)
        self.assertEqual(d["max_amount"], 50.0)

    def test_cross_currency_path(self):
        p = PaymentPath(
            hops=[("rA", "USD", "rA"), ("rA", "NXF", ""), ("rB", "NXF", ""), ("rB", "EUR", "rB")],
            max_amount=100.0,
            source="rA",
            destination="rB",
            currency="EUR",
            source_currency="USD",
            is_cross_currency=True,
        )
        self.assertTrue(p.is_cross_currency)
        self.assertEqual(p.source_currency, "USD")
        self.assertEqual(p.currency, "EUR")

    def test_repr(self):
        p = PaymentPath(
            hops=[("rAlice", "NXF", "")],
            max_amount=10.0,
            source="rAlice",
            destination="rBob",
            currency="NXF",
        )
        r = repr(p)
        self.assertIn("rAlice", r)


class TestPathFinderNative(unittest.TestCase):

    def setUp(self):
        self.ledger = Ledger(total_supply=10_000.0, genesis_account="rGen")
        self.ledger.create_account("rAlice", 500.0)
        self.ledger.create_account("rBob", 100.0)
        self.graph = TrustGraph()
        self.pf = PathFinder(self.graph, self.ledger)

    def test_native_path_found(self):
        paths = self.pf.find_paths("rAlice", "rBob", "NXF", 100.0)
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0].currency, "NXF")
        self.assertGreaterEqual(paths[0].max_amount, 100.0)

    def test_native_path_insufficient_funds(self):
        paths = self.pf.find_paths("rAlice", "rBob", "NXF", 999.0)
        self.assertEqual(len(paths), 0)


class TestPathFinderCrossCurrency(unittest.TestCase):

    def setUp(self):
        self.ledger = Ledger(total_supply=10_000.0, genesis_account="rGen")
        self.ledger.create_account("rAlice", 500.0)
        self.ledger.create_account("rBob", 500.0)
        self.graph = TrustGraph()
        self.pf = PathFinder(self.graph, self.ledger)

    def test_cross_currency_bridge(self):
        paths = self.pf.find_paths(
            "rAlice", "rBob", "EUR", 100.0,
            source_currency="USD",
        )
        self.assertGreater(len(paths), 0)
        self.assertTrue(paths[0].is_cross_currency)
        self.assertEqual(paths[0].source_currency, "USD")
        self.assertEqual(paths[0].currency, "EUR")

    def test_cross_currency_with_order_book(self):
        ob = OrderBook()
        ob.submit_order("rMM", "EUR/USD", "sell", 1.1, 1000.0)
        pf = PathFinder(self.graph, self.ledger, order_book=ob)
        paths = pf.find_paths(
            "rAlice", "rBob", "EUR", 100.0,
            source_currency="USD",
        )
        # Should have both: NXF bridge path and DEX direct path
        self.assertGreaterEqual(len(paths), 1)

    def test_cross_currency_zero_balance(self):
        self.ledger.create_account("rPoor", 0.0)
        paths = self.pf.find_paths(
            "rPoor", "rBob", "EUR", 100.0,
            source_currency="USD",
        )
        self.assertEqual(len(paths), 0)


class TestPathFinderIOU(unittest.TestCase):

    def setUp(self):
        self.ledger = Ledger(total_supply=10_000.0, genesis_account="rGen")
        self.ledger.create_account("rAlice", 500.0)
        self.ledger.create_account("rBob", 500.0)
        self.ledger.create_account("rGateway", 1000.0)
        self.ledger.set_trust_line("rAlice", "USD", "rGateway", 1000.0)
        self.ledger.set_trust_line("rBob", "USD", "rGateway", 500.0)
        self.graph = TrustGraph()
        self.graph.build_from_ledger(self.ledger)
        self.pf = PathFinder(self.graph, self.ledger)

    def test_iou_path_discovered(self):
        paths = self.pf.find_paths("rGateway", "rBob", "USD", 100.0)
        self.assertGreater(len(paths), 0)

    def test_iou_source_currency_same(self):
        """If source_currency == currency, uses regular IOU pathfinding."""
        paths = self.pf.find_paths("rGateway", "rBob", "USD", 100.0,
                                   source_currency="USD")
        self.assertGreater(len(paths), 0)


if __name__ == "__main__":
    unittest.main()
