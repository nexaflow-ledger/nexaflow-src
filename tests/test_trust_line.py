"""
Test suite for nexaflow_core.trust_line — TrustGraph utilities.

Covers:
  - TrustGraph.build_from_ledger
  - get_trustees, get_trusted_issuers
  - has_trust, available_credit
  - all_currencies, summary
"""

import unittest

from nexaflow_core.ledger import Ledger
from nexaflow_core.trust_line import TrustGraph


class TrustGraphTestBase(unittest.TestCase):
    """Base class that sets up a ledger with trust lines."""

    def setUp(self):
        self.ledger = Ledger(total_supply=10000.0, genesis_account="rGen")
        self.ledger.create_account("rAlice", 100.0)
        self.ledger.create_account("rBob", 100.0)
        self.ledger.create_account("rGW", 100.0)
        # Alice trusts GW for USD
        self.ledger.set_trust_line("rAlice", "USD", "rGW", 1000.0)
        # Bob trusts GW for USD
        self.ledger.set_trust_line("rBob", "USD", "rGW", 500.0)
        # Alice trusts GW for EUR
        self.ledger.set_trust_line("rAlice", "EUR", "rGW", 200.0)

        self.graph = TrustGraph()
        self.graph.build_from_ledger(self.ledger)


class TestTrustGraphBuild(TrustGraphTestBase):

    def test_forward_populated(self):
        issuers = self.graph.get_trusted_issuers("rAlice")
        self.assertTrue(len(issuers) >= 2)  # USD + EUR

    def test_reverse_populated(self):
        trustees = self.graph.get_trustees("rGW")
        # Both Alice and Bob trust GW
        holders = {t[0] for t in trustees}
        self.assertIn("rAlice", holders)
        self.assertIn("rBob", holders)

    def test_rebuild_clears_old_data(self):
        self.graph.build_from_ledger(self.ledger)
        # Should not double entries
        trustees = self.graph.get_trustees("rGW")
        holder_currency = [(t[0], t[1]) for t in trustees]
        unique = set(holder_currency)
        self.assertEqual(len(unique), len(holder_currency))


class TestTrustGraphQuery(TrustGraphTestBase):

    def test_has_trust_true(self):
        self.assertTrue(self.graph.has_trust("rAlice", "rGW", "USD"))

    def test_has_trust_false(self):
        self.assertFalse(self.graph.has_trust("rBob", "rGW", "EUR"))

    def test_has_trust_unknown_holder(self):
        self.assertFalse(self.graph.has_trust("rNobody", "rGW", "USD"))

    def test_available_credit_full(self):
        # Alice has limit 1000, balance 0 → credit = 1000
        credit = self.graph.available_credit("rAlice", "rGW", "USD")
        self.assertAlmostEqual(credit, 1000.0)

    def test_available_credit_partial(self):
        # Set balance manually
        tl = self.ledger.get_trust_line("rAlice", "USD", "rGW")
        tl.balance = 600.0
        self.graph.build_from_ledger(self.ledger)
        credit = self.graph.available_credit("rAlice", "rGW", "USD")
        self.assertAlmostEqual(credit, 400.0)

    def test_available_credit_no_trust(self):
        credit = self.graph.available_credit("rNobody", "rGW", "USD")
        self.assertAlmostEqual(credit, 0.0)

    def test_get_trustees_empty(self):
        self.assertEqual(self.graph.get_trustees("rAlice"), [])

    def test_get_trusted_issuers_empty(self):
        self.assertEqual(self.graph.get_trusted_issuers("rNobody"), [])


class TestTrustGraphAggregation(TrustGraphTestBase):

    def test_all_currencies(self):
        currencies = self.graph.all_currencies()
        self.assertIn("USD", currencies)
        self.assertIn("EUR", currencies)

    def test_summary(self):
        s = self.graph.summary()
        self.assertEqual(s["total_trust_lines"], 3)  # Alice:USD, Bob:USD, Alice:EUR
        self.assertIn("unique_holders", s)
        self.assertIn("unique_issuers", s)
        self.assertIn("currencies", s)


class TestTrustGraphEmpty(unittest.TestCase):

    def test_empty_ledger(self):
        ledger = Ledger(total_supply=1000.0)
        graph = TrustGraph()
        graph.build_from_ledger(ledger)
        self.assertEqual(graph.all_currencies(), set())
        s = graph.summary()
        self.assertEqual(s["total_trust_lines"], 0)


if __name__ == "__main__":
    unittest.main()
