"""
Test suite for nexaflow_core.order_book advanced features.

Covers:
  - Basic limit order matching (buy/sell)
  - Immediate-or-Cancel (IOC) time_in_force
  - Fill-or-Kill (FOK) time_in_force
  - Order expiration (is_expired, _purge_expired)
  - Auto-bridging through NXF
  - Market orders (price=0)
  - Cancel order
  - get_book_snapshot and get_fills
  - Edge cases: FOK insufficient liquidity, IOC partial fill, expired maker
"""

import time
import unittest

from nexaflow_core.order_book import Fill, Order, OrderBook


class TestOrder(unittest.TestCase):

    def test_defaults(self):
        o = Order(order_id="o1", account="rA", pair="NXF/USD",
                  side="buy", price=1.0, quantity=100.0)
        self.assertEqual(o.remaining, 100.0)
        self.assertEqual(o.status, "open")
        self.assertEqual(o.time_in_force, "GTC")

    def test_sort_key_sell(self):
        o = Order(order_id="o1", account="rA", pair="NXF/USD",
                  side="sell", price=2.0, quantity=50.0)
        self.assertEqual(o.sort_key[0], 2.0)

    def test_sort_key_buy(self):
        o = Order(order_id="o1", account="rA", pair="NXF/USD",
                  side="buy", price=2.0, quantity=50.0)
        self.assertEqual(o.sort_key[0], -2.0)

    def test_is_expired_false(self):
        o = Order(order_id="o1", account="rA", pair="NXF/USD",
                  side="buy", price=1.0, quantity=10.0, expiration=0)
        self.assertFalse(o.is_expired)

    def test_is_expired_true(self):
        o = Order(order_id="o1", account="rA", pair="NXF/USD",
                  side="buy", price=1.0, quantity=10.0,
                  expiration=time.time() - 100)
        self.assertTrue(o.is_expired)

    def test_to_dict(self):
        o = Order(order_id="o1", account="rA", pair="NXF/USD",
                  side="buy", price=1.5, quantity=10.0)
        d = o.to_dict()
        self.assertEqual(d["order_id"], "o1")
        self.assertIn("time_in_force", d)
        self.assertIn("expiration", d)


class TestOrderBookBasic(unittest.TestCase):

    def setUp(self):
        self.ob = OrderBook()

    def test_submit_and_match(self):
        # rAlice sells 100 NXF/USD at $2
        self.ob.submit_order("rAlice", "NXF/USD", "sell", 2.0, 100.0)
        # rBob buys 50 NXF/USD at $2
        fills = self.ob.submit_order("rBob", "NXF/USD", "buy", 2.0, 50.0)
        self.assertEqual(len(fills), 1)
        self.assertEqual(fills[0].quantity, 50.0)
        self.assertEqual(fills[0].price, 2.0)

    def test_no_match_price_gap(self):
        self.ob.submit_order("rAlice", "NXF/USD", "sell", 3.0, 100.0)
        fills = self.ob.submit_order("rBob", "NXF/USD", "buy", 2.0, 100.0)
        self.assertEqual(len(fills), 0)

    def test_partial_fill(self):
        self.ob.submit_order("rAlice", "NXF/USD", "sell", 2.0, 30.0)
        fills = self.ob.submit_order("rBob", "NXF/USD", "buy", 2.0, 100.0)
        self.assertEqual(fills[0].quantity, 30.0)
        # Remaining 70 rests on book
        order = self.ob.get_order("ORD-000002")
        self.assertEqual(order.status, "partially_filled")
        self.assertAlmostEqual(order.remaining, 70.0)

    def test_market_order_price_zero(self):
        self.ob.submit_order("rAlice", "NXF/USD", "sell", 2.0, 100.0)
        fills = self.ob.submit_order("rBob", "NXF/USD", "buy", 0.0, 50.0)
        self.assertEqual(len(fills), 1)
        self.assertEqual(fills[0].quantity, 50.0)

    def test_cancel_order(self):
        self.ob.submit_order("rAlice", "NXF/USD", "sell", 5.0, 100.0,
                             order_id="oid1")
        self.assertTrue(self.ob.cancel_order("oid1"))
        self.assertEqual(self.ob.get_order("oid1").status, "cancelled")
        # Can't cancel again
        self.assertFalse(self.ob.cancel_order("oid1"))

    def test_cancel_nonexistent(self):
        self.assertFalse(self.ob.cancel_order("nope"))


class TestOrderBookIOC(unittest.TestCase):

    def setUp(self):
        self.ob = OrderBook()

    def test_ioc_full_fill(self):
        self.ob.submit_order("rAlice", "NXF/USD", "sell", 2.0, 100.0)
        fills = self.ob.submit_order("rBob", "NXF/USD", "buy", 2.0, 100.0,
                                     time_in_force="IOC")
        self.assertEqual(len(fills), 1)
        self.assertEqual(fills[0].quantity, 100.0)

    def test_ioc_partial_fill_remainder_cancelled(self):
        self.ob.submit_order("rAlice", "NXF/USD", "sell", 2.0, 30.0)
        fills = self.ob.submit_order("rBob", "NXF/USD", "buy", 2.0, 100.0,
                                     time_in_force="IOC")
        self.assertEqual(fills[0].quantity, 30.0)
        # Remaining should be cancelled, NOT resting
        order = self.ob.get_order("ORD-000002")
        self.assertEqual(order.status, "cancelled")

    def test_ioc_no_match(self):
        fills = self.ob.submit_order("rBob", "NXF/USD", "buy", 2.0, 100.0,
                                     time_in_force="IOC")
        self.assertEqual(len(fills), 0)
        order = self.ob.get_order("ORD-000001")
        self.assertEqual(order.status, "cancelled")


class TestOrderBookFOK(unittest.TestCase):

    def setUp(self):
        self.ob = OrderBook()

    def test_fok_full_fill(self):
        self.ob.submit_order("rAlice", "NXF/USD", "sell", 2.0, 100.0)
        fills = self.ob.submit_order("rBob", "NXF/USD", "buy", 2.0, 50.0,
                                     time_in_force="FOK")
        self.assertEqual(len(fills), 1)
        self.assertEqual(fills[0].quantity, 50.0)

    def test_fok_insufficient_liquidity_cancelled(self):
        self.ob.submit_order("rAlice", "NXF/USD", "sell", 2.0, 30.0)
        fills = self.ob.submit_order("rBob", "NXF/USD", "buy", 2.0, 100.0,
                                     time_in_force="FOK")
        self.assertEqual(len(fills), 0)
        order = self.ob.get_order("ORD-000002")
        self.assertEqual(order.status, "cancelled")

    def test_fok_no_liquidity(self):
        fills = self.ob.submit_order("rBob", "NXF/USD", "buy", 2.0, 100.0,
                                     time_in_force="FOK")
        self.assertEqual(len(fills), 0)


class TestOrderBookExpiration(unittest.TestCase):

    def setUp(self):
        self.ob = OrderBook()

    def test_expired_order_skipped_during_match(self):
        # Place an ask that's already expired
        self.ob.submit_order("rAlice", "NXF/USD", "sell", 2.0, 100.0,
                             expiration=time.time() - 100)
        # Place a valid ask
        self.ob.submit_order("rBob", "NXF/USD", "sell", 2.5, 100.0)
        fills = self.ob.submit_order("rCharlie", "NXF/USD", "buy", 3.0, 50.0)
        # Should match against rBob, not expired rAlice
        self.assertEqual(len(fills), 1)
        self.assertEqual(fills[0].price, 2.5)


class TestOrderBookAutoBridge(unittest.TestCase):

    def setUp(self):
        self.ob = OrderBook()

    def test_direct_pair_no_bridge(self):
        self.ob.submit_order("rAlice", "NXF/USD", "sell", 2.0, 100.0)
        fills = self.ob.submit_auto_bridged_order(
            "rBob", "USD", "NXF", "buy", 50.0,
        )
        self.assertEqual(len(fills), 1)

    def test_auto_bridge_usd_to_eur(self):
        # Provide liquidity: NXF/USD sells and EUR/NXF sells
        self.ob.submit_order("rMM1", "NXF/USD", "sell", 2.0, 1000.0)
        self.ob.submit_order("rMM2", "EUR/NXF", "sell", 0.5, 1000.0)
        fills = self.ob.submit_auto_bridged_order(
            "rTrader", "USD", "EUR", "buy", 100.0,
        )
        self.assertGreater(len(fills), 0)


class TestOrderBookSnapshot(unittest.TestCase):

    def setUp(self):
        self.ob = OrderBook()

    def test_get_book_snapshot(self):
        self.ob.submit_order("rA", "NXF/USD", "sell", 2.0, 100.0)
        self.ob.submit_order("rB", "NXF/USD", "buy", 1.5, 50.0)
        snap = self.ob.get_book_snapshot("NXF/USD")
        self.assertEqual(snap["pair"], "NXF/USD")
        self.assertEqual(len(snap["asks"]), 1)
        self.assertEqual(len(snap["bids"]), 1)

    def test_get_fills(self):
        self.ob.submit_order("rA", "NXF/USD", "sell", 2.0, 100.0)
        self.ob.submit_order("rB", "NXF/USD", "buy", 2.0, 50.0)
        fills = self.ob.get_fills()
        self.assertEqual(len(fills), 1)
        self.assertEqual(fills[0]["quantity"], 50.0)

    def test_pairs(self):
        self.ob.submit_order("rA", "NXF/USD", "sell", 2.0, 100.0)
        self.ob.submit_order("rA", "NXF/EUR", "sell", 1.5, 50.0)
        self.assertIn("NXF/USD", self.ob.pairs)
        self.assertIn("NXF/EUR", self.ob.pairs)


if __name__ == "__main__":
    unittest.main()
