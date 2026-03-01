"""
Tests for nexaflow_core.order_book — DEX limit-order matching engine.

Covers:
  - Order creation and ID generation
  - Price-time priority matching
  - Partial fills
  - Full fills
  - Bid-ask spread (no match)
  - Cancel order
  - Cancel already-filled / cancelled order
  - get_book_snapshot ─ depth, ask/bid counts
  - get_fills
  - Multiple pairs isolation
  - Self-trade (same account on both sides)
  - Edge cases: zero price, negative quantity, very small quantities
"""

import unittest

from nexaflow_core.order_book import Fill, Order, OrderBook


class TestOrderCreation(unittest.TestCase):

    def test_order_defaults(self):
        o = Order(order_id="O1", account="rAlice", pair="NXF/USD",
                  side="buy", price=1.0, quantity=10.0)
        self.assertEqual(o.remaining, 10.0)
        self.assertEqual(o.status, "open")

    def test_remaining_set_in_post_init(self):
        o = Order(order_id="O1", account="rAlice", pair="NXF/USD",
                  side="buy", price=1.0, quantity=50.0)
        self.assertEqual(o.remaining, 50.0)

    def test_buy_sort_key_negative_price(self):
        o = Order(order_id="O1", account="rA", pair="X/Y",
                  side="buy", price=5.0, quantity=1.0)
        self.assertEqual(o.sort_key[0], -5.0)

    def test_sell_sort_key_positive_price(self):
        o = Order(order_id="O1", account="rA", pair="X/Y",
                  side="sell", price=5.0, quantity=1.0)
        self.assertEqual(o.sort_key[0], 5.0)

    def test_to_dict(self):
        o = Order(order_id="O1", account="rA", pair="NXF/USD",
                  side="buy", price=2.5, quantity=100.0)
        d = o.to_dict()
        self.assertEqual(d["order_id"], "O1")
        self.assertEqual(d["price"], 2.5)
        self.assertEqual(d["quantity"], 100.0)


class TestFill(unittest.TestCase):

    def test_fill_to_dict(self):
        f = Fill(maker_order_id="M1", taker_order_id="T1",
                 pair="NXF/USD", price=1.5, quantity=10.0, timestamp=1.0)
        d = f.to_dict()
        self.assertEqual(d["price"], 1.5)
        self.assertEqual(d["quantity"], 10.0)


class TestSubmitOrder(unittest.TestCase):

    def setUp(self):
        self.ob = OrderBook()

    def test_auto_generated_id(self):
        fills = self.ob.submit_order("rAlice", "NXF/USD", "buy", 1.0, 10.0)
        self.assertEqual(len(fills), 0)
        o = self.ob.get_order("ORD-000001")
        self.assertIsNotNone(o)
        self.assertEqual(o.account, "rAlice")

    def test_custom_id(self):
        self.ob.submit_order("rAlice", "NXF/USD", "buy", 1.0, 5.0, order_id="CUSTOM")
        o = self.ob.get_order("CUSTOM")
        self.assertIsNotNone(o)

    def test_resting_buy_order(self):
        self.ob.submit_order("rAlice", "NXF/USD", "buy", 1.0, 100.0)
        snap = self.ob.get_book_snapshot("NXF/USD")
        self.assertEqual(snap["bid_count"], 1)
        self.assertEqual(snap["ask_count"], 0)

    def test_resting_sell_order(self):
        self.ob.submit_order("rAlice", "NXF/USD", "sell", 2.0, 50.0)
        snap = self.ob.get_book_snapshot("NXF/USD")
        self.assertEqual(snap["bid_count"], 0)
        self.assertEqual(snap["ask_count"], 1)


# ═══════════════════════════════════════════════════════════════════
#  Matching
# ═══════════════════════════════════════════════════════════════════

class TestMatching(unittest.TestCase):

    def setUp(self):
        self.ob = OrderBook()

    def test_exact_match(self):
        """Buy and sell at same price, same quantity → single fill."""
        self.ob.submit_order("rAlice", "NXF/USD", "sell", 1.0, 10.0, order_id="S1")
        fills = self.ob.submit_order("rBob", "NXF/USD", "buy", 1.0, 10.0, order_id="B1")
        self.assertEqual(len(fills), 1)
        self.assertEqual(fills[0].quantity, 10.0)
        self.assertEqual(fills[0].price, 1.0)
        self.assertEqual(fills[0].maker_order_id, "S1")
        self.assertEqual(fills[0].taker_order_id, "B1")
        # Both should be filled
        self.assertEqual(self.ob.get_order("S1").status, "filled")
        self.assertEqual(self.ob.get_order("B1").status, "filled")

    def test_taker_crosses_spread(self):
        """Buy price > ask price → match at maker's price."""
        self.ob.submit_order("rSeller", "NXF/USD", "sell", 1.0, 20.0, order_id="S1")
        fills = self.ob.submit_order("rBuyer", "NXF/USD", "buy", 1.5, 20.0)
        self.assertEqual(len(fills), 1)
        self.assertEqual(fills[0].price, 1.0)  # fills at maker price

    def test_no_match_bid_below_ask(self):
        """Buy at 0.5, sell at 1.0 → no fill."""
        self.ob.submit_order("rSeller", "NXF/USD", "sell", 1.0, 10.0)
        fills = self.ob.submit_order("rBuyer", "NXF/USD", "buy", 0.5, 10.0)
        self.assertEqual(len(fills), 0)
        snap = self.ob.get_book_snapshot("NXF/USD")
        self.assertEqual(snap["ask_count"], 1)
        self.assertEqual(snap["bid_count"], 1)

    def test_partial_fill_taker_larger(self):
        """Taker wants more than maker offers → partial fill, taker rests."""
        self.ob.submit_order("rSeller", "NXF/USD", "sell", 1.0, 5.0, order_id="S1")
        fills = self.ob.submit_order("rBuyer", "NXF/USD", "buy", 1.0, 20.0, order_id="B1")
        self.assertEqual(len(fills), 1)
        self.assertEqual(fills[0].quantity, 5.0)
        # Seller fully filled, buyer partially
        self.assertEqual(self.ob.get_order("S1").status, "filled")
        buyer = self.ob.get_order("B1")
        self.assertEqual(buyer.status, "partially_filled")
        self.assertEqual(buyer.remaining, 15.0)

    def test_partial_fill_maker_larger(self):
        """Maker has more than taker needs → maker partially filled."""
        self.ob.submit_order("rSeller", "NXF/USD", "sell", 1.0, 100.0, order_id="S1")
        fills = self.ob.submit_order("rBuyer", "NXF/USD", "buy", 1.0, 30.0, order_id="B1")
        self.assertEqual(len(fills), 1)
        self.assertEqual(fills[0].quantity, 30.0)
        seller = self.ob.get_order("S1")
        self.assertEqual(seller.status, "partially_filled")
        self.assertEqual(seller.remaining, 70.0)
        self.assertEqual(self.ob.get_order("B1").status, "filled")

    def test_multi_maker_fill(self):
        """Taker matches against multiple resting orders."""
        self.ob.submit_order("rA", "NXF/USD", "sell", 1.0, 10.0, order_id="SA")
        self.ob.submit_order("rB", "NXF/USD", "sell", 1.1, 10.0, order_id="SB")
        self.ob.submit_order("rC", "NXF/USD", "sell", 1.2, 10.0, order_id="SC")
        fills = self.ob.submit_order("rBuyer", "NXF/USD", "buy", 1.15, 25.0)
        # Should match SA @1.0 (10) + SB @1.1 (10) = 20, not SC (price too high)
        self.assertEqual(len(fills), 2)
        self.assertEqual(fills[0].price, 1.0)
        self.assertEqual(fills[1].price, 1.1)

    def test_price_time_priority_asks(self):
        """Among equal-price asks, earlier order fills first."""
        self.ob.submit_order("rOld", "NXF/USD", "sell", 1.0, 5.0, order_id="S_OLD")
        self.ob.submit_order("rNew", "NXF/USD", "sell", 1.0, 5.0, order_id="S_NEW")
        fills = self.ob.submit_order("rBuyer", "NXF/USD", "buy", 1.0, 5.0)
        self.assertEqual(fills[0].maker_order_id, "S_OLD")

    def test_price_time_priority_bids(self):
        """Among equal-price bids, earlier order fills first."""
        self.ob.submit_order("rOld", "NXF/USD", "buy", 1.0, 5.0, order_id="B_OLD")
        self.ob.submit_order("rNew", "NXF/USD", "buy", 1.0, 5.0, order_id="B_NEW")
        fills = self.ob.submit_order("rSeller", "NXF/USD", "sell", 1.0, 5.0)
        self.assertEqual(fills[0].maker_order_id, "B_OLD")

    def test_sell_into_bids(self):
        """Incoming sell order matches resting bid."""
        self.ob.submit_order("rBuyer", "NXF/USD", "buy", 2.0, 10.0, order_id="B1")
        fills = self.ob.submit_order("rSeller", "NXF/USD", "sell", 1.5, 10.0)
        self.assertEqual(len(fills), 1)
        self.assertEqual(fills[0].price, 2.0)  # maker's price

    def test_sell_no_match_above_bids(self):
        """Sell at 3.0, best bid at 2.0 → no match."""
        self.ob.submit_order("rBuyer", "NXF/USD", "buy", 2.0, 10.0)
        fills = self.ob.submit_order("rSeller", "NXF/USD", "sell", 3.0, 10.0)
        self.assertEqual(len(fills), 0)


# ═══════════════════════════════════════════════════════════════════
#  Cancel
# ═══════════════════════════════════════════════════════════════════

class TestCancel(unittest.TestCase):

    def setUp(self):
        self.ob = OrderBook()

    def test_cancel_resting_order(self):
        self.ob.submit_order("rA", "NXF/USD", "buy", 1.0, 10.0, order_id="B1")
        self.assertTrue(self.ob.cancel_order("B1"))
        snap = self.ob.get_book_snapshot("NXF/USD")
        self.assertEqual(snap["bid_count"], 0)

    def test_cancel_nonexistent(self):
        self.assertFalse(self.ob.cancel_order("GHOST"))

    def test_cancel_already_filled(self):
        self.ob.submit_order("rA", "NXF/USD", "sell", 1.0, 10.0, order_id="S1")
        self.ob.submit_order("rB", "NXF/USD", "buy", 1.0, 10.0)  # fills S1
        self.assertFalse(self.ob.cancel_order("S1"))

    def test_cancel_already_cancelled(self):
        self.ob.submit_order("rA", "NXF/USD", "sell", 1.0, 10.0, order_id="S1")
        self.ob.cancel_order("S1")
        self.assertFalse(self.ob.cancel_order("S1"))

    def test_cancelled_order_not_matchable(self):
        """After cancelling, a new taker should not match it."""
        self.ob.submit_order("rA", "NXF/USD", "sell", 1.0, 10.0, order_id="S1")
        self.ob.cancel_order("S1")
        fills = self.ob.submit_order("rB", "NXF/USD", "buy", 1.0, 10.0)
        self.assertEqual(len(fills), 0)


# ═══════════════════════════════════════════════════════════════════
#  Snapshot & Fills
# ═══════════════════════════════════════════════════════════════════

class TestSnapshot(unittest.TestCase):

    def setUp(self):
        self.ob = OrderBook()

    def test_empty_snapshot(self):
        snap = self.ob.get_book_snapshot("NXF/USD")
        self.assertEqual(snap["pair"], "NXF/USD")
        self.assertEqual(snap["asks"], [])
        self.assertEqual(snap["bids"], [])

    def test_depth_limit(self):
        for i in range(30):
            self.ob.submit_order("rA", "NXF/USD", "sell", 1.0 + i * 0.01, 1.0)
        snap = self.ob.get_book_snapshot("NXF/USD", depth=5)
        self.assertEqual(len(snap["asks"]), 5)

    def test_fills_returned(self):
        self.ob.submit_order("rA", "NXF/USD", "sell", 1.0, 10.0)
        self.ob.submit_order("rB", "NXF/USD", "buy", 1.0, 10.0)
        fills = self.ob.get_fills()
        self.assertEqual(len(fills), 1)
        self.assertEqual(fills[0]["quantity"], 10.0)

    def test_fills_limit(self):
        for _i in range(60):
            self.ob.submit_order("rA", "NXF/USD", "sell", 1.0, 1.0)
            self.ob.submit_order("rB", "NXF/USD", "buy", 1.0, 1.0)
        fills = self.ob.get_fills(limit=10)
        self.assertEqual(len(fills), 10)

    def test_pairs_property(self):
        self.ob.submit_order("rA", "NXF/USD", "sell", 1.0, 1.0)
        self.ob.submit_order("rB", "ETH/USD", "buy", 100.0, 1.0)
        self.assertIn("NXF/USD", self.ob.pairs)
        self.assertIn("ETH/USD", self.ob.pairs)


# ═══════════════════════════════════════════════════════════════════
#  Multi-pair isolation
# ═══════════════════════════════════════════════════════════════════

class TestMultiPair(unittest.TestCase):

    def test_different_pairs_dont_match(self):
        ob = OrderBook()
        ob.submit_order("rA", "NXF/USD", "sell", 1.0, 10.0)
        fills = ob.submit_order("rB", "ETH/USD", "buy", 1.0, 10.0)
        self.assertEqual(len(fills), 0)

    def test_separate_book_state(self):
        ob = OrderBook()
        ob.submit_order("rA", "NXF/USD", "sell", 1.0, 10.0)
        ob.submit_order("rB", "ETH/USD", "sell", 100.0, 5.0)
        nxf = ob.get_book_snapshot("NXF/USD")
        eth = ob.get_book_snapshot("ETH/USD")
        self.assertEqual(nxf["ask_count"], 1)
        self.assertEqual(eth["ask_count"], 1)


# ═══════════════════════════════════════════════════════════════════
#  Edge cases
# ═══════════════════════════════════════════════════════════════════

class TestEdgeCases(unittest.TestCase):

    def test_zero_price_order(self):
        """Zero price should still be accepted (free order)."""
        ob = OrderBook()
        ob.submit_order("rA", "NXF/USD", "sell", 0.0, 10.0)
        snap = ob.get_book_snapshot("NXF/USD")
        self.assertEqual(snap["ask_count"], 1)

    def test_very_small_quantity(self):
        ob = OrderBook()
        ob.submit_order("rA", "NXF/USD", "sell", 1.0, 0.00001)
        fills = ob.submit_order("rB", "NXF/USD", "buy", 1.0, 0.00001)
        self.assertEqual(len(fills), 1)
        self.assertAlmostEqual(fills[0].quantity, 0.00001, places=8)

    def test_large_quantity(self):
        ob = OrderBook()
        ob.submit_order("rA", "NXF/USD", "sell", 1.0, 1e15)
        fills = ob.submit_order("rB", "NXF/USD", "buy", 1.0, 1e15)
        self.assertEqual(len(fills), 1)
        self.assertEqual(fills[0].quantity, 1e15)

    def test_self_trade(self):
        """Same account on both sides should still match (no prevention)."""
        ob = OrderBook()
        ob.submit_order("rAlice", "NXF/USD", "sell", 1.0, 10.0)
        fills = ob.submit_order("rAlice", "NXF/USD", "buy", 1.0, 10.0)
        self.assertEqual(len(fills), 1)

    def test_get_order_unknown(self):
        ob = OrderBook()
        self.assertIsNone(ob.get_order("NONEXISTENT"))
