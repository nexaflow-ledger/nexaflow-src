"""
Extended security tests for Order Book / DEX engine (nexaflow_core.order_book).

Covers:
  - Zero price / zero quantity orders
  - Negative price / negative quantity orders
  - Self-trading (same account on both sides)
  - NaN / Inf price manipulation
  - Wash trading patterns
  - Cancellation of already-filled orders
  - Cancellation race: cancel while matching
  - Price-time priority correctness under stress
  - Very large order quantities
  - Float precision in matching
  - Order book depth limits
  - Duplicate order IDs
  - Empty pair strings
"""

from __future__ import annotations

import math
import time
import unittest

from nexaflow_core.order_book import Fill, Order, OrderBook


class OrderBookTestBase(unittest.TestCase):
    def setUp(self):
        self.ob = OrderBook()


# ═══════════════════════════════════════════════════════════════════
#  Zero / Negative Price and Quantity
# ═══════════════════════════════════════════════════════════════════

class TestZeroNegativeValues(OrderBookTestBase):

    def test_zero_price_order(self):
        """
        VULN: Zero-price sell orders should not be valid — a sell at price 0
        means giving away assets for free.
        """
        fills = self.ob.submit_order("alice", "NXF/USD", "sell", 0.0, 100.0)
        # Order accepted (no validation)
        order = list(self.ob._orders.values())[0]
        self.assertEqual(order.price, 0.0)
        # A buy at any price should match
        fills = self.ob.submit_order("bob", "NXF/USD", "buy", 0.01, 100.0)
        self.assertGreater(len(fills), 0)
        self.assertEqual(fills[0].price, 0.0)  # filled at zero

    def test_negative_price_order(self):
        """
        VULN: Negative price creates an inverted sort_key, potentially
        breaking price-time priority.
        """
        fills = self.ob.submit_order("alice", "NXF/USD", "sell", -1.0, 100.0)
        order = list(self.ob._orders.values())[0]
        self.assertEqual(order.price, -1.0)

    def test_zero_quantity_order(self):
        """
        VULN: Zero-quantity order takes space in the book
        but can never be filled.
        """
        fills = self.ob.submit_order("alice", "NXF/USD", "buy", 1.0, 0.0)
        self.assertEqual(len(fills), 0)
        order = list(self.ob._orders.values())[0]
        self.assertEqual(order.remaining, 0.0)
        # Order should be marked "filled" since remaining == 0
        self.assertEqual(order.status, "filled")

    def test_negative_quantity_order(self):
        """
        VULN: Negative quantity makes remaining negative, which breaks
        the matching engine's fill_qty = min(taker.remaining, best.remaining).
        """
        fills = self.ob.submit_order("alice", "NXF/USD", "sell", 1.0, -100.0)
        order = list(self.ob._orders.values())[0]
        self.assertEqual(order.quantity, -100.0)


# ═══════════════════════════════════════════════════════════════════
#  Self-Trading
# ═══════════════════════════════════════════════════════════════════

class TestSelfTrading(OrderBookTestBase):

    def test_self_trade_allowed(self):
        """
        VULN: Same account can trade against itself.
        This enables wash trading for volume inflation.
        """
        self.ob.submit_order("alice", "NXF/USD", "sell", 1.0, 100.0)
        fills = self.ob.submit_order("alice", "NXF/USD", "buy", 1.0, 100.0)
        self.assertEqual(len(fills), 1)
        self.assertEqual(fills[0].quantity, 100.0)
        # Both maker and taker are the same account
        maker = self.ob.get_order(fills[0].maker_order_id)
        taker = self.ob.get_order(fills[0].taker_order_id)
        self.assertEqual(maker.account, taker.account)

    def test_wash_trading_inflates_volume(self):
        """Repeated self-trades inflate fill history."""
        for i in range(100):
            self.ob.submit_order("alice", "NXF/USD", "sell", 1.0, 10.0, f"s{i}")
            self.ob.submit_order("alice", "NXF/USD", "buy", 1.0, 10.0, f"b{i}")
        fills = self.ob.get_fills(limit=200)
        self.assertEqual(len(fills), 100)


# ═══════════════════════════════════════════════════════════════════
#  NaN / Inf Price Injection
# ═══════════════════════════════════════════════════════════════════

class TestNaNInfPrices(OrderBookTestBase):

    def test_nan_price_order(self):
        """
        VULN: NaN price breaks all comparisons in _match().
        NaN < x and NaN > x are both False, so price checks never break.
        """
        self.ob.submit_order("alice", "NXF/USD", "sell", float("nan"), 100.0)
        order = list(self.ob._orders.values())[0]
        self.assertTrue(math.isnan(order.price))
        # Buy should NOT match a NaN ask, but let's see
        fills = self.ob.submit_order("bob", "NXF/USD", "buy", 1000.0, 100.0)
        # NaN > 1000.0 is False, so the price check passes (breaks the loop)
        # This means NaN prices create phantom liquidity that can't be matched

    def test_inf_price_sell(self):
        """
        VULN: Infinite price sell is unmatchable (no one will pay infinity),
        but it sits on the book forever.
        """
        self.ob.submit_order("alice", "NXF/USD", "sell", float("inf"), 100.0)
        fills = self.ob.submit_order("bob", "NXF/USD", "buy", 1e18, 100.0)
        self.assertEqual(len(fills), 0)  # inf > 1e18

    def test_negative_inf_price_sell(self):
        """Negative infinity sell price — matched by any buy."""
        self.ob.submit_order("alice", "NXF/USD", "sell", float("-inf"), 100.0)
        fills = self.ob.submit_order("bob", "NXF/USD", "buy", 0.01, 100.0)
        self.assertGreater(len(fills), 0)

    def test_inf_quantity(self):
        """Infinite quantity monopolizes the entire book side."""
        self.ob.submit_order("alice", "NXF/USD", "sell", 1.0, float("inf"))
        fills = self.ob.submit_order("bob", "NXF/USD", "buy", 1.0, 1000.0)
        if fills:
            self.assertEqual(fills[0].quantity, 1000.0)
            maker = self.ob.get_order(fills[0].maker_order_id)
            # Remaining is inf - 1000 = inf
            self.assertTrue(math.isinf(maker.remaining))


# ═══════════════════════════════════════════════════════════════════
#  Cancellation Edge Cases
# ═══════════════════════════════════════════════════════════════════

class TestCancellationEdgeCases(OrderBookTestBase):

    def test_cancel_filled_order(self):
        """Cannot cancel an already-filled order."""
        self.ob.submit_order("alice", "NXF/USD", "sell", 1.0, 100.0, "s1")
        self.ob.submit_order("bob", "NXF/USD", "buy", 1.0, 100.0)
        self.assertFalse(self.ob.cancel_order("s1"))

    def test_cancel_unknown_order(self):
        self.assertFalse(self.ob.cancel_order("nonexistent"))

    def test_cancel_already_cancelled(self):
        self.ob.submit_order("alice", "NXF/USD", "sell", 1.0, 100.0, "s1")
        self.assertTrue(self.ob.cancel_order("s1"))
        self.assertFalse(self.ob.cancel_order("s1"))

    def test_cancel_partially_filled(self):
        """Partially filled orders can still be cancelled."""
        self.ob.submit_order("alice", "NXF/USD", "sell", 1.0, 100.0, "s1")
        self.ob.submit_order("bob", "NXF/USD", "buy", 1.0, 50.0)
        order = self.ob.get_order("s1")
        self.assertEqual(order.status, "partially_filled")
        self.assertTrue(self.ob.cancel_order("s1"))
        self.assertEqual(order.status, "cancelled")


# ═══════════════════════════════════════════════════════════════════
#  Price-Time Priority
# ═══════════════════════════════════════════════════════════════════

class TestPriceTimePriority(OrderBookTestBase):

    def test_best_ask_matched_first(self):
        """Lowest-price ask should be matched first."""
        self.ob.submit_order("alice", "NXF/USD", "sell", 2.0, 100.0, "s_high")
        self.ob.submit_order("bob", "NXF/USD", "sell", 1.0, 100.0, "s_low")
        fills = self.ob.submit_order("charlie", "NXF/USD", "buy", 2.0, 50.0)
        self.assertEqual(fills[0].maker_order_id, "s_low")
        self.assertEqual(fills[0].price, 1.0)

    def test_best_bid_matched_first(self):
        """Highest-price bid should be matched first."""
        self.ob.submit_order("alice", "NXF/USD", "buy", 1.0, 100.0, "b_low")
        self.ob.submit_order("bob", "NXF/USD", "buy", 2.0, 100.0, "b_high")
        fills = self.ob.submit_order("charlie", "NXF/USD", "sell", 1.0, 50.0)
        self.assertEqual(fills[0].maker_order_id, "b_high")
        self.assertEqual(fills[0].price, 2.0)

    def test_time_priority_at_same_price(self):
        """Earlier order wins at same price."""
        self.ob.submit_order("first", "NXF/USD", "sell", 1.0, 100.0, "s1")
        time.sleep(0.01)  # tiny delay for timestamp difference
        self.ob.submit_order("second", "NXF/USD", "sell", 1.0, 100.0, "s2")
        fills = self.ob.submit_order("buyer", "NXF/USD", "buy", 1.0, 50.0)
        self.assertEqual(fills[0].maker_order_id, "s1")

    def test_many_orders_stress(self):
        """100 asks at various prices, verify correct matching order."""
        for i in range(100):
            self.ob.submit_order(f"seller{i}", "NXF/USD", "sell", float(100 - i), 10.0)
        fills = self.ob.submit_order("buyer", "NXF/USD", "buy", 100.0, 100.0)
        # Should match from cheapest (1.0) upward
        prices = [f.price for f in fills]
        # First fill should be the lowest price
        self.assertEqual(prices[0], 1.0)
        # Prices should be non-decreasing
        for i in range(1, len(prices)):
            self.assertGreaterEqual(prices[i], prices[i - 1])


# ═══════════════════════════════════════════════════════════════════
#  Float Precision in Matching
# ═══════════════════════════════════════════════════════════════════

class TestFloatPrecisionMatching(OrderBookTestBase):

    def test_tiny_remainder_after_fill(self):
        """
        Float precision can leave tiny remainders (e.g., 1e-15)
        instead of exactly zero after matching.
        """
        self.ob.submit_order("alice", "NXF/USD", "sell", 1.0, 0.1, "s1")
        # Buy exactly 0.1 — but float subtraction might not yield 0.0
        fills = self.ob.submit_order("bob", "NXF/USD", "buy", 1.0, 0.1)
        order = self.ob.get_order("s1")
        # remaining should be exactly 0 or very close
        self.assertAlmostEqual(order.remaining, 0.0, places=10)

    def test_many_small_fills_accumulate_error(self):
        """100 fills of 0.01 against a 1.0 order — precision check."""
        self.ob.submit_order("alice", "NXF/USD", "sell", 1.0, 1.0, "s1")
        total_filled = 0.0
        for i in range(100):
            fills = self.ob.submit_order(f"buyer{i}", "NXF/USD", "buy", 1.0, 0.01)
            for f in fills:
                total_filled += f.quantity
        self.assertAlmostEqual(total_filled, 1.0, places=10)


# ═══════════════════════════════════════════════════════════════════
#  Duplicate Order IDs
# ═══════════════════════════════════════════════════════════════════

class TestDuplicateOrderIDs(OrderBookTestBase):

    def test_same_order_id_overwrites(self):
        """
        VULN: Submitting with the same order_id replaces the previous
        entry in _orders dict. The old order still sits on the book.
        """
        self.ob.submit_order("alice", "NXF/USD", "sell", 1.0, 100.0, "dup")
        self.ob.submit_order("alice", "NXF/USD", "sell", 2.0, 200.0, "dup")
        # _orders["dup"] now points to the second order
        order = self.ob.get_order("dup")
        self.assertEqual(order.price, 2.0)
        # But the first order is still on the book!
        snapshot = self.ob.get_book_snapshot("NXF/USD")
        self.assertEqual(snapshot["ask_count"], 2)  # both are in asks list


# ═══════════════════════════════════════════════════════════════════
#  Empty / Special Pair Strings
# ═══════════════════════════════════════════════════════════════════

class TestEmptyPairStrings(OrderBookTestBase):

    def test_empty_pair(self):
        """Empty pair string should work (it's just a dict key)."""
        fills = self.ob.submit_order("alice", "", "sell", 1.0, 100.0)
        snapshot = self.ob.get_book_snapshot("")
        self.assertEqual(snapshot["ask_count"], 1)

    def test_pair_with_special_chars(self):
        pair = "🚀/💎"
        fills = self.ob.submit_order("alice", pair, "sell", 1.0, 100.0)
        snapshot = self.ob.get_book_snapshot(pair)
        self.assertEqual(snapshot["ask_count"], 1)


# ═══════════════════════════════════════════════════════════════════
#  Book Snapshot Depth
# ═══════════════════════════════════════════════════════════════════

class TestBookSnapshotDepth(OrderBookTestBase):

    def test_depth_limits_output(self):
        for i in range(50):
            self.ob.submit_order(f"s{i}", "NXF/USD", "sell", float(i + 1), 10.0)
        snapshot = self.ob.get_book_snapshot("NXF/USD", depth=5)
        self.assertEqual(len(snapshot["asks"]), 5)
        self.assertEqual(snapshot["ask_count"], 50)

    def test_depth_zero(self):
        self.ob.submit_order("alice", "NXF/USD", "sell", 1.0, 100.0)
        snapshot = self.ob.get_book_snapshot("NXF/USD", depth=0)
        self.assertEqual(len(snapshot["asks"]), 0)


# ═══════════════════════════════════════════════════════════════════
#  Fill History
# ═══════════════════════════════════════════════════════════════════

class TestFillHistory(OrderBookTestBase):

    def test_fill_history_limit(self):
        for i in range(100):
            self.ob.submit_order(f"s{i}", "NXF/USD", "sell", 1.0, 1.0, f"s{i}")
            self.ob.submit_order(f"b{i}", "NXF/USD", "buy", 1.0, 1.0, f"b{i}")
        fills = self.ob.get_fills(limit=10)
        self.assertEqual(len(fills), 10)

    def test_fills_have_all_fields(self):
        self.ob.submit_order("alice", "NXF/USD", "sell", 1.0, 100.0, "s1")
        self.ob.submit_order("bob", "NXF/USD", "buy", 1.0, 100.0, "b1")
        fills = self.ob.get_fills()
        self.assertEqual(len(fills), 1)
        f = fills[0]
        self.assertEqual(f["maker_order_id"], "s1")
        self.assertEqual(f["taker_order_id"], "b1")
        self.assertEqual(f["pair"], "NXF/USD")
        self.assertEqual(f["price"], 1.0)
        self.assertEqual(f["quantity"], 100.0)


if __name__ == "__main__":
    unittest.main()
