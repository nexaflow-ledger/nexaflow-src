"""
Order Book / DEX matching engine for NexaFlow.

Implements a limit-order book that matches OfferCreate
transactions within the ledger.

Each "book" is identified by a trading pair string such as
``"NXF/USD"`` (base/counter).  Orders on the **bid** side want
to buy the base, orders on the **ask** side want to sell the base.

Matching follows price-time priority:
  • Best price first (lowest ask, highest bid).
  • Among equal prices, the earliest order wins.

Advanced features:
  • Immediate-or-Cancel (IoC) — fill what you can, cancel the rest
  • Fill-or-Kill (FoK) — fill entirely or cancel entirely
  • Time-in-Force expiration — orders expire after a set timestamp
  • Auto-bridging through NXF — cross-currency pairs route via NXF

Usage:
    ob = OrderBook()
    fills = ob.submit_order(order)
    snapshot = ob.get_book_snapshot("NXF/USD")
"""

from __future__ import annotations

import bisect
import contextlib
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass(order=True)
class Order:
    """A single limit order."""

    # Fields used for sorting (price-time priority)
    sort_key: tuple[float, float] = field(init=False, repr=False)

    order_id: str = ""
    account: str = ""
    pair: str = ""           # e.g. "NXF/USD"
    side: str = "buy"        # "buy" (bid) or "sell" (ask)
    price: float = 0.0       # price of base in units of counter
    quantity: float = 0.0    # quantity of base
    remaining: float = 0.0
    timestamp: float = field(default_factory=time.time)
    status: str = "open"     # open | partially_filled | filled | cancelled
    # Advanced order types
    time_in_force: str = "GTC"  # GTC (Good-til-Cancelled) | IOC | FOK
    expiration: float = 0.0     # Unix timestamp, 0 = never expires

    def __post_init__(self):
        if self.remaining == 0.0:
            self.remaining = self.quantity
        # Asks: lowest price first.  Bids: highest price first (negate).
        if self.side == "sell":
            self.sort_key = (self.price, self.timestamp)
        else:
            self.sort_key = (-self.price, self.timestamp)

    @property
    def is_expired(self) -> bool:
        if self.expiration <= 0:
            return False
        return time.time() >= self.expiration

    def to_dict(self) -> dict:
        return {
            "order_id": self.order_id,
            "account": self.account,
            "pair": self.pair,
            "side": self.side,
            "price": self.price,
            "quantity": self.quantity,
            "remaining": self.remaining,
            "timestamp": self.timestamp,
            "status": self.status,
            "time_in_force": self.time_in_force,
            "expiration": self.expiration,
        }


@dataclass
class Fill:
    """Record of a single match between two orders."""
    maker_order_id: str
    taker_order_id: str
    pair: str
    price: float
    quantity: float
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "maker_order_id": self.maker_order_id,
            "taker_order_id": self.taker_order_id,
            "pair": self.pair,
            "price": self.price,
            "quantity": self.quantity,
            "timestamp": self.timestamp,
        }


class OrderBook:
    """
    In-memory order book supporting multiple trading pairs.

    Maintains sorted bid/ask lists and matches incoming orders
    against resting liquidity using price-time priority.
    """

    def __init__(self):
        # pair -> sorted list of Order (asks ascending, bids descending)
        self._asks: dict[str, list[Order]] = {}
        self._bids: dict[str, list[Order]] = {}
        self._orders: dict[str, Order] = {}  # order_id -> Order
        self._fills: list[Fill] = []
        self._next_id: int = 1

    # ── public API ───────────────────────────────────────────────

    def submit_order(
        self,
        account: str,
        pair: str,
        side: str,
        price: float,
        quantity: float,
        order_id: str | None = None,
        time_in_force: str = "GTC",
        expiration: float = 0.0,
    ) -> list[Fill]:
        """
        Submit a new limit order.  Returns a list of immediate fills
        (may be empty if no match).

        time_in_force:
          - GTC: Good-til-Cancelled (default) — rest on book if not fully filled
          - IOC: Immediate-or-Cancel — fill what matches, cancel remainder
          - FOK: Fill-or-Kill — fill entirely or reject
        """
        if order_id is None:
            order_id = f"ORD-{self._next_id:06d}"
            self._next_id += 1

        # Purge expired orders before matching
        self._purge_expired(pair)

        order = Order(
            order_id=order_id,
            account=account,
            pair=pair,
            side=side,
            price=price,
            quantity=quantity,
            remaining=quantity,
            time_in_force=time_in_force,
            expiration=expiration,
        )

        # FOK: pre-check liquidity
        if time_in_force == "FOK":
            available = self._available_liquidity(order)
            if available < quantity:
                order.status = "cancelled"
                self._orders[order.order_id] = order
                return []

        fills = self._match(order)

        # IOC: cancel any remaining
        if time_in_force == "IOC" and order.remaining > 0:
            order.status = "cancelled"
        elif order.remaining > 0:
            # GTC: rest on the book
            order.status = "partially_filled" if order.remaining < quantity else "open"
            self._insert(order)
        else:
            order.status = "filled"

        self._orders[order.order_id] = order
        return fills

    def submit_auto_bridged_order(
        self,
        account: str,
        src_currency: str,
        dst_currency: str,
        side: str,
        amount: float,
        order_id: str | None = None,
    ) -> list[Fill]:
        """
        Auto-bridge a cross-currency order through NXF.

        e.g., USD→EUR becomes USD→NXF then NXF→EUR.
        Returns combined fills from both legs.
        """
        if src_currency == "NXF" or dst_currency == "NXF":
            # Direct pair, no bridging needed
            pair = f"{dst_currency}/{src_currency}" if side == "buy" else f"{src_currency}/{dst_currency}"
            return self.submit_order(account, pair, side, 0.0, amount, order_id)

        all_fills: list[Fill] = []

        # Leg 1: sell src_currency for NXF
        pair1 = f"NXF/{src_currency}"
        id1 = f"{order_id or 'AB'}-leg1"
        fills1 = self.submit_order(account, pair1, "buy", 0.0, amount, id1)
        all_fills.extend(fills1)

        # Compute NXF received from leg 1
        nxf_received = sum(f.quantity for f in fills1)
        if nxf_received <= 0:
            return all_fills

        # Leg 2: buy dst_currency with NXF
        pair2 = f"{dst_currency}/NXF"
        id2 = f"{order_id or 'AB'}-leg2"
        fills2 = self.submit_order(account, pair2, "buy", 0.0, nxf_received, id2)
        all_fills.extend(fills2)

        return all_fills

    def cancel_order(self, order_id: str) -> bool:
        """Cancel a resting order.  Returns True if found and cancelled."""
        order = self._orders.get(order_id)
        if order is None or order.status in ("filled", "cancelled"):
            return False

        order.status = "cancelled"
        # Remove from book
        book = self._asks if order.side == "sell" else self._bids
        lst = book.get(order.pair, [])
        with contextlib.suppress(ValueError):
            lst.remove(order)
        return True

    def get_order(self, order_id: str) -> Order | None:
        return self._orders.get(order_id)

    def get_book_snapshot(self, pair: str, depth: int = 20) -> dict:
        """Return top-of-book asks and bids for a pair."""
        asks = [o.to_dict() for o in self._asks.get(pair, [])[:depth]]
        bids = [o.to_dict() for o in self._bids.get(pair, [])[:depth]]
        return {
            "pair": pair,
            "asks": asks,
            "bids": bids,
            "ask_count": len(self._asks.get(pair, [])),
            "bid_count": len(self._bids.get(pair, [])),
        }

    def get_fills(self, limit: int = 50) -> list[dict]:
        return [f.to_dict() for f in self._fills[-limit:]]

    @property
    def pairs(self) -> list[str]:
        return sorted(set(list(self._asks.keys()) + list(self._bids.keys())))

    # ── matching engine ──────────────────────────────────────────

    def _match(self, taker: Order) -> list[Fill]:
        """Match an incoming order against resting orders."""
        fills: list[Fill] = []

        if taker.side == "buy":
            book = self._asks.get(taker.pair, [])
        else:
            book = self._bids.get(taker.pair, [])

        while taker.remaining > 0 and book:
            best = book[0]

            # Skip expired orders
            if best.is_expired:
                best.status = "cancelled"
                book.pop(0)
                continue

            # Price check (skip if taker price is 0 — market order)
            if taker.price > 0:
                if taker.side == "buy" and best.price > taker.price:
                    break
                if taker.side == "sell" and best.price < taker.price:
                    break

            fill_qty = min(taker.remaining, best.remaining)
            fill = Fill(
                maker_order_id=best.order_id,
                taker_order_id=taker.order_id,
                pair=taker.pair,
                price=best.price,
                quantity=fill_qty,
            )
            fills.append(fill)
            self._fills.append(fill)

            taker.remaining -= fill_qty
            best.remaining -= fill_qty

            if best.remaining <= 0:
                best.status = "filled"
                book.pop(0)
            else:
                best.status = "partially_filled"

        return fills

    def _available_liquidity(self, taker: Order) -> float:
        """Check how much liquidity is available for a taker order (for FOK)."""
        if taker.side == "buy":
            book = self._asks.get(taker.pair, [])
        else:
            book = self._bids.get(taker.pair, [])

        total = 0.0
        for order in book:
            if order.is_expired:
                continue
            if taker.price > 0:
                if taker.side == "buy" and order.price > taker.price:
                    break
                if taker.side == "sell" and order.price < taker.price:
                    break
            total += order.remaining
            if total >= taker.remaining:
                return total
        return total

    def _purge_expired(self, pair: str) -> int:
        """Remove expired orders from a pair's book. Returns count removed."""
        removed = 0
        for book in (self._asks.get(pair, []), self._bids.get(pair, [])):
            i = 0
            while i < len(book):
                if book[i].is_expired:
                    book[i].status = "cancelled"
                    book.pop(i)
                    removed += 1
                else:
                    i += 1
        return removed

    def _insert(self, order: Order) -> None:
        """Insert an order into the appropriate sorted book."""
        if order.side == "sell":
            book = self._asks.setdefault(order.pair, [])
        else:
            book = self._bids.setdefault(order.pair, [])
        bisect.insort(book, order)

    # ── integration helper ───────────────────────────────────────

    def process_offer_create(self, tx: Any) -> list[Fill]:
        """
        Convenience method to process an OfferCreate transaction.

        Expects ``tx.amount`` (taker_pays) and a ``taker_gets`` attribute
        or falls back to ``tx.destination`` conventions.
        """
        taker_pays = tx.amount  # what the offerer pays
        taker_gets = getattr(tx, "taker_gets", None)

        if taker_gets is None:
            return []

        # Determine pair, side, price
        base_currency = taker_gets.currency or "NXF"
        counter_currency = taker_pays.currency or "NXF"
        pair = f"{base_currency}/{counter_currency}"

        if taker_pays.value > 0:
            price = taker_pays.value / taker_gets.value
        else:
            price = 0.0

        return self.submit_order(
            account=tx.account,
            pair=pair,
            side="sell",
            price=price,
            quantity=taker_gets.value,
            order_id=getattr(tx, "tx_id", None),
        )
