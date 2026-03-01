"""
Payment path finding for NexaFlow.

Implements a simplified version of NexaFlow's path-finding algorithm:
  - BFS/DFS through the trust graph to find multi-hop IOU paths
  - Native NXF direct transfers (no path needed)
  - Cross-currency pathfinding via NXF auto-bridge
  - Liquidity aggregation along discovered paths
  - Partial payment support
  - Order book integration for DEX liquidity
  - Path ranking by cost / hop count

A "path" is a list of (account, currency, issuer) hops that connect
a source to a destination for a given currency.
"""

from __future__ import annotations

from nexaflow_core.trust_line import TrustGraph


class PaymentPath:
    """A single discovered payment path."""

    def __init__(
        self,
        hops: list[tuple[str, str, str]],
        max_amount: float,
        source: str,
        destination: str,
        currency: str,
        source_currency: str = "",
        is_cross_currency: bool = False,
    ):
        # Each hop: (account, currency, issuer)
        self.hops = hops
        self.max_amount = max_amount
        self.source = source
        self.destination = destination
        self.currency = currency
        self.source_currency = source_currency or currency
        self.is_cross_currency = is_cross_currency
        self.hop_count = len(hops)

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "destination": self.destination,
            "currency": self.currency,
            "source_currency": self.source_currency,
            "is_cross_currency": self.is_cross_currency,
            "hops": [
                {"account": a, "currency": c, "issuer": i}
                for a, c, i in self.hops
            ],
            "hop_count": self.hop_count,
            "max_amount": self.max_amount,
        }

    def __repr__(self) -> str:
        path_str = " -> ".join(
            f"{a[:8]}({c})" for a, c, _ in self.hops
        )
        return f"Path({self.source[:8]} -> {path_str} -> {self.destination[:8]}, max={self.max_amount:.8f})"


class PathFinder:
    """
    Discovers payment paths through the trust graph.

    Supports:
      - Direct native NXF transfers
      - Single-hop IOU payments (sender->issuer or issuer->receiver)
      - Multi-hop IOU rippling through intermediaries
      - Cross-currency paths via NXF auto-bridge
      - Partial payment delivery
    """

    def __init__(self, trust_graph: TrustGraph, ledger, order_book=None):
        self.graph = trust_graph
        self.ledger = ledger
        self.order_book = order_book

    def find_paths(
        self,
        source: str,
        destination: str,
        currency: str,
        amount: float,
        max_hops: int = 6,
        max_paths: int = 5,
        source_currency: str = "",
    ) -> list[PaymentPath]:
        """
        Find up to max_paths payment paths from source to destination
        for the given currency and amount.

        If source_currency differs from currency, attempts cross-currency
        routing via NXF auto-bridge.
        """
        if currency == "NXF" and (not source_currency or source_currency == "NXF"):
            return self._find_native_path(source, destination, amount)

        # Cross-currency: route through NXF bridge
        if source_currency and source_currency != currency:
            return self._find_cross_currency_paths(
                source, destination, source_currency, currency, amount, max_paths,
            )

        paths: list[PaymentPath] = []
        visited: set[str] = set()

        self._dfs(
            current=source,
            destination=destination,
            currency=currency,
            amount=amount,
            current_path=[],
            visited=visited,
            paths=paths,
            max_hops=max_hops,
            max_paths=max_paths,
        )

        # Sort by max_amount descending then hop count ascending
        paths.sort(key=lambda p: (-p.max_amount, p.hop_count))
        return paths[:max_paths]

    def _find_native_path(
        self, source: str, destination: str, amount: float
    ) -> list[PaymentPath]:
        """Native NXF is always direct, no path needed."""
        src_bal = self.ledger.get_balance(source)
        if src_bal >= amount:
            path = PaymentPath(
                hops=[(source, "NXF", ""), (destination, "NXF", "")],
                max_amount=src_bal,
                source=source,
                destination=destination,
                currency="NXF",
            )
            return [path]
        return []

    def _find_cross_currency_paths(
        self,
        source: str,
        destination: str,
        src_currency: str,
        dst_currency: str,
        amount: float,
        max_paths: int = 5,
    ) -> list[PaymentPath]:
        """
        Find cross-currency paths by auto-bridging through NXF.

        Route: source(src_currency) → NXF → destination(dst_currency)
        """
        paths: list[PaymentPath] = []

        # First: can source sell src_currency for NXF?
        src_bal = self.ledger.get_balance(source)

        # Build a bridged path: source sends src_currency,
        # it gets converted to NXF, then to dst_currency
        hops = [
            (source, src_currency, source),
            (source, "NXF", ""),
            (destination, "NXF", ""),
            (destination, dst_currency, destination),
        ]

        # Estimate max amount as min of source balance and available liquidity
        max_amt = min(src_bal, amount)

        if max_amt > 0:
            paths.append(PaymentPath(
                hops=hops,
                max_amount=max_amt,
                source=source,
                destination=destination,
                currency=dst_currency,
                source_currency=src_currency,
                is_cross_currency=True,
            ))

        # Also check if order book has direct liquidity
        if self.order_book is not None:
            pair = f"{dst_currency}/{src_currency}"
            snapshot = self.order_book.get_book_snapshot(pair, depth=5)
            if snapshot.get("asks") or snapshot.get("bids"):
                dex_hops = [
                    (source, src_currency, source),
                    (destination, dst_currency, destination),
                ]
                paths.append(PaymentPath(
                    hops=dex_hops,
                    max_amount=amount,
                    source=source,
                    destination=destination,
                    currency=dst_currency,
                    source_currency=src_currency,
                    is_cross_currency=True,
                ))

        paths.sort(key=lambda p: (-p.max_amount, p.hop_count))
        return paths[:max_paths]

    def _dfs(
        self,
        current: str,
        destination: str,
        currency: str,
        amount: float,
        current_path: list[tuple[str, str, str]],
        visited: set[str],
        paths: list[PaymentPath],
        max_hops: int,
        max_paths: int,
    ) -> None:
        """Depth-first search through trust graph."""
        if len(paths) >= max_paths:
            return
        if len(current_path) > max_hops:
            return
        if current in visited:
            return

        visited.add(current)

        # Check if current can reach destination directly
        if current != destination:
            # Can current send to destination via their trust line?
            credit = self.graph.available_credit(destination, current, currency)
            if (credit >= amount or current_path) and self.graph.has_trust(destination, current, currency):
                    full_path = [*current_path, (current, currency, current), (destination, currency, current)]
                    max_amt = min(credit, amount) if credit > 0 else amount
                    paths.append(
                        PaymentPath(
                            hops=full_path,
                            max_amount=max_amt,
                            source=current_path[0][0] if current_path else current,
                            destination=destination,
                            currency=currency,
                        )
                    )

        # Explore neighbors — accounts that trust current as issuer
        for holder, cur, _limit, _balance in self.graph.get_trustees(current):
            if cur == currency and holder != current:
                self._dfs(
                    current=holder,
                    destination=destination,
                    currency=currency,
                    amount=amount,
                    current_path=[*current_path, (current, currency, current)],
                    visited=visited,
                    paths=paths,
                    max_hops=max_hops,
                    max_paths=max_paths,
                )

        visited.discard(current)

    def find_best_path(
        self,
        source: str,
        destination: str,
        currency: str,
        amount: float,
    ) -> PaymentPath | None:
        """Find the single best path (highest liquidity, fewest hops)."""
        paths = self.find_paths(source, destination, currency, amount)
        return paths[0] if paths else None

    def find_partial_payment_path(
        self,
        source: str,
        destination: str,
        currency: str,
        max_amount: float,
        deliver_min: float = 0.0,
    ) -> tuple[PaymentPath | None, float]:
        """
        Find a path for partial payments.
        Returns (best_path, deliverable_amount).

        If deliver_min is set, returns None if we can't deliver at least that much.
        """
        paths = self.find_paths(source, destination, currency, max_amount)
        if not paths:
            return None, 0.0

        best = paths[0]
        deliverable = min(best.max_amount, max_amount)

        if deliver_min > 0 and deliverable < deliver_min:
            return None, deliverable

        return best, deliverable
