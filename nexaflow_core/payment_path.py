"""
Payment path finding for NexaFlow.

Implements a simplified version of NexaFlow's path-finding algorithm:
  - BFS/DFS through the trust graph to find multi-hop IOU paths
  - Native NXF direct transfers (no path needed)
  - Liquidity aggregation along discovered paths
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
    ):
        # Each hop: (account, currency, issuer)
        self.hops = hops
        self.max_amount = max_amount
        self.source = source
        self.destination = destination
        self.currency = currency
        self.hop_count = len(hops)

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "destination": self.destination,
            "currency": self.currency,
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
        return f"Path({self.source[:8]} -> {path_str} -> {self.destination[:8]}, max={self.max_amount:.4f})"


class PathFinder:
    """
    Discovers payment paths through the trust graph.

    Supports:
      - Direct native NXF transfers
      - Single-hop IOU payments (sender->issuer or issuer->receiver)
      - Multi-hop IOU rippling through intermediaries
    """

    def __init__(self, trust_graph: TrustGraph, ledger):
        self.graph = trust_graph
        self.ledger = ledger

    def find_paths(
        self,
        source: str,
        destination: str,
        currency: str,
        amount: float,
        max_hops: int = 6,
        max_paths: int = 5,
    ) -> list[PaymentPath]:
        """
        Find up to max_paths payment paths from source to destination
        for the given currency and amount.
        """
        if currency == "NXF":
            return self._find_native_path(source, destination, amount)

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
