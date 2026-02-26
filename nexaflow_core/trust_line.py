"""
Trust-line management utilities for NexaFlow.

Provides higher-level trust-line operations:
  - Network-wide trust graph construction
  - Trust-line querying and aggregation
  - Rippling detection
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple, Set


class TrustGraph:
    """
    Builds and queries a directed graph of trust relationships
    across all accounts in the ledger.

    Edges: holder --trusts(currency, limit)--> issuer
    """

    def __init__(self):
        # adjacency: holder -> [(issuer, currency, limit, balance)]
        self._forward: Dict[str, List[Tuple[str, str, float, float]]] = {}
        # reverse:   issuer -> [(holder, currency, limit, balance)]
        self._reverse: Dict[str, List[Tuple[str, str, float, float]]] = {}

    def build_from_ledger(self, ledger) -> None:
        """Scan the ledger and populate the trust graph."""
        self._forward.clear()
        self._reverse.clear()
        for address, acc in ledger.accounts.items():
            for (currency, issuer), tl in acc.trust_lines.items():
                fwd = self._forward.setdefault(address, [])
                fwd.append((issuer, currency, tl.limit, tl.balance))
                rev = self._reverse.setdefault(issuer, [])
                rev.append((address, currency, tl.limit, tl.balance))

    def get_trustees(self, issuer: str) -> List[Tuple[str, str, float, float]]:
        """Return all holders that trust this issuer."""
        return self._reverse.get(issuer, [])

    def get_trusted_issuers(self, holder: str) -> List[Tuple[str, str, float, float]]:
        """Return all issuers this holder trusts."""
        return self._forward.get(holder, [])

    def has_trust(self, holder: str, issuer: str, currency: str) -> bool:
        """Check if holder has a trust line to issuer for currency."""
        for iss, cur, _, _ in self._forward.get(holder, []):
            if iss == issuer and cur == currency:
                return True
        return False

    def available_credit(
        self, holder: str, issuer: str, currency: str
    ) -> float:
        """How much more IOU the holder can receive from issuer."""
        for iss, cur, limit, balance in self._forward.get(holder, []):
            if iss == issuer and cur == currency:
                return max(0.0, limit - balance)
        return 0.0

    def all_currencies(self) -> Set[str]:
        """Return all currencies present in trust lines."""
        currencies: Set[str] = set()
        for edges in self._forward.values():
            for _, cur, _, _ in edges:
                currencies.add(cur)
        return currencies

    def summary(self) -> dict:
        holders = set(self._forward.keys())
        issuers = set(self._reverse.keys())
        total_lines = sum(len(v) for v in self._forward.values())
        return {
            "total_trust_lines": total_lines,
            "unique_holders": len(holders),
            "unique_issuers": len(issuers),
            "currencies": sorted(self.all_currencies()),
        }
