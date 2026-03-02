"""
Price Oracle support for NexaFlow — XLS-47 equivalent.

On-ledger price feeds that any account can publish:
  - OracleSet: create or update an oracle with price data
  - OracleDelete: remove an oracle
  - Aggregate price: compute median/mean from multiple oracles

Each oracle can carry up to 10 price entries per update,
each with an asset pair, price, and scale.
"""

from __future__ import annotations

import statistics
import time
from dataclasses import dataclass, field


@dataclass
class PriceEntry:
    """A single price data point within an oracle."""
    base_asset: str          # e.g. "NXF"
    quote_asset: str         # e.g. "USD"
    price: float             # the value
    scale: int = 0           # decimal scale (price * 10^-scale)
    timestamp: float = field(default_factory=time.time)

    @property
    def scaled_price(self) -> float:
        return self.price * (10 ** -self.scale)

    def to_dict(self) -> dict:
        return {
            "base_asset": self.base_asset,
            "quote_asset": self.quote_asset,
            "price": self.price,
            "scale": self.scale,
            "scaled_price": self.scaled_price,
            "timestamp": self.timestamp,
        }


@dataclass
class Oracle:
    """A single oracle instance owned by an account."""
    oracle_id: str
    owner: str
    provider: str = ""
    asset_class: str = ""    # e.g. "currency", "commodity"
    uri: str = ""            # optional metadata URI
    prices: list[PriceEntry] = field(default_factory=list)
    last_update: float = field(default_factory=time.time)
    created_at: float = field(default_factory=time.time)
    document_id: int = 0     # owner-scoped sequence number

    def to_dict(self) -> dict:
        return {
            "oracle_id": self.oracle_id,
            "owner": self.owner,
            "provider": self.provider,
            "asset_class": self.asset_class,
            "uri": self.uri,
            "document_id": self.document_id,
            "last_update": self.last_update,
            "prices": [p.to_dict() for p in self.prices],
        }


MAX_PRICE_ENTRIES = 10
MAX_ORACLES_PER_ACCOUNT = 100


class OracleManager:
    """Manages all on-ledger price oracles."""

    def __init__(self):
        self.oracles: dict[str, Oracle] = {}
        self._owner_index: dict[str, list[str]] = {}
        self._next_seq: dict[str, int] = {}

    def _make_id(self, owner: str, doc_id: int) -> str:
        return f"{owner}:{doc_id}"

    def set_oracle(self, owner: str, document_id: int | None = None,
                   provider: str = "", asset_class: str = "",
                   uri: str = "",
                   prices: list[dict] | None = None) -> tuple[bool, str, Oracle | None]:
        """Create or update an oracle.  Returns (ok, msg, oracle)."""
        if document_id is None:
            seq = self._next_seq.get(owner, 0)
            document_id = seq
            self._next_seq[owner] = seq + 1

        oid = self._make_id(owner, document_id)

        if prices and len(prices) > MAX_PRICE_ENTRIES:
            return False, f"Max {MAX_PRICE_ENTRIES} price entries per update", None

        existing = self.oracles.get(oid)

        if existing is None:
            # Create new
            owned = self._owner_index.get(owner, [])
            if len(owned) >= MAX_ORACLES_PER_ACCOUNT:
                return False, f"Max {MAX_ORACLES_PER_ACCOUNT} oracles per account", None

            oracle = Oracle(
                oracle_id=oid,
                owner=owner,
                provider=provider,
                asset_class=asset_class,
                uri=uri,
                document_id=document_id,
            )
            if prices:
                oracle.prices = [
                    PriceEntry(
                        base_asset=p.get("base_asset", ""),
                        quote_asset=p.get("quote_asset", ""),
                        price=p.get("price", 0),
                        scale=p.get("scale", 0),
                    )
                    for p in prices
                ]
            oracle.last_update = time.time()
            self.oracles[oid] = oracle
            self._owner_index.setdefault(owner, []).append(oid)
            self._next_seq[owner] = max(
                self._next_seq.get(owner, 0), document_id + 1)
            return True, "Oracle created", oracle

        # Update existing
        if existing.owner != owner:
            return False, "Not oracle owner", None

        if provider:
            existing.provider = provider
        if asset_class:
            existing.asset_class = asset_class
        if uri:
            existing.uri = uri
        if prices:
            existing.prices = [
                PriceEntry(
                    base_asset=p.get("base_asset", ""),
                    quote_asset=p.get("quote_asset", ""),
                    price=p.get("price", 0),
                    scale=p.get("scale", 0),
                )
                for p in prices
            ]
        existing.last_update = time.time()
        return True, "Oracle updated", existing

    def delete_oracle(self, owner: str,
                      document_id: int) -> tuple[bool, str]:
        """Delete an oracle."""
        oid = self._make_id(owner, document_id)
        oracle = self.oracles.get(oid)
        if oracle is None:
            return False, "Oracle not found"
        if oracle.owner != owner:
            return False, "Not oracle owner"
        del self.oracles[oid]
        owned = self._owner_index.get(owner, [])
        if oid in owned:
            owned.remove(oid)
        return True, "Oracle deleted"

    def get_oracle(self, owner: str, document_id: int) -> Oracle | None:
        return self.oracles.get(self._make_id(owner, document_id))

    def get_oracles_by_owner(self, owner: str) -> list[Oracle]:
        oids = self._owner_index.get(owner, [])
        return [self.oracles[oid] for oid in oids if oid in self.oracles]

    def get_aggregate_price(self, base_asset: str, quote_asset: str,
                            trim: int = 20,
                            max_age: float = 3600.0) -> dict | None:
        """
        Compute an aggregate price from all oracles reporting this pair.
        Uses trimmed mean (removing top/bottom `trim`% outliers).
        Returns dict with mean, median, and count, or None.
        """
        now = time.time()
        values: list[float] = []

        for oracle in self.oracles.values():
            for pe in oracle.prices:
                if pe.base_asset == base_asset and pe.quote_asset == quote_asset:
                    if now - pe.timestamp <= max_age:
                        values.append(pe.scaled_price)

        if not values:
            return None

        values.sort()
        # Trim outliers
        trim_count = max(0, int(len(values) * trim / 100))
        if trim_count > 0 and len(values) > 2 * trim_count:
            trimmed = values[trim_count: -trim_count]
        else:
            trimmed = values

        return {
            "base_asset": base_asset,
            "quote_asset": quote_asset,
            "mean": statistics.mean(trimmed) if trimmed else 0,
            "median": statistics.median(trimmed) if trimmed else 0,
            "count": len(values),
            "trimmed_count": len(trimmed),
            "entire_set": values,
        }

    def get_all_oracles(self) -> list[dict]:
        return [o.to_dict() for o in self.oracles.values()]
