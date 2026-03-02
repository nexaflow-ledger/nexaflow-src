"""
DirectoryNode implementation for NexaFlow.

Mirrors the XRP Ledger's DirectoryNode concept:
  - Owner directories: index all objects owned by an account
    (offers, trust lines, escrows, payment channels, checks, NFTs, etc.)
  - Offer directories: index offers for a particular currency pair

DirectoryNodes provide efficient enumeration of owned objects
without scanning the entire ledger state.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ObjectType(Enum):
    """Types of objects that can be stored in an owner directory."""
    TRUST_LINE = "trust_line"
    OFFER = "offer"
    ESCROW = "escrow"
    PAYMENT_CHANNEL = "payment_channel"
    CHECK = "check"
    NFTOKEN = "nftoken"
    NFTOKEN_OFFER = "nftoken_offer"
    TICKET = "ticket"
    AMM_POSITION = "amm_position"
    DID = "did"
    CREDENTIAL = "credential"
    HOOK = "hook"
    MPT = "mpt"


@dataclass
class DirectoryEntry:
    """A single entry in a directory node."""
    object_id: str
    object_type: ObjectType
    data: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "object_id": self.object_id,
            "type": self.object_type.value,
            "data": self.data,
        }


class DirectoryNode:
    """
    A page in a directory chain.

    Mirrors the XRP Ledger's DirectoryNode which stores up to
    PAGE_SIZE entries.  Overflow creates linked pages.
    """

    PAGE_SIZE = 32  # entries per page (XRPL uses 32)

    def __init__(self, directory_id: str, page_index: int = 0):
        self.directory_id = directory_id
        self.page_index = page_index
        self.entries: list[DirectoryEntry] = []
        self.next_page: DirectoryNode | None = None
        self.prev_page: DirectoryNode | None = None

    @property
    def is_full(self) -> bool:
        return len(self.entries) >= self.PAGE_SIZE

    @property
    def count(self) -> int:
        return len(self.entries)

    def add(self, entry: DirectoryEntry) -> "DirectoryNode":
        """
        Add an entry.  If this page is full, creates/uses the next
        page and returns that page.  Otherwise returns self.
        """
        if self.is_full:
            if self.next_page is None:
                self.next_page = DirectoryNode(
                    self.directory_id, self.page_index + 1
                )
                self.next_page.prev_page = self
            return self.next_page.add(entry)
        self.entries.append(entry)
        return self

    def remove(self, object_id: str) -> bool:
        """Remove an entry by object_id.  Returns True if found."""
        for i, e in enumerate(self.entries):
            if e.object_id == object_id:
                self.entries.pop(i)
                return True
        if self.next_page is not None:
            return self.next_page.remove(object_id)
        return False

    def find(self, object_id: str) -> DirectoryEntry | None:
        """Find an entry by ID across all pages."""
        for e in self.entries:
            if e.object_id == object_id:
                return e
        if self.next_page is not None:
            return self.next_page.find(object_id)
        return None

    def all_entries(self) -> list[DirectoryEntry]:
        """Collect all entries across all pages."""
        result = list(self.entries)
        if self.next_page is not None:
            result.extend(self.next_page.all_entries())
        return result

    def total_count(self) -> int:
        """Total entries across all pages."""
        n = len(self.entries)
        if self.next_page is not None:
            n += self.next_page.total_count()
        return n

    def to_dict(self) -> dict:
        return {
            "directory_id": self.directory_id,
            "page_index": self.page_index,
            "entries": [e.to_dict() for e in self.entries],
            "has_next": self.next_page is not None,
            "count": self.count,
        }


class OwnerDirectory:
    """
    Manages the owner directory for a single account.

    Indexes all ledger objects owned by the account, grouped by type.
    Automatically creates/extends DirectoryNode pages as needed.
    """

    def __init__(self, owner: str):
        self.owner = owner
        self._root = DirectoryNode(f"owner:{owner}")
        self._by_type: dict[ObjectType, list[str]] = {}

    @property
    def owner_count(self) -> int:
        """Total number of owned objects (matches AccountEntry.owner_count)."""
        return self._root.total_count()

    def add_object(
        self,
        object_id: str,
        object_type: ObjectType,
        data: dict | None = None,
    ) -> None:
        """Add an owned object to the directory."""
        entry = DirectoryEntry(object_id, object_type, data or {})
        self._root.add(entry)
        self._by_type.setdefault(object_type, []).append(object_id)

    def remove_object(self, object_id: str) -> bool:
        """Remove an owned object from the directory."""
        found = self._root.remove(object_id)
        if found:
            for otype, ids in self._by_type.items():
                if object_id in ids:
                    ids.remove(object_id)
                    break
        return found

    def get_objects(
        self, object_type: ObjectType | None = None
    ) -> list[DirectoryEntry]:
        """
        Get all owned objects, optionally filtered by type.
        """
        if object_type is None:
            return self._root.all_entries()
        target_ids = set(self._by_type.get(object_type, []))
        return [
            e for e in self._root.all_entries()
            if e.object_id in target_ids
        ]

    def get_object_ids(
        self, object_type: ObjectType | None = None
    ) -> list[str]:
        """Get just the IDs of owned objects."""
        if object_type is not None:
            return list(self._by_type.get(object_type, []))
        return [e.object_id for e in self._root.all_entries()]

    def has_object(self, object_id: str) -> bool:
        return self._root.find(object_id) is not None

    def to_dict(self) -> dict:
        type_counts = {
            otype.value: len(ids) for otype, ids in self._by_type.items()
        }
        return {
            "owner": self.owner,
            "total_objects": self.owner_count,
            "by_type": type_counts,
            "pages": self._root.to_dict(),
        }


class OfferDirectory:
    """
    Indexes DEX offers for a specific currency pair and price level.

    In the XRP Ledger, offer directories organise offers by
    (TakerPays, TakerGets) pair and exchange rate.  This simplified
    version groups by pair string.
    """

    def __init__(self, pair: str):
        self.pair = pair
        self._root = DirectoryNode(f"offers:{pair}")

    def add_offer(self, offer_id: str, owner: str, price: float,
                  quantity: float, side: str) -> None:
        self._root.add(DirectoryEntry(offer_id, ObjectType.OFFER, {
            "owner": owner,
            "price": price,
            "quantity": quantity,
            "side": side,
        }))

    def remove_offer(self, offer_id: str) -> bool:
        return self._root.remove(offer_id)

    def get_offers(self) -> list[DirectoryEntry]:
        return self._root.all_entries()

    @property
    def count(self) -> int:
        return self._root.total_count()

    def to_dict(self) -> dict:
        return {
            "pair": self.pair,
            "count": self.count,
            "offers": [e.to_dict() for e in self.get_offers()],
        }


class DirectoryManager:
    """
    Top-level manager for all owner and offer directories in the ledger.
    """

    def __init__(self):
        self._owner_dirs: dict[str, OwnerDirectory] = {}
        self._offer_dirs: dict[str, OfferDirectory] = {}

    def get_owner_dir(self, owner: str) -> OwnerDirectory:
        """Get or create the owner directory for an account."""
        if owner not in self._owner_dirs:
            self._owner_dirs[owner] = OwnerDirectory(owner)
        return self._owner_dirs[owner]

    def get_offer_dir(self, pair: str) -> OfferDirectory:
        """Get or create the offer directory for a pair."""
        if pair not in self._offer_dirs:
            self._offer_dirs[pair] = OfferDirectory(pair)
        return self._offer_dirs[pair]

    def add_owned_object(
        self,
        owner: str,
        object_id: str,
        object_type: ObjectType,
        data: dict | None = None,
    ) -> None:
        """Add an object to the owner's directory."""
        self.get_owner_dir(owner).add_object(object_id, object_type, data)

    def remove_owned_object(self, owner: str, object_id: str) -> bool:
        """Remove an object from the owner's directory."""
        odir = self._owner_dirs.get(owner)
        if odir is None:
            return False
        return odir.remove_object(object_id)

    def owner_count(self, owner: str) -> int:
        """Get the total number of objects owned by an account."""
        odir = self._owner_dirs.get(owner)
        return odir.owner_count if odir else 0

    def build_from_ledger(self, ledger) -> None:
        """
        Scan the ledger and populate all owner directories.

        This reconstructs directories from the current ledger state.
        """
        self._owner_dirs.clear()
        self._offer_dirs.clear()

        for addr, acc in ledger.accounts.items():
            odir = self.get_owner_dir(addr)

            # Trust lines
            for (cur, iss), tl in acc.trust_lines.items():
                odir.add_object(
                    f"tl:{addr}:{cur}:{iss}",
                    ObjectType.TRUST_LINE,
                    {"currency": cur, "issuer": iss,
                     "balance": tl.balance, "limit": tl.limit},
                )

            # Open offers
            for offer in acc.open_offers:
                oid = offer if isinstance(offer, str) else getattr(offer, "id", str(offer))
                odir.add_object(oid, ObjectType.OFFER)

        # Escrows
        if hasattr(ledger, "escrow_manager"):
            for eid, escrow in ledger.escrow_manager.escrows.items():
                self.get_owner_dir(escrow.source).add_object(
                    eid, ObjectType.ESCROW,
                    {"destination": escrow.destination,
                     "amount": escrow.amount},
                )

        # Payment channels
        if hasattr(ledger, "channel_manager"):
            for cid, chan in ledger.channel_manager.channels.items():
                self.get_owner_dir(chan.source).add_object(
                    cid, ObjectType.PAYMENT_CHANNEL,
                    {"destination": chan.destination,
                     "amount": chan.amount},
                )

        # Checks
        if hasattr(ledger, "check_manager"):
            for chk_id, chk in ledger.check_manager.checks.items():
                self.get_owner_dir(chk.source).add_object(
                    chk_id, ObjectType.CHECK,
                    {"destination": chk.destination},
                )

        # NFTokens
        if hasattr(ledger, "nftoken_manager"):
            for tid, token in ledger.nftoken_manager.tokens.items():
                self.get_owner_dir(token.owner).add_object(
                    tid, ObjectType.NFTOKEN,
                    {"issuer": token.issuer, "uri": token.uri},
                )
            for oid, offer in ledger.nftoken_manager.offers.items():
                self.get_owner_dir(offer.owner).add_object(
                    oid, ObjectType.NFTOKEN_OFFER,
                )

    def to_dict(self) -> dict:
        return {
            "owner_directories": len(self._owner_dirs),
            "offer_directories": len(self._offer_dirs),
            "total_objects": sum(
                od.owner_count for od in self._owner_dirs.values()
            ),
        }
