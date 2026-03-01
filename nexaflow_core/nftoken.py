"""
NFToken management for NexaFlow.

Non-fungible tokens (NFTs) with:
  - Minting with configurable taxon, transfer fee, and flags
  - Burning by owner (or minter if burnable flag set)
  - Buy/sell offers and acceptance
  - On-ledger transfer via offer matching

Mirrors the XRP Ledger's NFToken feature set.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field


@dataclass
class NFToken:
    """A single non-fungible token."""
    nftoken_id: str         # unique identifier
    issuer: str             # minting account
    owner: str              # current owner
    uri: str                # metadata URI
    transfer_fee: int       # 0-50000 (0.000%-50.000%)
    nftoken_taxon: int      # issuer-defined category
    transferable: bool      # whether token can be transferred
    burnable: bool          # whether issuer can burn after transfer
    serial: int             # minting serial number
    create_time: float = field(default_factory=time.time)
    burned: bool = False

    def to_dict(self) -> dict:
        return {
            "nftoken_id": self.nftoken_id,
            "issuer": self.issuer,
            "owner": self.owner,
            "uri": self.uri,
            "transfer_fee": self.transfer_fee,
            "nftoken_taxon": self.nftoken_taxon,
            "transferable": self.transferable,
            "burnable": self.burnable,
            "serial": self.serial,
            "create_time": self.create_time,
            "burned": self.burned,
        }


@dataclass
class NFTokenOffer:
    """A buy or sell offer for an NFToken."""
    offer_id: str
    nftoken_id: str
    owner: str              # offer creator
    amount: float           # NXF price
    destination: str        # specific buyer/seller (empty = open)
    is_sell: bool           # True = sell offer, False = buy offer
    expiration: int         # 0 = no expiration
    create_time: float = field(default_factory=time.time)
    accepted: bool = False
    cancelled: bool = False

    def is_valid(self, now: float | None = None) -> bool:
        if self.accepted or self.cancelled:
            return False
        if now is None:
            now = time.time()
        if self.expiration > 0 and now >= self.expiration:
            return False
        return True

    def to_dict(self) -> dict:
        return {
            "offer_id": self.offer_id,
            "nftoken_id": self.nftoken_id,
            "owner": self.owner,
            "amount": self.amount,
            "destination": self.destination,
            "is_sell": self.is_sell,
            "expiration": self.expiration,
            "accepted": self.accepted,
            "cancelled": self.cancelled,
        }


class NFTokenManager:
    """Manages all NFTokens and offers on the ledger."""

    def __init__(self):
        self.tokens: dict[str, NFToken] = {}
        self.offers: dict[str, NFTokenOffer] = {}
        self._next_serial: dict[str, int] = {}  # issuer -> next serial

    def _compute_nftoken_id(self, issuer: str, taxon: int, serial: int) -> str:
        blob = f"{issuer}:{taxon}:{serial}".encode("utf-8")
        return hashlib.blake2b(blob, digest_size=32).hexdigest()

    def mint(
        self,
        issuer: str,
        uri: str = "",
        transfer_fee: int = 0,
        nftoken_taxon: int = 0,
        transferable: bool = True,
        burnable: bool = True,
        now: float | None = None,
    ) -> NFToken:
        """Mint a new NFToken."""
        if transfer_fee < 0 or transfer_fee > 50000:
            raise ValueError("transfer_fee must be 0-50000")
        serial = self._next_serial.get(issuer, 0)
        self._next_serial[issuer] = serial + 1
        nftoken_id = self._compute_nftoken_id(issuer, nftoken_taxon, serial)
        token = NFToken(
            nftoken_id=nftoken_id,
            issuer=issuer,
            owner=issuer,
            uri=uri,
            transfer_fee=transfer_fee,
            nftoken_taxon=nftoken_taxon,
            transferable=transferable,
            burnable=burnable,
            serial=serial,
            create_time=now if now is not None else time.time(),
        )
        self.tokens[nftoken_id] = token
        return token

    def burn(self, nftoken_id: str, requester: str) -> tuple[NFToken, str]:
        """Burn an NFToken. Returns (token, error_msg)."""
        token = self.tokens.get(nftoken_id)
        if token is None:
            return None, "NFToken not found"  # type: ignore[return-value]
        if token.burned:
            return token, "Already burned"
        # Owner can always burn
        if requester == token.owner:
            token.burned = True
            return token, ""
        # Issuer can burn if burnable flag
        if requester == token.issuer and token.burnable:
            token.burned = True
            return token, ""
        return token, "Not authorized to burn"

    def create_offer(
        self,
        offer_id: str,
        nftoken_id: str,
        owner: str,
        amount: float,
        destination: str = "",
        is_sell: bool = False,
        expiration: int = 0,
        now: float | None = None,
    ) -> tuple[NFTokenOffer, str]:
        """Create a buy or sell offer."""
        token = self.tokens.get(nftoken_id)
        if token is None or token.burned:
            return None, "NFToken not found or burned"  # type: ignore[return-value]
        if is_sell and token.owner != owner:
            return None, "Only owner can create sell offers"  # type: ignore[return-value]
        if not is_sell and token.owner == owner:
            return None, "Cannot buy your own token"  # type: ignore[return-value]
        if not token.transferable and owner != token.issuer and not is_sell:
            return None, "Token is not transferable"  # type: ignore[return-value]
        offer = NFTokenOffer(
            offer_id=offer_id,
            nftoken_id=nftoken_id,
            owner=owner,
            amount=amount,
            destination=destination,
            is_sell=is_sell,
            expiration=expiration,
            create_time=now if now is not None else time.time(),
        )
        self.offers[offer_id] = offer
        return offer, ""

    def accept_offer(
        self, offer_id: str, acceptor: str, now: float | None = None,
    ) -> tuple[NFTokenOffer | None, str]:
        """
        Accept an NFToken offer. Transfers the token.
        Returns (offer, error_msg).
        """
        offer = self.offers.get(offer_id)
        if offer is None:
            return None, "Offer not found"
        if not offer.is_valid(now):
            return offer, "Offer is expired or already resolved"
        token = self.tokens.get(offer.nftoken_id)
        if token is None or token.burned:
            return offer, "NFToken not found or burned"
        # Destination check
        if offer.destination and offer.destination != acceptor:
            return offer, "Offer is restricted to a specific account"
        if offer.is_sell:
            # Acceptor is the buyer — must not be the seller
            if acceptor == offer.owner:
                return offer, "Cannot accept own offer"
            # Transfer token
            token.owner = acceptor
        else:
            # Buy offer — acceptor is the seller (current owner)
            if acceptor != token.owner:
                return offer, "Only token owner can accept buy offers"
            token.owner = offer.owner
        offer.accepted = True
        return offer, ""

    def get_token(self, nftoken_id: str) -> NFToken | None:
        return self.tokens.get(nftoken_id)

    def get_tokens_for_account(self, account: str) -> list[NFToken]:
        return [t for t in self.tokens.values()
                if t.owner == account and not t.burned]

    def get_offers_for_token(self, nftoken_id: str) -> list[NFTokenOffer]:
        return [o for o in self.offers.values()
                if o.nftoken_id == nftoken_id and not o.accepted and not o.cancelled]

    def cancel_offer(self, offer_id: str, requester: str) -> tuple[NFTokenOffer | None, str]:
        offer = self.offers.get(offer_id)
        if offer is None:
            return None, "Offer not found"
        if offer.accepted or offer.cancelled:
            return offer, "Offer already resolved"
        if offer.owner != requester:
            return offer, "Only offer creator can cancel"
        offer.cancelled = True
        return offer, ""
