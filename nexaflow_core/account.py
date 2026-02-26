"""
Account management for NexaFlow.

High-level account abstraction that combines wallet, ledger state,
and convenience methods for interacting with the network.
"""

from __future__ import annotations

from nexaflow_core.transaction import (
    Amount,
    Transaction,
    create_offer,
    create_payment,
    create_trust_set,
)
from nexaflow_core.wallet import Wallet


class Account:
    """
    High-level account that wraps a Wallet and provides
    convenient methods for creating and signing transactions.
    """

    def __init__(self, wallet: Wallet):
        self.wallet = wallet
        self.address: str = wallet.address
        self.tx_history: list[Transaction] = []

    @classmethod
    def create(cls) -> Account:
        """Create a new account with a fresh wallet."""
        return cls(Wallet.create())

    @classmethod
    def from_seed(cls, seed: str) -> Account:
        """Create an account from a deterministic seed."""
        return cls(Wallet.from_seed(seed))

    # ---- transaction builders ----

    def send_payment(
        self,
        destination: str,
        amount: float,
        currency: str = "NXF",
        issuer: str = "",
        fee: float = 0.00001,
        memo: str = "",
    ) -> Transaction:
        """Build and sign a Payment transaction."""
        tx = create_payment(
            self.address,
            destination,
            amount,
            currency,
            issuer,
            fee,
            0,  # sequence filled by wallet
            memo,
        )
        self.wallet.sign_transaction(tx)
        self.tx_history.append(tx)
        return tx

    def set_trust(
        self,
        currency: str,
        issuer: str,
        limit: float,
        fee: float = 0.00001,
    ) -> Transaction:
        """Build and sign a TrustSet transaction."""
        tx = create_trust_set(self.address, currency, issuer, limit, fee)
        self.wallet.sign_transaction(tx)
        self.tx_history.append(tx)
        return tx

    def create_offer(
        self,
        taker_pays: Amount,
        taker_gets: Amount,
        fee: float = 0.00001,
    ) -> Transaction:
        """Build and sign an OfferCreate transaction."""
        tx = create_offer(self.address, taker_pays, taker_gets, fee)
        self.wallet.sign_transaction(tx)
        self.tx_history.append(tx)
        return tx

    def get_history(self) -> list[dict]:
        """Return transaction history as list of dicts."""
        return [tx.to_dict() for tx in self.tx_history]

    def __repr__(self) -> str:
        return f"Account({self.address})"
