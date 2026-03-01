"""
Payment channel management for NexaFlow.

Payment channels allow two parties to conduct rapid off-ledger
micropayments, with only the channel open/close hitting the ledger.

Mirrors the XRP Ledger's PayChannel feature set.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field


@dataclass
class PaymentChannel:
    """A unidirectional payment channel between two accounts."""
    channel_id: str         # unique ID (== creating tx_id)
    account: str            # channel creator / funder
    destination: str        # channel recipient
    amount: float           # total NXF deposited into channel
    balance: float          # amount already claimed by destination
    settle_delay: int       # seconds after close request before channel settles
    public_key: str         # hex pubkey authorised to sign claims
    cancel_after: int       # absolute expiration (0 = no expiration)
    create_time: float = field(default_factory=time.time)
    close_requested: bool = False
    close_request_time: float = 0.0
    closed: bool = False

    @property
    def available(self) -> float:
        """NXF remaining in the channel that can be claimed."""
        return max(0.0, self.amount - self.balance)

    def can_claim(self, claim_balance: float, now: float | None = None) -> tuple[bool, str]:
        """Check if a claim for new balance is valid."""
        if self.closed:
            return False, "Channel is closed"
        if now is None:
            now = time.time()
        if self.cancel_after > 0 and now >= self.cancel_after:
            return False, "Channel has expired"
        if claim_balance < self.balance:
            return False, "Claim balance must be >= current balance"
        if claim_balance > self.amount:
            return False, "Claim exceeds channel amount"
        return True, "OK"

    def can_close(self, requester: str, now: float | None = None) -> tuple[bool, str]:
        """Check if the channel can be closed."""
        if self.closed:
            return False, "Already closed"
        if now is None:
            now = time.time()
        # Destination can close immediately
        if requester == self.destination:
            return True, "OK"
        # Creator must wait settle_delay after requesting close
        if requester == self.account:
            if not self.close_requested:
                return True, "OK"  # will set close_requested
            if now >= self.close_request_time + self.settle_delay:
                return True, "OK"
            return False, f"Settle delay not elapsed (wait until {self.close_request_time + self.settle_delay})"
        return False, "Only channel parties can close"

    def to_dict(self) -> dict:
        return {
            "channel_id": self.channel_id,
            "account": self.account,
            "destination": self.destination,
            "amount": self.amount,
            "balance": self.balance,
            "settle_delay": self.settle_delay,
            "public_key": self.public_key,
            "cancel_after": self.cancel_after,
            "create_time": self.create_time,
            "close_requested": self.close_requested,
            "closed": self.closed,
            "available": self.available,
        }


class PaymentChannelManager:
    """Manages all payment channels on the ledger."""

    def __init__(self):
        self.channels: dict[str, PaymentChannel] = {}

    def create_channel(
        self,
        channel_id: str,
        account: str,
        destination: str,
        amount: float,
        settle_delay: int,
        public_key: str = "",
        cancel_after: int = 0,
        now: float | None = None,
    ) -> PaymentChannel:
        """Create a new payment channel."""
        ch = PaymentChannel(
            channel_id=channel_id,
            account=account,
            destination=destination,
            amount=amount,
            balance=0.0,
            settle_delay=settle_delay,
            public_key=public_key,
            cancel_after=cancel_after,
            create_time=now if now is not None else time.time(),
        )
        self.channels[channel_id] = ch
        return ch

    def fund_channel(self, channel_id: str, additional: float) -> PaymentChannel:
        """Add more NXF to an existing channel."""
        ch = self.channels.get(channel_id)
        if ch is None:
            raise KeyError(f"Channel {channel_id} not found")
        if ch.closed:
            raise ValueError("Cannot fund a closed channel")
        ch.amount += additional
        return ch

    def claim(
        self, channel_id: str, new_balance: float, now: float | None = None,
    ) -> tuple[PaymentChannel, float, str]:
        """Process a claim. Returns (channel, NXF_paid_out, error_msg)."""
        ch = self.channels.get(channel_id)
        if ch is None:
            raise KeyError(f"Channel {channel_id} not found")
        ok, reason = ch.can_claim(new_balance, now)
        if not ok:
            return ch, 0.0, reason
        payout = new_balance - ch.balance
        ch.balance = new_balance
        return ch, payout, ""

    def request_close(
        self, channel_id: str, requester: str, now: float | None = None,
    ) -> tuple[PaymentChannel, bool, str]:
        """Request or finalise channel closure. Returns (channel, is_closed, error_msg)."""
        ch = self.channels.get(channel_id)
        if ch is None:
            raise KeyError(f"Channel {channel_id} not found")
        if now is None:
            now = time.time()
        ok, reason = ch.can_close(requester, now)
        if not ok:
            return ch, False, reason
        # Destination can close immediately
        if requester == ch.destination:
            ch.closed = True
            return ch, True, ""
        # Creator: if already requested and delay elapsed, close
        if ch.close_requested and now >= ch.close_request_time + ch.settle_delay:
            ch.closed = True
            return ch, True, ""
        # Otherwise mark close requested
        if not ch.close_requested:
            ch.close_requested = True
            ch.close_request_time = now
            return ch, False, "Close requested, settle delay started"
        return ch, False, "Waiting for settle delay"

    def get_channel(self, channel_id: str) -> PaymentChannel | None:
        return self.channels.get(channel_id)

    def get_channels_for_account(self, account: str) -> list[PaymentChannel]:
        return [c for c in self.channels.values()
                if (c.account == account or c.destination == account)
                and not c.closed]

    def total_locked(self) -> float:
        return sum(c.amount - c.balance for c in self.channels.values()
                   if not c.closed)
