"""
Check management for NexaFlow.

Checks are deferred pull-payments. A sender creates a Check authorising
a recipient to cash up to a specified amount. The recipient cashes the
Check when ready.  Either party can cancel an uncashed Check.

Mirrors the XRP Ledger's Checks feature set.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass
class CheckEntry:
    """A single Check on the ledger."""
    check_id: str          # unique ID (== creating tx_id)
    account: str           # creator / sender
    destination: str       # authorised casher
    send_max: float        # max NXF the sender authorises
    currency: str          # "NXF" or IOU currency code
    issuer: str            # issuer for IOUs, empty for NXF
    expiration: int        # Unix timestamp (0 = never expires)
    create_time: float = field(default_factory=time.time)
    cashed: bool = False
    cancelled: bool = False
    cashed_amount: float = 0.0

    def can_cash(
        self, amount: float = 0.0, deliver_min: float = 0.0,
        now: float | None = None,
    ) -> tuple[bool, str]:
        """Check whether this Check can be cashed."""
        if self.cashed or self.cancelled:
            return False, "Check already resolved"
        if now is None:
            now = time.time()
        if self.expiration > 0 and now >= self.expiration:
            return False, "Check has expired"
        cash_amount = amount if amount > 0 else self.send_max
        if cash_amount > self.send_max:
            return False, f"Amount {cash_amount} exceeds send_max {self.send_max}"
        if deliver_min > 0 and cash_amount < deliver_min:
            return False, f"Amount {cash_amount} below deliver_min {deliver_min}"
        return True, "OK"

    def can_cancel(self, requester: str, now: float | None = None) -> tuple[bool, str]:
        """Check whether this Check can be cancelled."""
        if self.cashed or self.cancelled:
            return False, "Check already resolved"
        if now is None:
            now = time.time()
        # Either party can cancel; also anyone can cancel if expired
        if requester in (self.account, self.destination):
            return True, "OK"
        if self.expiration > 0 and now >= self.expiration:
            return True, "OK"
        return False, "Only sender or destination can cancel"

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "account": self.account,
            "destination": self.destination,
            "send_max": self.send_max,
            "currency": self.currency,
            "issuer": self.issuer,
            "expiration": self.expiration,
            "create_time": self.create_time,
            "cashed": self.cashed,
            "cancelled": self.cancelled,
            "cashed_amount": self.cashed_amount,
        }


class CheckManager:
    """Manages all Checks on the ledger."""

    def __init__(self):
        self.checks: dict[str, CheckEntry] = {}

    def create_check(
        self,
        check_id: str,
        account: str,
        destination: str,
        send_max: float,
        currency: str = "NXF",
        issuer: str = "",
        expiration: int = 0,
        now: float | None = None,
    ) -> CheckEntry:
        """Create and store a new Check."""
        entry = CheckEntry(
            check_id=check_id,
            account=account,
            destination=destination,
            send_max=send_max,
            currency=currency,
            issuer=issuer,
            expiration=expiration,
            create_time=now if now is not None else time.time(),
        )
        self.checks[check_id] = entry
        return entry

    def cash_check(
        self,
        check_id: str,
        amount: float = 0.0,
        deliver_min: float = 0.0,
        now: float | None = None,
    ) -> tuple[CheckEntry, float, str]:
        """Cash a Check. Returns (entry, cashed_amount, error_msg)."""
        entry = self.checks.get(check_id)
        if entry is None:
            raise KeyError(f"Check {check_id} not found")
        ok, reason = entry.can_cash(amount, deliver_min, now)
        if not ok:
            return entry, 0.0, reason
        cash_amount = amount if amount > 0 else entry.send_max
        entry.cashed = True
        entry.cashed_amount = cash_amount
        return entry, cash_amount, ""

    def cancel_check(
        self, check_id: str, requester: str, now: float | None = None,
    ) -> tuple[CheckEntry, str]:
        """Cancel a Check. Returns (entry, error_msg)."""
        entry = self.checks.get(check_id)
        if entry is None:
            raise KeyError(f"Check {check_id} not found")
        ok, reason = entry.can_cancel(requester, now)
        if not ok:
            return entry, reason
        entry.cancelled = True
        return entry, ""

    def get_check(self, check_id: str) -> CheckEntry | None:
        return self.checks.get(check_id)

    def get_checks_for_account(self, account: str) -> list[CheckEntry]:
        return [c for c in self.checks.values()
                if (c.account == account or c.destination == account)
                and not c.cashed and not c.cancelled]

    def get_pending_count(self) -> int:
        return sum(1 for c in self.checks.values()
                   if not c.cashed and not c.cancelled)
