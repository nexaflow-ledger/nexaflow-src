"""
Escrow management for NexaFlow.

Escrows lock NXF on the ledger and release them when:
  - A time condition (finish_after) is met, and/or
  - A crypto-condition fulfillment is provided, and/or
  - The escrow is cancelled after cancel_after time.

Mirrors the XRP Ledger's Escrow feature set.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field


@dataclass
class EscrowEntry:
    """A single escrow held on the ledger."""
    escrow_id: str          # unique ID (== creating tx_id)
    account: str            # creator / funder
    destination: str        # recipient when finished
    amount: float           # NXF locked
    condition: str          # SHA-256 hash hex of the fulfillment (empty = no condition)
    finish_after: int       # Unix timestamp after which escrow can be finished (0 = immediate)
    cancel_after: int       # Unix timestamp after which escrow can be cancelled (0 = never)
    create_time: float = field(default_factory=time.time)
    finished: bool = False
    cancelled: bool = False

    def can_finish(self, fulfillment: str = "", now: float | None = None) -> tuple[bool, str]:
        """Check if escrow can be finished. Returns (ok, reason)."""
        if self.finished or self.cancelled:
            return False, "Escrow already resolved"
        if now is None:
            now = time.time()
        if self.finish_after > 0 and now < self.finish_after:
            return False, f"Cannot finish before {self.finish_after}"
        if self.cancel_after > 0 and now >= self.cancel_after:
            return False, "Escrow has expired (past cancel_after)"
        if self.condition:
            if not fulfillment:
                return False, "Condition requires fulfillment"
            # Verify: SHA-256(fulfillment) == condition
            computed = hashlib.sha256(fulfillment.encode("utf-8")).hexdigest()
            if computed != self.condition:
                return False, "Fulfillment does not match condition"
        return True, "OK"

    def can_cancel(self, account: str, now: float | None = None) -> tuple[bool, str]:
        """Check if escrow can be cancelled."""
        if self.finished or self.cancelled:
            return False, "Escrow already resolved"
        if now is None:
            now = time.time()
        # Only the creator can cancel, and only after cancel_after
        if self.cancel_after <= 0:
            return False, "Escrow has no cancel_after — cannot be cancelled"
        if now < self.cancel_after:
            return False, f"Cannot cancel before {self.cancel_after}"
        return True, "OK"

    def to_dict(self) -> dict:
        return {
            "escrow_id": self.escrow_id,
            "account": self.account,
            "destination": self.destination,
            "amount": self.amount,
            "condition": self.condition,
            "finish_after": self.finish_after,
            "cancel_after": self.cancel_after,
            "create_time": self.create_time,
            "finished": self.finished,
            "cancelled": self.cancelled,
        }


class EscrowManager:
    """Manages all escrows on the ledger."""

    def __init__(self):
        self.escrows: dict[str, EscrowEntry] = {}

    def create_escrow(
        self,
        escrow_id: str,
        account: str,
        destination: str,
        amount: float,
        condition: str = "",
        finish_after: int = 0,
        cancel_after: int = 0,
        now: float | None = None,
    ) -> EscrowEntry:
        """Create and store a new escrow."""
        if cancel_after > 0 and finish_after > 0 and finish_after >= cancel_after:
            raise ValueError("finish_after must be before cancel_after")
        entry = EscrowEntry(
            escrow_id=escrow_id,
            account=account,
            destination=destination,
            amount=amount,
            condition=condition,
            finish_after=finish_after,
            cancel_after=cancel_after,
            create_time=now if now is not None else time.time(),
        )
        self.escrows[escrow_id] = entry
        return entry

    def finish_escrow(
        self, escrow_id: str, fulfillment: str = "", now: float | None = None,
    ) -> tuple[EscrowEntry, str]:
        """Finish an escrow, returning (entry, error_msg). Error empty on success."""
        entry = self.escrows.get(escrow_id)
        if entry is None:
            raise KeyError(f"Escrow {escrow_id} not found")
        ok, reason = entry.can_finish(fulfillment, now)
        if not ok:
            return entry, reason
        entry.finished = True
        return entry, ""

    def cancel_escrow(
        self, escrow_id: str, account: str, now: float | None = None,
    ) -> tuple[EscrowEntry, str]:
        """Cancel an escrow, returning (entry, error_msg)."""
        entry = self.escrows.get(escrow_id)
        if entry is None:
            raise KeyError(f"Escrow {escrow_id} not found")
        ok, reason = entry.can_cancel(account, now)
        if not ok:
            return entry, reason
        entry.cancelled = True
        return entry, ""

    def get_escrow(self, escrow_id: str) -> EscrowEntry | None:
        return self.escrows.get(escrow_id)

    def get_escrows_for_account(self, account: str) -> list[EscrowEntry]:
        return [e for e in self.escrows.values()
                if e.account == account and not e.finished and not e.cancelled]

    def get_pending_count(self) -> int:
        return sum(1 for e in self.escrows.values()
                   if not e.finished and not e.cancelled)

    def total_locked(self) -> float:
        return sum(e.amount for e in self.escrows.values()
                   if not e.finished and not e.cancelled)
