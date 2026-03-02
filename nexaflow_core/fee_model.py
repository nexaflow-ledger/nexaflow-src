"""
Formal Transaction Cost Model (Tier 3).

Implements a drops-based fee structure that mirrors the XRP Ledger's
transaction cost model:

* **Reference Fee** — the minimum cost in *fee units* for a reference
  transaction.
* **Base Fee** — the minimum cost in *drops* after applying the
  current ``load_factor``.
* **Open-ledger Fee** — an escalated fee when the open ledger is
  congested.
* **Queue** — transactions below the open-ledger fee may be held in
  a queue sorted by fee-per-byte, to be included in later ledgers.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any


# ── Constants (same as rippled defaults) ────────────────────────

REFERENCE_FEE_UNITS: int = 10          # ref tx cost in fee units
BASE_FEE_DROPS: int = 10               # one fee unit = 1 drop
RESERVE_BASE_DROPS: int = 10_000_000   # 10 NXF account reserve
RESERVE_INCREMENT_DROPS: int = 2_000_000  # 2 NXF per owned object
DROPS_PER_NXF: int = 1_000_000

# Load factor thresholds
LOAD_FACTOR_NORMAL: int = 256          # denominator = 256
LOAD_FACTOR_FEE_ESCALATION: int = 256

# Queue sizing
DEFAULT_QUEUE_MAX: int = 2000          # max queued txns


@dataclass
class FeeLevel:
    """Represents the current fee levels for the network."""
    reference_fee_units: int = REFERENCE_FEE_UNITS
    base_fee_drops: int = BASE_FEE_DROPS
    reserve_base_drops: int = RESERVE_BASE_DROPS
    reserve_increment_drops: int = RESERVE_INCREMENT_DROPS
    load_factor: int = LOAD_FACTOR_NORMAL
    load_base: int = LOAD_FACTOR_NORMAL
    queue_size: int = 0
    expected_ledger_size: int = 100
    max_queue_size: int = DEFAULT_QUEUE_MAX
    median_fee_level: int = BASE_FEE_DROPS
    minimum_fee_level: int = BASE_FEE_DROPS
    open_ledger_fee_level: int = BASE_FEE_DROPS

    @property
    def load_factor_ratio(self) -> float:
        if self.load_base == 0:
            return 1.0
        return self.load_factor / self.load_base

    @property
    def current_base_fee(self) -> int:
        """Base fee adjusted for current load (in drops)."""
        return max(1, int(self.base_fee_drops * self.load_factor_ratio))

    def to_dict(self) -> dict[str, Any]:
        return {
            "base_fee": str(self.base_fee_drops),
            "current_ledger_size": str(self.queue_size),
            "current_queue_size": str(self.queue_size),
            "drops": {
                "base_fee": str(self.current_base_fee),
                "median_fee": str(self.median_fee_level),
                "minimum_fee": str(self.minimum_fee_level),
                "open_ledger_fee": str(self.open_ledger_fee_level),
            },
            "expected_ledger_size": str(self.expected_ledger_size),
            "ledger_current_index": 0,
            "levels": {
                "median_level": str(self.median_fee_level * 256),
                "minimum_level": str(self.minimum_fee_level * 256),
                "open_ledger_level": str(self.open_ledger_fee_level * 256),
                "reference_level": str(self.reference_fee_units * 256),
            },
            "max_queue_size": str(self.max_queue_size),
        }


@dataclass
class QueuedTransaction:
    """A transaction waiting in the fee queue."""
    tx_id: str
    account: str
    fee_drops: int
    fee_level: int      # fee / reference_cost * 256
    sequence: int
    queued_at: float = field(default_factory=time.time)
    retries: int = 0
    max_retries: int = 10

    @property
    def expired(self) -> bool:
        return self.retries >= self.max_retries


class FeeModel:
    """
    Manages the global fee schedule, load factor, and tx queue.
    """

    def __init__(self, *, base_fee: int = BASE_FEE_DROPS,
                 reserve_base: int = RESERVE_BASE_DROPS,
                 reserve_inc: int = RESERVE_INCREMENT_DROPS,
                 queue_max: int = DEFAULT_QUEUE_MAX):
        self.fee_level = FeeLevel(
            base_fee_drops=base_fee,
            reserve_base_drops=reserve_base,
            reserve_increment_drops=reserve_inc,
            max_queue_size=queue_max,
        )
        self._queue: list[QueuedTransaction] = []
        self._recent_fees: list[int] = []
        self._txn_count_in_ledger: int = 0

    # ── Reserve logic ───────────────────────────────────────────

    def account_reserve(self, owner_count: int) -> int:
        """Minimum balance (in drops) an account must maintain."""
        return (self.fee_level.reserve_base_drops +
                self.fee_level.reserve_increment_drops * max(0, owner_count))

    def owner_reserve_increment(self) -> int:
        return self.fee_level.reserve_increment_drops

    # ── Fee validation ──────────────────────────────────────────

    def minimum_fee(self) -> int:
        """Minimum fee in drops for the next ledger."""
        return self.fee_level.current_base_fee

    def validate_fee(self, fee_drops: int) -> tuple[bool, str]:
        """Check if a submitted fee meets the minimum threshold."""
        minimum = self.minimum_fee()
        if fee_drops < minimum:
            return False, f"Fee {fee_drops} drops below minimum {minimum} drops"
        return True, ""

    def should_queue(self, fee_drops: int) -> bool:
        """
        Return True if the tx fee is below the open-ledger fee level
        but above the absolute minimum, so it should be queued.
        """
        if fee_drops < self.fee_level.current_base_fee:
            return False
        return fee_drops < self.fee_level.open_ledger_fee_level

    # ── Queue management ────────────────────────────────────────

    def enqueue(self, tx_id: str, account: str, fee_drops: int,
                sequence: int) -> bool:
        """
        Enqueue a transaction. Returns False if queue is full or fee
        is below absolute minimum.
        """
        if len(self._queue) >= self.fee_level.max_queue_size:
            return False
        if fee_drops < self.fee_level.current_base_fee:
            return False

        fl = self._compute_fee_level(fee_drops)
        qtx = QueuedTransaction(
            tx_id=tx_id, account=account, fee_drops=fee_drops,
            fee_level=fl, sequence=sequence,
        )
        self._queue.append(qtx)
        self._queue.sort(key=lambda q: -q.fee_level)  # highest first
        self.fee_level.queue_size = len(self._queue)
        return True

    def dequeue_for_ledger(self, max_txns: int | None = None) -> list[QueuedTransaction]:
        """Pop the highest-fee transactions from the queue for the next ledger."""
        limit = max_txns or self.fee_level.expected_ledger_size
        result: list[QueuedTransaction] = []
        remaining: list[QueuedTransaction] = []
        for qtx in self._queue:
            if len(result) < limit and not qtx.expired:
                result.append(qtx)
            else:
                qtx.retries += 1
                if not qtx.expired:
                    remaining.append(qtx)
        self._queue = remaining
        self.fee_level.queue_size = len(self._queue)
        return result

    def queue_contents(self) -> list[dict]:
        return [
            {
                "tx_id": q.tx_id,
                "account": q.account,
                "fee": q.fee_drops,
                "fee_level": q.fee_level,
                "retries": q.retries,
            }
            for q in self._queue
        ]

    # ── Load factor / escalation ────────────────────────────────

    def record_transaction(self, fee_drops: int) -> None:
        """Called when a transaction is applied to the current ledger."""
        self._recent_fees.append(fee_drops)
        self._txn_count_in_ledger += 1

    def on_ledger_close(self) -> None:
        """Update fee levels based on the just-closed ledger."""
        if self._recent_fees:
            sorted_fees = sorted(self._recent_fees)
            mid = len(sorted_fees) // 2
            self.fee_level.median_fee_level = sorted_fees[mid]
            self.fee_level.minimum_fee_level = sorted_fees[0]
        else:
            self.fee_level.median_fee_level = self.fee_level.base_fee_drops
            self.fee_level.minimum_fee_level = self.fee_level.base_fee_drops

        # Escalate open-ledger fee if congested
        expected = max(1, self.fee_level.expected_ledger_size)
        if self._txn_count_in_ledger > expected:
            ratio = self._txn_count_in_ledger / expected
            self.fee_level.open_ledger_fee_level = int(
                self.fee_level.base_fee_drops * ratio * ratio
            )
            self.fee_level.load_factor = int(
                self.fee_level.load_base * ratio
            )
        else:
            self.fee_level.open_ledger_fee_level = self.fee_level.base_fee_drops
            self.fee_level.load_factor = self.fee_level.load_base

        # Reset per-ledger counters
        self._recent_fees = []
        self._txn_count_in_ledger = 0

    # ── Internal ────────────────────────────────────────────────

    def _compute_fee_level(self, fee_drops: int) -> int:
        base = max(1, self.fee_level.base_fee_drops)
        return int(fee_drops / base * 256)

    def to_dict(self) -> dict:
        return self.fee_level.to_dict()
