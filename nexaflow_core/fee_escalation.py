"""
Fee escalation engine for NexaFlow.

Mirrors XRP Ledger's open-ledger cost and transaction queue:
  - Base fee: minimum cost to include a transaction
  - Open-ledger cost: dynamic multiplier when the ledger is above target
  - Queue: transactions that can't afford the open-ledger cost wait
  - Escalation formula: fee = base_fee * (queue_size / target_size)^2

This prevents spam during high load by making inclusion cost rise
quickly, while queuing lower-fee transactions for the next ledger.
"""

from __future__ import annotations

import heapq
import time
from dataclasses import dataclass, field


@dataclass(order=True)
class QueuedTransaction:
    """A transaction waiting in the fee queue, ordered by fee (highest first)."""
    priority: float = field(init=False, repr=False)
    fee: float = 0.0
    tx_hash: str = ""
    account: str = ""
    sequence: int = 0
    submitted_at: float = field(default_factory=time.time)
    tx_data: dict = field(default_factory=dict, compare=False)

    def __post_init__(self):
        self.priority = -self.fee  # heapq is min-heap, negate for max-fee-first


# Default constants (matching XRPL-style values, adjusted for NexaFlow)
DEFAULT_BASE_FEE = 0.00001       # NXF
DEFAULT_TARGET_TXN_COUNT = 25    # target txns per ledger
DEFAULT_MAX_TXN_COUNT = 50       # hard cap per ledger
DEFAULT_MAX_QUEUE_SIZE = 2000
DEFAULT_ESCALATION_MULTIPLIER = 1.0
DEFAULT_QUEUE_MAX_AGE = 300.0    # seconds


class FeeEscalation:
    """
    Manages dynamic fee escalation and the transaction queue.
    """

    def __init__(self,
                 base_fee: float = DEFAULT_BASE_FEE,
                 target_txn_count: int = DEFAULT_TARGET_TXN_COUNT,
                 max_txn_count: int = DEFAULT_MAX_TXN_COUNT,
                 max_queue_size: int = DEFAULT_MAX_QUEUE_SIZE,
                 escalation_multiplier: float = DEFAULT_ESCALATION_MULTIPLIER,
                 queue_max_age: float = DEFAULT_QUEUE_MAX_AGE):
        self.base_fee = base_fee
        self.target_txn_count = target_txn_count
        self.max_txn_count = max_txn_count
        self.max_queue_size = max_queue_size
        self.escalation_multiplier = escalation_multiplier
        self.queue_max_age = queue_max_age

        self._queue: list[QueuedTransaction] = []
        self._current_ledger_count: int = 0
        self._last_ledger_close: float = time.time()

    @property
    def queue_size(self) -> int:
        return len(self._queue)

    @property
    def current_ledger_count(self) -> int:
        return self._current_ledger_count

    def open_ledger_cost(self) -> float:
        """
        Compute the current open-ledger fee.
        If txn count is below target, returns base_fee.
        Otherwise, escalates quadratically.
        """
        if self._current_ledger_count <= self.target_txn_count:
            return self.base_fee

        ratio = self._current_ledger_count / self.target_txn_count
        return self.base_fee * (ratio ** 2) * self.escalation_multiplier

    def minimum_fee(self) -> float:
        """Minimum fee to enter the queue (not necessarily the open ledger)."""
        if self.queue_size == 0:
            return self.base_fee
        # At least the base fee, but also consider queue depth
        queue_pressure = max(1.0, self.queue_size / self.target_txn_count)
        return self.base_fee * queue_pressure

    def can_include_in_ledger(self, fee: float) -> bool:
        """Check if a transaction's fee meets the open-ledger cost."""
        if self._current_ledger_count >= self.max_txn_count:
            return False
        return fee >= self.open_ledger_cost()

    def submit(self, tx_hash: str, account: str, sequence: int,
               fee: float, tx_data: dict | None = None
               ) -> tuple[str, str]:
        """
        Submit a transaction.  Returns (status, message) where status is
        one of: 'applied', 'queued', 'rejected'.
        """
        if fee < self.base_fee:
            return "rejected", f"Fee {fee} below minimum {self.base_fee}"

        # Can go straight into the ledger?
        if self.can_include_in_ledger(fee):
            self._current_ledger_count += 1
            return "applied", "Included in open ledger"

        # Try to queue
        if self.queue_size >= self.max_queue_size:
            # Check if this txn's fee is higher than the lowest in queue
            if self._queue and fee > -self._queue[-1].priority:
                # Evict lowest
                heapq.heappop(self._queue)
            else:
                return "rejected", "Queue full and fee too low"

        entry = QueuedTransaction(
            fee=fee,
            tx_hash=tx_hash,
            account=account,
            sequence=sequence,
            tx_data=tx_data or {},
        )
        heapq.heappush(self._queue, entry)
        return "queued", f"Queued (position ~{self.queue_size})"

    def drain_for_ledger(self, max_count: int | None = None
                         ) -> list[QueuedTransaction]:
        """
        Pull the highest-fee transactions from the queue for inclusion
        in the next ledger.  Returns transactions in fee-descending order.
        """
        limit = max_count or self.max_txn_count
        result: list[QueuedTransaction] = []
        now = time.time()

        while self._queue and len(result) < limit:
            entry = heapq.heappop(self._queue)
            # Expire old entries
            if now - entry.submitted_at > self.queue_max_age:
                continue
            result.append(entry)

        return result

    def on_ledger_close(self) -> list[QueuedTransaction]:
        """
        Called when a ledger closes.  Resets the open-ledger count
        and drains queued transactions for the new ledger.
        """
        self._current_ledger_count = 0
        self._last_ledger_close = time.time()

        # Purge expired entries
        now = time.time()
        self._queue = [
            q for q in self._queue
            if now - q.submitted_at <= self.queue_max_age
        ]
        heapq.heapify(self._queue)

        return self.drain_for_ledger()

    def get_stats(self) -> dict:
        """Return current fee escalation statistics."""
        return {
            "base_fee": self.base_fee,
            "open_ledger_cost": self.open_ledger_cost(),
            "minimum_fee": self.minimum_fee(),
            "queue_size": self.queue_size,
            "current_ledger_txn_count": self._current_ledger_count,
            "target_txn_count": self.target_txn_count,
            "max_txn_count": self.max_txn_count,
        }
