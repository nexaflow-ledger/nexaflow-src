"""
Negative UNL tracking for NexaFlow.

Mirrors the XRP Ledger's Negative UNL feature:
  - Tracks validators that appear to be offline or unreliable
  - Adjusts quorum requirement downward so the network can
    continue making progress even when some validators are down
  - Validators are added/removed from the Negative UNL by consensus

This improves liveness: the network doesn't stall when a minority
of validators go offline.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass
class NegativeUNLEntry:
    """A validator on the negative UNL."""
    validator_id: str
    added_at: float = field(default_factory=time.time)
    ledger_seq: int = 0
    reason: str = ""

    def to_dict(self) -> dict:
        return {
            "validator_id": self.validator_id,
            "added_at": self.added_at,
            "ledger_seq": self.ledger_seq,
            "reason": self.reason,
        }


# How many consecutive missed validations before flagging
DEFAULT_MISS_THRESHOLD = 5
# Maximum fraction of validators that can be on nUNL
MAX_NEGATIVE_UNL_FRACTION = 0.25
# Cooldown before a validator can be re-added after removal
READD_COOLDOWN = 3600.0  # 1 hour


class NegativeUNL:
    """
    Manages the negative UNL — the set of validators temporarily
    excluded from quorum calculations.
    """

    def __init__(self, miss_threshold: int = DEFAULT_MISS_THRESHOLD):
        self.entries: dict[str, NegativeUNLEntry] = {}
        self._miss_counts: dict[str, int] = {}
        self._removal_times: dict[str, float] = {}
        self.miss_threshold = miss_threshold

    @property
    def size(self) -> int:
        return len(self.entries)

    def is_on_negative_unl(self, validator_id: str) -> bool:
        return validator_id in self.entries

    def record_validation(self, validator_id: str, participated: bool) -> None:
        """
        Record whether a validator participated in a consensus round.
        If they miss enough rounds, they get added to the negative UNL.
        """
        if participated:
            self._miss_counts[validator_id] = 0
            return

        count = self._miss_counts.get(validator_id, 0) + 1
        self._miss_counts[validator_id] = count

    def check_and_update(self, total_validators: int,
                         ledger_seq: int = 0) -> list[str]:
        """
        Check miss counts and update the negative UNL.
        Returns list of newly added validator IDs.
        """
        max_size = max(1, int(total_validators * MAX_NEGATIVE_UNL_FRACTION))
        added: list[str] = []
        now = time.time()

        for vid, count in list(self._miss_counts.items()):
            if vid in self.entries:
                continue
            if count < self.miss_threshold:
                continue
            if len(self.entries) >= max_size:
                break
            # Check cooldown
            removed_at = self._removal_times.get(vid, 0)
            if now - removed_at < READD_COOLDOWN:
                continue

            self.entries[vid] = NegativeUNLEntry(
                validator_id=vid,
                ledger_seq=ledger_seq,
                reason=f"Missed {count} consecutive rounds",
            )
            added.append(vid)

        return added

    def remove(self, validator_id: str) -> bool:
        """Remove a validator from the negative UNL (they're back online)."""
        if validator_id not in self.entries:
            return False
        del self.entries[validator_id]
        self._miss_counts[validator_id] = 0
        self._removal_times[validator_id] = time.time()
        return True

    def adjusted_quorum(self, total_validators: int,
                        base_quorum_pct: float = 0.80) -> int:
        """
        Compute the adjusted quorum, excluding negative-UNL validators.
        
        The effective validator set is total_validators - nUNL_size.
        Quorum is base_quorum_pct of the effective set, minimum 1.
        """
        effective = total_validators - self.size
        if effective <= 0:
            return 1
        return max(1, int(effective * base_quorum_pct + 0.5))

    def effective_validators(self, all_validators: list[str]) -> list[str]:
        """Return validators NOT on the negative UNL."""
        return [v for v in all_validators if v not in self.entries]

    def get_entries(self) -> list[dict]:
        return [e.to_dict() for e in self.entries.values()]

    def get_stats(self, total_validators: int) -> dict:
        return {
            "negative_unl_size": self.size,
            "total_validators": total_validators,
            "effective_validators": total_validators - self.size,
            "adjusted_quorum": self.adjusted_quorum(total_validators),
            "entries": self.get_entries(),
        }
