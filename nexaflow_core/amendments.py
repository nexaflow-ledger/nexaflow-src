"""
Amendment voting system for NexaFlow.

Amendments allow network-wide feature flagging so new functionality
can be gated behind consensus-based approval. Validators vote on
proposed amendments; once a supermajority (80%) approve an amendment
for two consecutive weeks (configurable), it becomes enabled.

Mirrors the XRP Ledger's Amendment system.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from enum import Enum


class AmendmentStatus(Enum):
    PROPOSED = "proposed"
    VOTING = "voting"
    ENABLED = "enabled"
    VETOED = "vetoed"


@dataclass
class Amendment:
    """A single protocol amendment."""
    amendment_id: str       # unique identifier (hash of name)
    name: str               # human-readable name
    description: str        # what the amendment does
    status: AmendmentStatus = AmendmentStatus.PROPOSED
    votes_for: set[str] = field(default_factory=set)    # validator IDs
    votes_against: set[str] = field(default_factory=set)
    first_majority_time: float = 0.0   # when supermajority first reached
    enabled_time: float = 0.0          # when amendment was activated
    threshold: float = 0.80            # fraction of validators needed (80%)
    voting_period: float = 14 * 86_400  # 14 days sustained majority

    def to_dict(self) -> dict:
        return {
            "amendment_id": self.amendment_id,
            "name": self.name,
            "description": self.description,
            "status": self.status.value,
            "votes_for": len(self.votes_for),
            "votes_against": len(self.votes_against),
            "first_majority_time": self.first_majority_time,
            "enabled_time": self.enabled_time,
        }


class AmendmentManager:
    """Tracks and processes amendment proposals and votes."""

    def __init__(self, voting_period: float = 14 * 86_400, threshold: float = 0.80):
        self.amendments: dict[str, Amendment] = {}
        self.enabled_amendments: set[str] = set()
        self.voting_period = voting_period
        self.threshold = threshold

    @staticmethod
    def compute_amendment_id(name: str) -> str:
        """Deterministic amendment ID from name."""
        return hashlib.sha256(name.encode("utf-8")).hexdigest()

    def propose(self, name: str, description: str = "") -> Amendment:
        """Propose a new amendment for voting."""
        aid = self.compute_amendment_id(name)
        if aid in self.amendments:
            return self.amendments[aid]
        amendment = Amendment(
            amendment_id=aid,
            name=name,
            description=description,
            status=AmendmentStatus.VOTING,
            threshold=self.threshold,
            voting_period=self.voting_period,
        )
        self.amendments[aid] = amendment
        return amendment

    def vote(self, amendment_id: str, validator_id: str, support: bool) -> bool:
        """Record a validator's vote. Returns True if vote was accepted."""
        amendment = self.amendments.get(amendment_id)
        if amendment is None or amendment.status in (AmendmentStatus.ENABLED, AmendmentStatus.VETOED):
            return False
        if support:
            amendment.votes_for.add(validator_id)
            amendment.votes_against.discard(validator_id)
        else:
            amendment.votes_against.add(validator_id)
            amendment.votes_for.discard(validator_id)
        return True

    def process_voting_round(
        self, total_validators: int, now: float | None = None,
    ) -> list[Amendment]:
        """
        Process all amendments in voting. Returns list of newly enabled amendments.
        Call this periodically (e.g., every ledger close).
        """
        if now is None:
            now = time.time()
        if total_validators <= 0:
            return []

        newly_enabled: list[Amendment] = []

        for amendment in self.amendments.values():
            if amendment.status != AmendmentStatus.VOTING:
                continue

            support_ratio = len(amendment.votes_for) / total_validators

            if support_ratio >= amendment.threshold:
                # Supermajority reached
                if amendment.first_majority_time == 0.0:
                    amendment.first_majority_time = now
                elif now - amendment.first_majority_time >= amendment.voting_period:
                    # Sustained for voting_period — enable it
                    amendment.status = AmendmentStatus.ENABLED
                    amendment.enabled_time = now
                    self.enabled_amendments.add(amendment.amendment_id)
                    newly_enabled.append(amendment)
            else:
                # Lost supermajority — reset timer
                amendment.first_majority_time = 0.0

        return newly_enabled

    def is_enabled(self, amendment_name_or_id: str) -> bool:
        """Check if an amendment is enabled (accepts name or ID)."""
        # Try as ID first
        if amendment_name_or_id in self.enabled_amendments:
            return True
        # Try as name
        aid = self.compute_amendment_id(amendment_name_or_id)
        return aid in self.enabled_amendments

    def veto(self, amendment_id: str) -> bool:
        """Operator veto — prevents local node from voting for this amendment."""
        amendment = self.amendments.get(amendment_id)
        if amendment is None:
            return False
        if amendment.status == AmendmentStatus.ENABLED:
            return False  # can't veto already-enabled
        amendment.status = AmendmentStatus.VETOED
        return True

    def get_all_amendments(self) -> list[dict]:
        return [a.to_dict() for a in self.amendments.values()]

    def get_enabled(self) -> list[str]:
        return sorted(self.enabled_amendments)
