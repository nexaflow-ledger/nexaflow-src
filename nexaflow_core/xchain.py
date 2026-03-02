"""
Cross-Chain Bridge support for NexaFlow — Sidechain (XLS-38) equivalent.

Enables value transfer between a locking chain and an issuing chain:
  - XChainCreateBridge: establish a bridge definition
  - XChainCreateClaimID: reserve a claim ID on the destination
  - XChainCommit: lock assets on the source chain
  - XChainClaim: claim assets on the destination chain
  - XChainAddClaimAttestation: witness attestations for commits
  - XChainAccountCreateCommit: fund new account on destination

Bridge definitions specify:
  - locking_chain_door: door account on the locking chain
  - issuing_chain_door: door account on the issuing chain
  - locking_chain_issue: currency/issuer locked
  - issuing_chain_issue: currency/issuer issued
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field


@dataclass
class BridgeDefinition:
    """A cross-chain bridge definition."""
    bridge_id: str
    locking_chain_door: str
    issuing_chain_door: str
    locking_chain_issue: dict  # {"currency": "NXF", "issuer": ""}
    issuing_chain_issue: dict
    min_account_create_amount: float = 10.0
    signal_reward: float = 0.01
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "bridge_id": self.bridge_id,
            "locking_chain_door": self.locking_chain_door,
            "issuing_chain_door": self.issuing_chain_door,
            "locking_chain_issue": self.locking_chain_issue,
            "issuing_chain_issue": self.issuing_chain_issue,
            "min_account_create_amount": self.min_account_create_amount,
            "signal_reward": self.signal_reward,
        }


@dataclass
class ClaimID:
    """A reserved claim ID for a pending cross-chain transfer."""
    claim_id: int
    bridge_id: str
    sender: str
    destination: str = ""
    amount: float = 0.0
    attestations: list[dict] = field(default_factory=list)
    committed: bool = False
    claimed: bool = False
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "claim_id": self.claim_id,
            "bridge_id": self.bridge_id,
            "sender": self.sender,
            "destination": self.destination,
            "amount": self.amount,
            "attestation_count": len(self.attestations),
            "committed": self.committed,
            "claimed": self.claimed,
        }


@dataclass
class XChainCommitRecord:
    """Record of a locked/committed amount on the source chain."""
    commit_id: str
    bridge_id: str
    sender: str
    amount: float
    claim_id: int
    destination: str = ""
    timestamp: float = field(default_factory=time.time)


MIN_WITNESSES = 1  # for testing; prod would be higher (e.g. 3 of 5)


class XChainManager:
    """Manages cross-chain bridge operations."""

    def __init__(self, min_witnesses: int = MIN_WITNESSES):
        self.bridges: dict[str, BridgeDefinition] = {}
        self._claim_ids: dict[str, dict[int, ClaimID]] = {}  # bridge_id -> {claim_seq: ClaimID}
        self._commits: dict[str, list[XChainCommitRecord]] = {}  # bridge_id -> [commits]
        self._claim_seq: dict[str, int] = {}  # bridge_id -> next_seq
        self.min_witnesses = min_witnesses

    @staticmethod
    def _bridge_id(locking_door: str, issuing_door: str,
                   locking_issue: dict, issuing_issue: dict) -> str:
        raw = (f"XCHAIN:{locking_door}:{issuing_door}:"
               f"{locking_issue}:{issuing_issue}")
        return hashlib.sha256(raw.encode()).hexdigest()[:40]

    def create_bridge(self, locking_chain_door: str,
                      issuing_chain_door: str,
                      locking_chain_issue: dict,
                      issuing_chain_issue: dict,
                      min_account_create_amount: float = 10.0,
                      signal_reward: float = 0.01) -> tuple[bool, str, BridgeDefinition | None]:
        """Create a new bridge definition."""
        bid = self._bridge_id(locking_chain_door, issuing_chain_door,
                              locking_chain_issue, issuing_chain_issue)
        if bid in self.bridges:
            return False, "Bridge already exists", None

        bridge = BridgeDefinition(
            bridge_id=bid,
            locking_chain_door=locking_chain_door,
            issuing_chain_door=issuing_chain_door,
            locking_chain_issue=locking_chain_issue,
            issuing_chain_issue=issuing_chain_issue,
            min_account_create_amount=min_account_create_amount,
            signal_reward=signal_reward,
        )
        self.bridges[bid] = bridge
        self._claim_ids[bid] = {}
        self._commits[bid] = []
        self._claim_seq[bid] = 1
        return True, "Bridge created", bridge

    def create_claim_id(self, bridge_id: str,
                        sender: str,
                        destination: str = "") -> tuple[bool, str, int]:
        """Reserve a claim ID.  Returns (ok, msg, claim_id)."""
        if bridge_id not in self.bridges:
            return False, "Bridge not found", 0

        seq = self._claim_seq.get(bridge_id, 1)
        self._claim_seq[bridge_id] = seq + 1

        cid = ClaimID(
            claim_id=seq,
            bridge_id=bridge_id,
            sender=sender,
            destination=destination,
        )
        self._claim_ids[bridge_id][seq] = cid
        return True, "Claim ID created", seq

    def commit(self, bridge_id: str, sender: str,
               amount: float, claim_id: int,
               destination: str = "") -> tuple[bool, str]:
        """Lock assets on the source chain."""
        if bridge_id not in self.bridges:
            return False, "Bridge not found"
        if amount <= 0:
            return False, "Amount must be positive"

        claims = self._claim_ids.get(bridge_id, {})
        cid = claims.get(claim_id)
        if cid is None:
            return False, "Claim ID not found"
        if cid.committed:
            return False, "Already committed"

        cid.committed = True
        cid.amount = amount
        if destination:
            cid.destination = destination

        record = XChainCommitRecord(
            commit_id=f"{bridge_id}:{claim_id}",
            bridge_id=bridge_id,
            sender=sender,
            amount=amount,
            claim_id=claim_id,
            destination=destination,
        )
        self._commits.setdefault(bridge_id, []).append(record)
        return True, "Committed"

    def add_attestation(self, bridge_id: str, claim_id: int,
                        witness: str, signature: str = "") -> tuple[bool, str]:
        """Add a witness attestation for a commit."""
        claims = self._claim_ids.get(bridge_id, {})
        cid = claims.get(claim_id)
        if cid is None:
            return False, "Claim ID not found"
        if not cid.committed:
            return False, "Not yet committed"

        # Check duplicate
        for att in cid.attestations:
            if att["witness"] == witness:
                return False, "Witness already attested"

        cid.attestations.append({
            "witness": witness,
            "signature": signature,
            "timestamp": time.time(),
        })
        return True, f"Attestation added ({len(cid.attestations)} total)"

    def claim(self, bridge_id: str, claim_id: int,
              destination: str) -> tuple[bool, str, float]:
        """
        Claim assets on the destination chain.
        Returns (ok, msg, amount).
        """
        claims = self._claim_ids.get(bridge_id, {})
        cid = claims.get(claim_id)
        if cid is None:
            return False, "Claim ID not found", 0.0
        if not cid.committed:
            return False, "Not yet committed", 0.0
        if cid.claimed:
            return False, "Already claimed", 0.0
        if len(cid.attestations) < self.min_witnesses:
            return (False,
                    f"Need {self.min_witnesses} attestations, "
                    f"have {len(cid.attestations)}",
                    0.0)
        if cid.destination and cid.destination != destination:
            return False, "Destination mismatch", 0.0

        cid.claimed = True
        bridge = self.bridges[bridge_id]
        amount = cid.amount - bridge.signal_reward
        return True, "Claimed", max(0, amount)

    def account_create_commit(self, bridge_id: str, sender: str,
                              amount: float,
                              destination: str) -> tuple[bool, str]:
        """Commit to create a new account on the destination chain."""
        bridge = self.bridges.get(bridge_id)
        if bridge is None:
            return False, "Bridge not found"
        if amount < bridge.min_account_create_amount:
            return (False,
                    f"Amount must be >= {bridge.min_account_create_amount}")

        # Use a special claim ID with negative sequence for account creates
        seq = self._claim_seq.get(bridge_id, 1)
        self._claim_seq[bridge_id] = seq + 1

        cid = ClaimID(
            claim_id=seq,
            bridge_id=bridge_id,
            sender=sender,
            destination=destination,
            amount=amount,
            committed=True,
        )
        self._claim_ids[bridge_id][seq] = cid
        return True, f"Account create committed (claim_id={seq})"

    def get_bridge(self, bridge_id: str) -> BridgeDefinition | None:
        return self.bridges.get(bridge_id)

    def get_claim(self, bridge_id: str, claim_id: int) -> ClaimID | None:
        return self._claim_ids.get(bridge_id, {}).get(claim_id)

    def get_commits(self, bridge_id: str) -> list[dict]:
        records = self._commits.get(bridge_id, [])
        return [{"commit_id": r.commit_id, "sender": r.sender,
                 "amount": r.amount, "claim_id": r.claim_id}
                for r in records]

    def get_all_bridges(self) -> list[dict]:
        return [b.to_dict() for b in self.bridges.values()]
