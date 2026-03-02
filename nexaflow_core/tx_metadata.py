"""
Transaction metadata generation for NexaFlow.

Mirrors XRP Ledger's transaction metadata structure:
  - affected_nodes: list of created, modified, and deleted ledger entries
  - delivered_amount: actual amount delivered (differs for partial payments)
  - balance_changes: per-account balance deltas

Metadata is generated during transaction application and stored
alongside the transaction in the ledger history.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum


class NodeAction(Enum):
    CREATED = "CreatedNode"
    MODIFIED = "ModifiedNode"
    DELETED = "DeletedNode"


@dataclass
class AffectedNode:
    """A single ledger entry that was changed by a transaction."""
    action: NodeAction
    ledger_entry_type: str  # e.g. "AccountRoot", "TrustLine", "Offer", etc.
    ledger_index: str       # unique identifier
    previous_fields: dict = field(default_factory=dict)
    final_fields: dict = field(default_factory=dict)
    new_fields: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = {
            "action": self.action.value,
            "ledger_entry_type": self.ledger_entry_type,
            "ledger_index": self.ledger_index,
        }
        if self.previous_fields:
            d["previous_fields"] = self.previous_fields
        if self.final_fields:
            d["final_fields"] = self.final_fields
        if self.new_fields:
            d["new_fields"] = self.new_fields
        return d


@dataclass
class BalanceChange:
    """Balance change for a single account."""
    account: str
    currency: str
    issuer: str
    previous_balance: float
    final_balance: float

    @property
    def delta(self) -> float:
        return self.final_balance - self.previous_balance

    def to_dict(self) -> dict:
        return {
            "account": self.account,
            "currency": self.currency,
            "issuer": self.issuer,
            "previous_balance": self.previous_balance,
            "final_balance": self.final_balance,
            "delta": self.delta,
        }


@dataclass
class TransactionMetadata:
    """Full metadata record for a single transaction."""
    tx_hash: str = ""
    tx_index: int = 0
    result_code: int = 0
    result_name: str = ""
    affected_nodes: list[AffectedNode] = field(default_factory=list)
    balance_changes: list[BalanceChange] = field(default_factory=list)
    delivered_amount: float | None = None
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        d = {
            "tx_hash": self.tx_hash,
            "tx_index": self.tx_index,
            "result_code": self.result_code,
            "result_name": self.result_name,
            "affected_nodes": [n.to_dict() for n in self.affected_nodes],
            "balance_changes": [b.to_dict() for b in self.balance_changes],
            "timestamp": self.timestamp,
        }
        if self.delivered_amount is not None:
            d["delivered_amount"] = self.delivered_amount
        return d


class MetadataBuilder:
    """
    Collects state changes during transaction application and
    produces a TransactionMetadata object.
    """

    def __init__(self, tx_hash: str = "", tx_index: int = 0):
        self._tx_hash = tx_hash
        self._tx_index = tx_index
        self._nodes: list[AffectedNode] = []
        self._balance_changes: list[BalanceChange] = []
        self._delivered_amount: float | None = None
        self._result_code: int = 0
        self._result_name: str = ""
        self._snapshots: dict[str, dict] = {}

    def snapshot_account(self, addr: str, account_entry) -> None:
        """Record pre-transaction state of an account."""
        self._snapshots[addr] = {
            "balance": account_entry.balance,
            "sequence": account_entry.sequence,
            "owner_count": account_entry.owner_count,
        }

    def record_account_modify(self, addr: str, account_entry) -> None:
        """Record a modified account after transaction."""
        prev = self._snapshots.get(addr, {})
        prev_fields = {}
        final_fields = {}

        if prev:
            if prev.get("balance") != account_entry.balance:
                prev_fields["Balance"] = prev["balance"]
                final_fields["Balance"] = account_entry.balance
                self._balance_changes.append(BalanceChange(
                    account=addr,
                    currency="NXF",
                    issuer="",
                    previous_balance=prev["balance"],
                    final_balance=account_entry.balance,
                ))
            if prev.get("sequence") != account_entry.sequence:
                prev_fields["Sequence"] = prev["sequence"]
                final_fields["Sequence"] = account_entry.sequence
            if prev.get("owner_count") != account_entry.owner_count:
                prev_fields["OwnerCount"] = prev["owner_count"]
                final_fields["OwnerCount"] = account_entry.owner_count

        if prev_fields:
            self._nodes.append(AffectedNode(
                action=NodeAction.MODIFIED,
                ledger_entry_type="AccountRoot",
                ledger_index=addr,
                previous_fields=prev_fields,
                final_fields=final_fields,
            ))

    def record_account_create(self, addr: str, account_entry) -> None:
        """Record a newly created account."""
        self._nodes.append(AffectedNode(
            action=NodeAction.CREATED,
            ledger_entry_type="AccountRoot",
            ledger_index=addr,
            new_fields={
                "Balance": account_entry.balance,
                "Sequence": account_entry.sequence,
            },
        ))

    def record_account_delete(self, addr: str, prev_balance: float = 0.0) -> None:
        """Record a deleted account."""
        self._nodes.append(AffectedNode(
            action=NodeAction.DELETED,
            ledger_entry_type="AccountRoot",
            ledger_index=addr,
            previous_fields={"Balance": prev_balance},
        ))

    def record_offer_create(self, offer_id: str, fields: dict) -> None:
        self._nodes.append(AffectedNode(
            action=NodeAction.CREATED,
            ledger_entry_type="Offer",
            ledger_index=offer_id,
            new_fields=fields,
        ))

    def record_offer_modify(self, offer_id: str, prev: dict, final: dict) -> None:
        self._nodes.append(AffectedNode(
            action=NodeAction.MODIFIED,
            ledger_entry_type="Offer",
            ledger_index=offer_id,
            previous_fields=prev,
            final_fields=final,
        ))

    def record_offer_delete(self, offer_id: str, prev: dict) -> None:
        self._nodes.append(AffectedNode(
            action=NodeAction.DELETED,
            ledger_entry_type="Offer",
            ledger_index=offer_id,
            previous_fields=prev,
        ))

    def record_trust_line_modify(self, key: str, prev: dict, final: dict) -> None:
        self._nodes.append(AffectedNode(
            action=NodeAction.MODIFIED,
            ledger_entry_type="TrustLine",
            ledger_index=key,
            previous_fields=prev,
            final_fields=final,
        ))

    def record_trust_line_create(self, key: str, fields: dict) -> None:
        self._nodes.append(AffectedNode(
            action=NodeAction.CREATED,
            ledger_entry_type="TrustLine",
            ledger_index=key,
            new_fields=fields,
        ))

    def record_escrow_create(self, escrow_id: str, fields: dict) -> None:
        self._nodes.append(AffectedNode(
            action=NodeAction.CREATED,
            ledger_entry_type="Escrow",
            ledger_index=escrow_id,
            new_fields=fields,
        ))

    def record_escrow_finish(self, escrow_id: str, prev: dict) -> None:
        self._nodes.append(AffectedNode(
            action=NodeAction.DELETED,
            ledger_entry_type="Escrow",
            ledger_index=escrow_id,
            previous_fields=prev,
        ))

    def record_generic(self, action: NodeAction, entry_type: str,
                       index: str, **kwargs) -> None:
        """Record any node change generically."""
        self._nodes.append(AffectedNode(
            action=action,
            ledger_entry_type=entry_type,
            ledger_index=index,
            **kwargs,
        ))

    def set_delivered_amount(self, amount: float) -> None:
        self._delivered_amount = amount

    def set_result(self, code: int, name: str) -> None:
        self._result_code = code
        self._result_name = name

    def build(self) -> TransactionMetadata:
        return TransactionMetadata(
            tx_hash=self._tx_hash,
            tx_index=self._tx_index,
            result_code=self._result_code,
            result_name=self._result_name,
            affected_nodes=list(self._nodes),
            balance_changes=list(self._balance_changes),
            delivered_amount=self._delivered_amount,
        )
