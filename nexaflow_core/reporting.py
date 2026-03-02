"""
Reporting Mode / Clio Analogue (Tier 3).

A read-only API node that serves historical data from a separate data
store without participating in consensus or peer-to-peer networking.

In the XRPL, **Clio** is a dedicated reporting server that stores
validated data in Cassandra/ScyllaDB and serves it via the standard
WebSocket/JSON-RPC interface.  NexaFlow's ``ReportingServer`` provides
equivalent functionality backed by an in-process SQLite or pluggable
store so operators can run dedicated query endpoints.

Features
--------
* Read-only — never applies transactions or participates in consensus
* Historical ledger queries by sequence range
* Transaction search by hash or account
* Account-state point-in-time queries
* Configurable data retention (prune old ledgers)
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Optional

log = logging.getLogger("nexaflow.reporting")


@dataclass
class StoredLedger:
    """A snapshot of a validated ledger saved for historical queries."""
    sequence: int
    state_hash: str
    close_time: float
    parent_hash: str
    txn_count: int
    transactions: list[dict] = field(default_factory=list)
    accounts_affected: set[str] = field(default_factory=set)
    header: dict = field(default_factory=dict)


@dataclass
class StoredTransaction:
    """A validated transaction stored for historical lookup."""
    tx_id: str
    tx_type: int
    account: str
    destination: str
    sequence: int
    ledger_sequence: int
    result_code: int
    timestamp: float
    data: dict = field(default_factory=dict)


class ReportingStore:
    """
    In-memory store for validated ledgers and transactions.
    In production this would be backed by a persistent DB.
    """

    def __init__(self, *, max_ledgers: int = 10_000):
        self._ledgers: dict[int, StoredLedger] = {}
        self._tx_by_id: dict[str, StoredTransaction] = {}
        self._tx_by_account: dict[str, list[str]] = {}  # account -> [tx_id]
        self._max_ledgers = max_ledgers
        self._earliest_seq = 0
        self._latest_seq = 0

    @property
    def ledger_range(self) -> tuple[int, int]:
        if not self._ledgers:
            return (0, 0)
        return (self._earliest_seq, self._latest_seq)

    @property
    def ledger_count(self) -> int:
        return len(self._ledgers)

    @property
    def transaction_count(self) -> int:
        return len(self._tx_by_id)

    # ── Ingest ──────────────────────────────────────────────────

    def store_ledger(self, ledger_data: dict) -> None:
        """Store a validated ledger and its transactions."""
        seq = ledger_data.get("sequence", 0)
        sl = StoredLedger(
            sequence=seq,
            state_hash=ledger_data.get("state_hash", ""),
            close_time=ledger_data.get("close_time", 0.0),
            parent_hash=ledger_data.get("parent_hash", ""),
            txn_count=len(ledger_data.get("transactions", [])),
            header=ledger_data,
        )

        for tx_data in ledger_data.get("transactions", []):
            tx_id = tx_data.get("tx_id", "")
            stx = StoredTransaction(
                tx_id=tx_id,
                tx_type=tx_data.get("tx_type", 0),
                account=tx_data.get("account", ""),
                destination=tx_data.get("destination", ""),
                sequence=tx_data.get("sequence", 0),
                ledger_sequence=seq,
                result_code=tx_data.get("result_code", 0),
                timestamp=tx_data.get("timestamp", 0.0),
                data=tx_data,
            )
            self._tx_by_id[tx_id] = stx
            sl.transactions.append(tx_data)
            sl.accounts_affected.add(stx.account)
            if stx.destination:
                sl.accounts_affected.add(stx.destination)

            # Index by account
            for acct in (stx.account, stx.destination):
                if acct:
                    self._tx_by_account.setdefault(acct, []).append(tx_id)

        self._ledgers[seq] = sl
        if self._earliest_seq == 0 or seq < self._earliest_seq:
            self._earliest_seq = seq
        if seq > self._latest_seq:
            self._latest_seq = seq

        # Prune old ledgers
        self._prune()

    def _prune(self) -> None:
        """Remove ledgers beyond retention limit."""
        while len(self._ledgers) > self._max_ledgers:
            oldest = min(self._ledgers.keys())
            sl = self._ledgers.pop(oldest)
            for tx_data in sl.transactions:
                tx_id = tx_data.get("tx_id", "")
                self._tx_by_id.pop(tx_id, None)
            if self._ledgers:
                self._earliest_seq = min(self._ledgers.keys())
            else:
                self._earliest_seq = 0
                self._latest_seq = 0

    # ── Queries ─────────────────────────────────────────────────

    def get_ledger(self, sequence: int) -> Optional[StoredLedger]:
        return self._ledgers.get(sequence)

    def get_ledger_range(self, start: int, end: int) -> list[StoredLedger]:
        """Return ledgers in [start, end] inclusive."""
        result = []
        for seq in range(start, end + 1):
            sl = self._ledgers.get(seq)
            if sl:
                result.append(sl)
        return result

    def get_transaction(self, tx_id: str) -> Optional[StoredTransaction]:
        return self._tx_by_id.get(tx_id)

    def get_account_transactions(self, account: str, *,
                                 limit: int = 200,
                                 marker: int = 0) -> list[StoredTransaction]:
        """Return transactions for an account, paginated."""
        tx_ids = self._tx_by_account.get(account, [])
        result: list[StoredTransaction] = []
        for tx_id in tx_ids[marker:marker + limit]:
            stx = self._tx_by_id.get(tx_id)
            if stx:
                result.append(stx)
        return result

    def get_account_transactions_by_ledger(self, account: str,
                                           min_ledger: int,
                                           max_ledger: int) -> list[StoredTransaction]:
        """Return account txns within a ledger range."""
        tx_ids = self._tx_by_account.get(account, [])
        result: list[StoredTransaction] = []
        for tx_id in tx_ids:
            stx = self._tx_by_id.get(tx_id)
            if stx and min_ledger <= stx.ledger_sequence <= max_ledger:
                result.append(stx)
        return result


class ReportingServer:
    """
    Read-only query server backed by a ReportingStore.

    The ReportingServer exposes the same JSON interface as the normal
    API server but refuses any transaction submission.
    """

    def __init__(self, store: Optional[ReportingStore] = None):
        self.store = store or ReportingStore()
        self.started_at = time.time()
        self._read_only = True

    @property
    def is_read_only(self) -> bool:
        return self._read_only

    def ingest_ledger(self, ledger_data: dict) -> None:
        """Called by a trusted feeder to store new validated ledgers."""
        self.store.store_ledger(ledger_data)

    # ── Query API (mirrors rippled/Clio JSON responses) ─────────

    def server_info(self) -> dict:
        lo, hi = self.store.ledger_range
        return {
            "info": {
                "build_version": "nexaflow-reporting-1.0",
                "server_state": "reporting",
                "complete_ledgers": f"{lo}-{hi}" if lo else "empty",
                "uptime": int(time.time() - self.started_at),
                "reporting": {
                    "is_reporting": True,
                    "ledger_count": self.store.ledger_count,
                    "transaction_count": self.store.transaction_count,
                },
                "load_factor": 1,
            }
        }

    def ledger(self, *, sequence: int | None = None,
               ledger_hash: str | None = None,
               transactions: bool = False) -> dict:
        sl: Optional[StoredLedger] = None
        if sequence is not None:
            sl = self.store.get_ledger(sequence)
        elif ledger_hash:
            # Linear scan (small set in practice)
            for s in self.store._ledgers.values():
                if s.state_hash == ledger_hash:
                    sl = s
                    break
        if not sl:
            return {"error": "lgrNotFound", "error_message": "Ledger not found"}
        result: dict[str, Any] = {
            "ledger_index": sl.sequence,
            "ledger_hash": sl.state_hash,
            "close_time": sl.close_time,
            "parent_hash": sl.parent_hash,
            "txn_count": sl.txn_count,
        }
        if transactions:
            result["transactions"] = sl.transactions
        return {"result": result}

    def tx(self, tx_id: str) -> dict:
        stx = self.store.get_transaction(tx_id)
        if not stx:
            return {"error": "txnNotFound"}
        return {"result": stx.data}

    def account_tx(self, account: str, *, limit: int = 200,
                   marker: int = 0,
                   ledger_index_min: int = -1,
                   ledger_index_max: int = -1) -> dict:
        if ledger_index_min >= 0 and ledger_index_max >= 0:
            txns = self.store.get_account_transactions_by_ledger(
                account, ledger_index_min, ledger_index_max
            )
        else:
            txns = self.store.get_account_transactions(
                account, limit=limit, marker=marker
            )
        return {
            "result": {
                "account": account,
                "transactions": [
                    {"tx": t.data, "meta": {"ledger_sequence": t.ledger_sequence}}
                    for t in txns
                ],
                "limit": limit,
                "marker": marker + len(txns),
            }
        }

    def ledger_data(self, sequence: int, *, limit: int = 200,
                    marker: int = 0) -> dict:
        """Return raw ledger objects (state entries) for a ledger."""
        sl = self.store.get_ledger(sequence)
        if not sl:
            return {"error": "lgrNotFound"}
        return {
            "result": {
                "ledger_index": sl.sequence,
                "ledger_hash": sl.state_hash,
                "state": sl.transactions[marker:marker + limit],
                "marker": marker + min(limit, len(sl.transactions) - marker),
            }
        }

    def handle_request(self, method: str, params: dict) -> dict:
        """
        Universal JSON-RPC style dispatcher.

        Rejects any write operations.
        """
        READ_METHODS = {
            "server_info": lambda p: self.server_info(),
            "ledger": lambda p: self.ledger(
                sequence=p.get("ledger_index"),
                ledger_hash=p.get("ledger_hash"),
                transactions=p.get("transactions", False),
            ),
            "tx": lambda p: self.tx(p.get("transaction", "")),
            "account_tx": lambda p: self.account_tx(
                p.get("account", ""),
                limit=p.get("limit", 200),
                marker=p.get("marker", 0),
                ledger_index_min=p.get("ledger_index_min", -1),
                ledger_index_max=p.get("ledger_index_max", -1),
            ),
            "ledger_data": lambda p: self.ledger_data(
                p.get("ledger_index", 0),
                limit=p.get("limit", 200),
                marker=p.get("marker", 0),
            ),
        }

        handler = READ_METHODS.get(method)
        if handler:
            return handler(params)

        # Reject write methods
        WRITE_METHODS = {"submit", "submit_multisigned", "sign", "sign_for"}
        if method in WRITE_METHODS:
            return {
                "error": "reportingUnsupported",
                "error_message": "Reporting mode does not support transaction submission",
            }

        return {"error": "unknownCmd", "error_message": f"Unknown method: {method}"}
