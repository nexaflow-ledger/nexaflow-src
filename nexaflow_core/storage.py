"""
SQLite-based persistence layer for NexaFlow ledger state.

Stores account balances, trust lines, closed ledger headers,
and applied transactions so that a node can recover state after restart.

Usage:
    store = LedgerStore("data/nexaflow.db")
    store.save_account("rAddress", 1000.0, 1, False, 0)
    store.save_closed_ledger(seq=1, hash="abc...", prev="000...", ...)
    ...
    accounts = store.load_accounts()
"""

from __future__ import annotations

import json
import logging
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("nexaflow_storage")


class LedgerStore:
    """Thin SQLite wrapper for persisting ledger state."""

    def __init__(self, db_path: str = "data/nexaflow.db"):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(db_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._create_tables()
        logger.info(f"Storage opened: {db_path}")

    # ── schema ───────────────────────────────────────────────────

    def _create_tables(self) -> None:
        c = self._conn
        c.execute("""
            CREATE TABLE IF NOT EXISTS accounts (
                address    TEXT PRIMARY KEY,
                balance    REAL NOT NULL DEFAULT 0,
                sequence   INTEGER NOT NULL DEFAULT 1,
                is_gateway INTEGER NOT NULL DEFAULT 0,
                owner_count INTEGER NOT NULL DEFAULT 0
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS trust_lines (
                holder   TEXT NOT NULL,
                currency TEXT NOT NULL,
                issuer   TEXT NOT NULL,
                balance  REAL NOT NULL DEFAULT 0,
                "limit"  REAL NOT NULL DEFAULT 0,
                PRIMARY KEY (holder, currency, issuer)
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS closed_ledgers (
                sequence          INTEGER PRIMARY KEY,
                hash              TEXT NOT NULL,
                previous_hash     TEXT NOT NULL,
                timestamp         REAL NOT NULL,
                transaction_count INTEGER NOT NULL DEFAULT 0,
                total_nxf         REAL NOT NULL DEFAULT 0,
                account_count     INTEGER NOT NULL DEFAULT 0
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                tx_id       TEXT PRIMARY KEY,
                ledger_seq  INTEGER NOT NULL,
                tx_type     INTEGER NOT NULL,
                account     TEXT NOT NULL,
                destination TEXT,
                amount_json TEXT,
                fee_json    TEXT,
                memo        TEXT,
                timestamp   REAL
            )
        """)
        c.commit()

    # ── accounts ─────────────────────────────────────────────────

    def save_account(
        self,
        address: str,
        balance: float,
        sequence: int = 1,
        is_gateway: bool = False,
        owner_count: int = 0,
    ) -> None:
        self._conn.execute(
            """INSERT OR REPLACE INTO accounts
               (address, balance, sequence, is_gateway, owner_count)
               VALUES (?, ?, ?, ?, ?)""",
            (address, balance, sequence, int(is_gateway), owner_count),
        )
        self._conn.commit()

    def load_accounts(self) -> List[Dict[str, Any]]:
        rows = self._conn.execute("SELECT * FROM accounts").fetchall()
        return [dict(r) for r in rows]

    def get_account(self, address: str) -> Optional[Dict[str, Any]]:
        row = self._conn.execute(
            "SELECT * FROM accounts WHERE address = ?", (address,)
        ).fetchone()
        return dict(row) if row else None

    # ── trust lines ──────────────────────────────────────────────

    def save_trust_line(
        self,
        holder: str,
        currency: str,
        issuer: str,
        balance: float,
        limit: float,
    ) -> None:
        self._conn.execute(
            """INSERT OR REPLACE INTO trust_lines
               (holder, currency, issuer, balance, "limit")
               VALUES (?, ?, ?, ?, ?)""",
            (holder, currency, issuer, balance, limit),
        )
        self._conn.commit()

    def load_trust_lines(self) -> List[Dict[str, Any]]:
        rows = self._conn.execute("SELECT * FROM trust_lines").fetchall()
        return [dict(r) for r in rows]

    # ── closed ledgers ───────────────────────────────────────────

    def save_closed_ledger(
        self,
        sequence: int,
        hash: str,
        previous_hash: str,
        timestamp: float,
        transaction_count: int = 0,
        total_nxf: float = 0.0,
        account_count: int = 0,
    ) -> None:
        self._conn.execute(
            """INSERT OR REPLACE INTO closed_ledgers
               (sequence, hash, previous_hash, timestamp,
                transaction_count, total_nxf, account_count)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (sequence, hash, previous_hash, timestamp,
             transaction_count, total_nxf, account_count),
        )
        self._conn.commit()

    def load_closed_ledgers(self) -> List[Dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM closed_ledgers ORDER BY sequence"
        ).fetchall()
        return [dict(r) for r in rows]

    def latest_ledger_seq(self) -> int:
        row = self._conn.execute(
            "SELECT MAX(sequence) AS seq FROM closed_ledgers"
        ).fetchone()
        return row["seq"] if row and row["seq"] is not None else 0

    # ── transactions ─────────────────────────────────────────────

    def save_transaction(
        self,
        tx_id: str,
        ledger_seq: int,
        tx_type: int,
        account: str,
        destination: str = "",
        amount_json: str = "{}",
        fee_json: str = "{}",
        memo: str = "",
        timestamp: float = 0.0,
    ) -> None:
        self._conn.execute(
            """INSERT OR REPLACE INTO transactions
               (tx_id, ledger_seq, tx_type, account, destination,
                amount_json, fee_json, memo, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (tx_id, ledger_seq, tx_type, account, destination,
             amount_json, fee_json, memo, timestamp),
        )
        self._conn.commit()

    def load_transactions(self, ledger_seq: Optional[int] = None) -> List[Dict[str, Any]]:
        if ledger_seq is not None:
            rows = self._conn.execute(
                "SELECT * FROM transactions WHERE ledger_seq = ? ORDER BY rowid",
                (ledger_seq,),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM transactions ORDER BY ledger_seq, rowid"
            ).fetchall()
        return [dict(r) for r in rows]

    # ── bulk helpers ─────────────────────────────────────────────

    def snapshot_ledger(self, ledger: Any) -> None:
        """Persist the full current state of a Ledger object."""
        for addr, acc in ledger.accounts.items():
            self.save_account(
                addr, acc.balance, acc.sequence,
                bool(acc.is_gateway), acc.owner_count,
            )
            for (currency, issuer), tl in acc.trust_lines.items():
                self.save_trust_line(addr, currency, issuer, tl.balance, tl.limit)

        for header in ledger.closed_ledgers:
            self.save_closed_ledger(
                header.sequence, header.hash, header.previous_hash,
                header.timestamp, header.transaction_count,
                header.total_nxf, header.account_count,
            )

    # ── lifecycle ────────────────────────────────────────────────

    def close(self) -> None:
        self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
