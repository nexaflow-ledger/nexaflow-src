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

import logging
import sqlite3
from pathlib import Path
from typing import Any

logger = logging.getLogger("nexaflow_storage")


class LedgerStore:
    """Thin SQLite wrapper for persisting ledger state."""

    def __init__(self, db_path: str = "data/nexaflow.db"):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(db_path)
        self._conn.row_factory = sqlite3.Row
        # S2 — busy_timeout prevents "database is locked" under contention
        self._conn.execute("PRAGMA busy_timeout = 5000")
        self._conn.execute("PRAGMA journal_mode=WAL")
        # synchronous=NORMAL is safe with WAL and avoids fsync per commit
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._create_tables()
        self._ensure_schema_version()
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
                timestamp   REAL,
                tx_blob     TEXT
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS stakes (
                stake_id       TEXT PRIMARY KEY,
                tx_id          TEXT NOT NULL,
                address        TEXT NOT NULL,
                amount         REAL NOT NULL,
                tier           INTEGER NOT NULL,
                base_apy       REAL NOT NULL,
                effective_apy  REAL NOT NULL,
                lock_duration  INTEGER NOT NULL,
                start_time     REAL NOT NULL,
                maturity_time  REAL NOT NULL,
                matured        INTEGER NOT NULL DEFAULT 0,
                cancelled      INTEGER NOT NULL DEFAULT 0,
                payout_amount  REAL NOT NULL DEFAULT 0
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS applied_tx_ids (
                tx_id TEXT PRIMARY KEY
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS schema_version (
                id      INTEGER PRIMARY KEY CHECK (id = 1),
                version INTEGER NOT NULL
            )
        """)
        c.commit()

    # S4 — Schema versioning
    CURRENT_SCHEMA_VERSION = 1

    def _ensure_schema_version(self) -> None:
        """Check / set schema version; run migrations when needed."""
        row = self._conn.execute(
            "SELECT version FROM schema_version WHERE id = 1"
        ).fetchone()
        if row is None:
            self._conn.execute(
                "INSERT INTO schema_version (id, version) VALUES (1, ?)",
                (self.CURRENT_SCHEMA_VERSION,),
            )
            self._conn.commit()
        else:
            db_ver = row["version"]
            if db_ver < self.CURRENT_SCHEMA_VERSION:
                self._migrate(db_ver, self.CURRENT_SCHEMA_VERSION)
            elif db_ver > self.CURRENT_SCHEMA_VERSION:
                raise RuntimeError(
                    f"Database schema v{db_ver} is newer than this software "
                    f"(v{self.CURRENT_SCHEMA_VERSION}).  Upgrade NexaFlow."
                )

    def _migrate(self, from_ver: int, to_ver: int) -> None:
        """Run sequential migrations.  Add cases as schema evolves."""
        logger.info(f"Migrating database schema v{from_ver} → v{to_ver}")
        # Future migrations go here:
        # if from_ver < 2:
        #     self._conn.execute("ALTER TABLE ...")
        #     from_ver = 2
        self._conn.execute(
            "UPDATE schema_version SET version = ? WHERE id = 1", (to_ver,)
        )
        self._conn.commit()

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

    def load_accounts(self) -> list[dict[str, Any]]:
        rows = self._conn.execute("SELECT * FROM accounts").fetchall()
        return [dict(r) for r in rows]

    def get_account(self, address: str) -> dict[str, Any] | None:
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

    def load_trust_lines(self) -> list[dict[str, Any]]:
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

    def load_closed_ledgers(self) -> list[dict[str, Any]]:
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
        tx_blob: str = "",
    ) -> None:
        self._conn.execute(
            """INSERT OR REPLACE INTO transactions
               (tx_id, ledger_seq, tx_type, account, destination,
                amount_json, fee_json, memo, timestamp, tx_blob)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (tx_id, ledger_seq, tx_type, account, destination,
             amount_json, fee_json, memo, timestamp, tx_blob),
        )
        self._conn.commit()

    def load_transactions(self, ledger_seq: int | None = None) -> list[dict[str, Any]]:
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

    def load_tx_blobs(self, from_seq: int = 0) -> list[dict[str, Any]]:
        """Load all transaction blobs ordered by ledger sequence then rowid.

        Used for ledger replay from genesis.
        """
        rows = self._conn.execute(
            """SELECT tx_id, ledger_seq, tx_type, account, destination,
                      amount_json, fee_json, memo, timestamp, tx_blob
               FROM transactions
               WHERE ledger_seq >= ? AND tx_blob IS NOT NULL AND tx_blob != ''
               ORDER BY ledger_seq, rowid""",
            (from_seq,),
        ).fetchall()
        return [dict(r) for r in rows]

    def replay_from_genesis(self, ledger: Any) -> int:
        """
        Replay all stored transaction blobs against a fresh ledger,
        reconstructing state from genesis.

        Returns the number of transactions successfully replayed.
        """
        import json as _json
        from nexaflow_core.transaction import Transaction, Amount

        blobs = self.load_tx_blobs(from_seq=0)
        replayed = 0

        for row in blobs:
            blob_str = row.get("tx_blob", "")
            if not blob_str:
                continue
            try:
                blob = _json.loads(blob_str)
            except (ValueError, TypeError):
                logger.warning(
                    f"Skipping unparseable tx_blob for {row['tx_id']}"
                )
                continue

            # Reconstruct the Transaction object from the blob
            try:
                amt_data = blob.get("amount", {})
                fee_data = blob.get("fee", {})
                amount = Amount(
                    value=float(amt_data.get("value", 0)),
                    currency=amt_data.get("currency", "NXF"),
                    issuer=amt_data.get("issuer", ""),
                )
                fee = Amount(
                    value=float(fee_data.get("value", 0)),
                    currency="NXF",
                )
                tx = Transaction(
                    tx_type=blob.get("tx_type", 0),
                    account=blob.get("account", ""),
                    destination=blob.get("destination", ""),
                    amount=amount,
                    fee=fee,
                    sequence=blob.get("sequence", 0),
                    memo=blob.get("memo", ""),
                )
                tx.tx_id = blob.get("tx_id", row["tx_id"])
                if "flags" in blob:
                    tx.flags = blob["flags"]
                if "destination_tag" in blob:
                    tx.destination_tag = blob["destination_tag"]
                if "source_tag" in blob:
                    tx.source_tag = blob["source_tag"]

                result = ledger.apply_transaction(tx)
                if result == 0:
                    replayed += 1
                else:
                    logger.debug(
                        f"Replay tx {tx.tx_id} returned code {result}"
                    )
            except Exception as exc:
                logger.warning(
                    f"Failed to replay tx {row['tx_id']}: {exc}"
                )

        logger.info(f"Replayed {replayed}/{len(blobs)} transactions from genesis")
        return replayed

    # ── stakes ───────────────────────────────────────────────────

    def save_stake(
        self,
        stake_id: str,
        tx_id: str,
        address: str,
        amount: float,
        tier: int,
        base_apy: float,
        effective_apy: float,
        lock_duration: int,
        start_time: float,
        maturity_time: float,
        matured: bool = False,
        cancelled: bool = False,
        payout_amount: float = 0.0,
    ) -> None:
        self._conn.execute(
            """INSERT OR REPLACE INTO stakes
               (stake_id, tx_id, address, amount, tier, base_apy,
                effective_apy, lock_duration, start_time, maturity_time,
                matured, cancelled, payout_amount)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (stake_id, tx_id, address, amount, tier, base_apy,
             effective_apy, lock_duration, start_time, maturity_time,
             int(matured), int(cancelled), payout_amount),
        )
        self._conn.commit()

    def load_stakes(self) -> list[dict[str, Any]]:
        rows = self._conn.execute("SELECT * FROM stakes").fetchall()
        return [dict(r) for r in rows]

    # ── applied tx ids (replay protection) ───────────────────────

    def save_applied_tx_ids(self, tx_ids: set[str]) -> None:
        """Bulk-save applied transaction IDs for replay protection."""
        self._conn.executemany(
            "INSERT OR IGNORE INTO applied_tx_ids (tx_id) VALUES (?)",
            [(tid,) for tid in tx_ids],
        )
        self._conn.commit()

    def load_applied_tx_ids(self) -> set[str]:
        rows = self._conn.execute("SELECT tx_id FROM applied_tx_ids").fetchall()
        return {r["tx_id"] for r in rows}

    # ── bulk helpers ─────────────────────────────────────────────

    def snapshot_ledger(self, ledger: Any) -> None:
        """Persist the full current state of a Ledger object atomically.

        All writes are wrapped in a single transaction (S3) to prevent
        a partial snapshot if the process crashes mid-write.
        """
        c = self._conn
        try:
            c.execute("BEGIN IMMEDIATE")

            for addr, acc in ledger.accounts.items():
                c.execute(
                    """INSERT OR REPLACE INTO accounts
                       (address, balance, sequence, is_gateway, owner_count)
                       VALUES (?, ?, ?, ?, ?)""",
                    (addr, acc.balance, acc.sequence,
                     int(bool(acc.is_gateway)), acc.owner_count),
                )
                for (currency, issuer), tl in acc.trust_lines.items():
                    c.execute(
                        """INSERT OR REPLACE INTO trust_lines
                           (holder, currency, issuer, balance, "limit")
                           VALUES (?, ?, ?, ?, ?)""",
                        (addr, currency, issuer, tl.balance, tl.limit),
                    )

            for header in ledger.closed_ledgers:
                c.execute(
                    """INSERT OR REPLACE INTO closed_ledgers
                       (sequence, hash, previous_hash, timestamp,
                        transaction_count, total_nxf, account_count)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (header.sequence, header.hash, header.parent_hash,
                     header.close_time, header.tx_count,
                     header.total_nxf, 0),
                )

            # Persist staking pool
            if hasattr(ledger, "staking_pool") and ledger.staking_pool is not None:
                for record in ledger.staking_pool.stakes.values():
                    c.execute(
                        """INSERT OR REPLACE INTO stakes
                           (stake_id, tx_id, address, amount, tier, base_apy,
                            effective_apy, lock_duration, start_time, maturity_time,
                            matured, cancelled, payout_amount)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (record.stake_id, record.tx_id, record.address,
                         record.amount, int(record.tier), record.base_apy,
                         record.effective_apy, record.lock_duration,
                         record.start_time, record.maturity_time,
                         int(record.matured), int(record.cancelled),
                         record.payout_amount),
                    )

            # Persist applied tx IDs (replay protection)
            if hasattr(ledger, "applied_tx_ids") and ledger.applied_tx_ids:
                c.executemany(
                    "INSERT OR IGNORE INTO applied_tx_ids (tx_id) VALUES (?)",
                    [(tid,) for tid in ledger.applied_tx_ids],
                )

            c.execute("COMMIT")
        except Exception:
            c.execute("ROLLBACK")
            raise

    def restore_ledger(self, ledger: Any) -> None:
        """
        Restore ledger state from the database (accounts, trust lines,
        closed ledgers, staking pool, applied tx IDs).
        """
        from nexaflow_core.staking import StakeRecord, StakeTier

        # Accounts
        for row in self.load_accounts():
            acc = ledger.create_account(row["address"], row["balance"])
            acc.sequence = row["sequence"]
            acc.is_gateway = bool(row["is_gateway"])
            acc.owner_count = row["owner_count"]

        # Trust lines
        for row in self.load_trust_lines():
            ledger.set_trust_line(
                row["holder"], row["currency"], row["issuer"], row["limit"],
            )
            tl = ledger.accounts[row["holder"]].trust_lines.get(
                (row["currency"], row["issuer"])
            )
            if tl is not None:
                tl.balance = row["balance"]

        # Closed ledgers
        from nexaflow_core.ledger import LedgerHeader
        for row in self.load_closed_ledgers():
            header = LedgerHeader(row["sequence"], row["previous_hash"])
            header.hash = row["hash"]
            header.close_time = int(row["timestamp"])
            header.tx_count = row["transaction_count"]
            header.total_nxf = row["total_nxf"]
            ledger.closed_ledgers.append(header)
        if ledger.closed_ledgers:
            ledger.current_sequence = ledger.closed_ledgers[-1].sequence + 1

        # Staking pool
        if hasattr(ledger, "staking_pool"):
            for row in self.load_stakes():
                record = StakeRecord(
                    stake_id=row["stake_id"],
                    tx_id=row["tx_id"],
                    address=row["address"],
                    amount=row["amount"],
                    tier=StakeTier(row["tier"]),
                    base_apy=row["base_apy"],
                    effective_apy=row["effective_apy"],
                    lock_duration=row["lock_duration"],
                    start_time=row["start_time"],
                    maturity_time=row["maturity_time"],
                    matured=bool(row["matured"]),
                    cancelled=bool(row["cancelled"]),
                    payout_amount=row["payout_amount"],
                )
                pool = ledger.staking_pool
                pool.stakes[record.stake_id] = record
                pool.stakes_by_address.setdefault(record.address, []).append(record.stake_id)
                if record.is_active:
                    pool.total_staked += record.amount
                if record.payout_amount > record.amount:
                    pool.total_interest_paid += record.payout_amount - record.amount

        # Applied tx IDs (replay protection)
        if hasattr(ledger, "applied_tx_ids"):
            ledger.applied_tx_ids = self.load_applied_tx_ids()

    # ── lifecycle ────────────────────────────────────────────────

    def close(self) -> None:
        self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
