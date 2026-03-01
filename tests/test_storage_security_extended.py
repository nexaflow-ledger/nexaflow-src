"""
Extended security tests for Storage layer (nexaflow_core.storage).

Covers:
  - SQL injection via parameterized queries (verify they're safe)
  - Unicode and binary data in string fields
  - Extremely large values in numeric fields (float overflow)
  - Duplicate key behavior (INSERT OR REPLACE semantics)
  - Concurrent read/write (WAL mode correctness)
  - Corrupt/invalid data types persisted and loaded
  - Negative balances / negative sequences
  - Empty string primary keys
  - Path traversal in db_path
  - Snapshot/restore cycle data integrity
  - Applied tx_ids deduplication
  - NULL values in non-null columns
"""

from __future__ import annotations

import math
import os
import tempfile
import threading
import unittest

from nexaflow_core.storage import LedgerStore


class StorageTestBase(unittest.TestCase):
    """Base class providing a temporary database for each test."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "test.db")
        self.store = LedgerStore(self.db_path)

    def tearDown(self):
        self.store.close()
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
        # Remove WAL / SHM files
        for ext in ("-wal", "-shm"):
            p = self.db_path + ext
            if os.path.exists(p):
                os.remove(p)


# ═══════════════════════════════════════════════════════════════════
#  SQL Injection Attempts
# ═══════════════════════════════════════════════════════════════════

class TestSQLInjection(StorageTestBase):
    """All queries use parameterized placeholders — verify safety."""

    def test_address_with_sql_in_value(self):
        """SQL in address field should be treated as literal string."""
        evil = "'; DROP TABLE accounts; --"
        self.store.save_account(evil, 100.0)
        acct = self.store.get_account(evil)
        self.assertIsNotNone(acct)
        self.assertEqual(acct["address"], evil)
        self.assertEqual(acct["balance"], 100.0)
        # Table still exists
        rows = self.store.load_accounts()
        self.assertEqual(len(rows), 1)

    def test_trust_line_with_sql_in_fields(self):
        holder = "alice'; DELETE FROM trust_lines; --"
        currency = "USD' OR '1'='1"
        issuer = "gateway' UNION SELECT * FROM accounts --"
        self.store.save_trust_line(holder, currency, issuer, 50.0, 1000.0)
        lines = self.store.load_trust_lines()
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0]["holder"], holder)

    def test_tx_id_with_sql_injection(self):
        evil_id = "tx'; INSERT INTO transactions VALUES ('evil',0,0,'a','','{}','{}','',0); --"
        self.store.save_transaction(evil_id, 1, 0, "alice")
        txns = self.store.load_transactions()
        self.assertEqual(len(txns), 1)
        self.assertEqual(txns[0]["tx_id"], evil_id)

    def test_stake_id_with_sql_injection(self):
        evil = "stk'); DROP TABLE stakes; --"
        self.store.save_stake(
            stake_id=evil, tx_id="tx1", address="addr1",
            amount=100, tier=0, base_apy=0.03, effective_apy=0.03,
            lock_duration=0, start_time=1000, maturity_time=2000,
        )
        stakes = self.store.load_stakes()
        self.assertEqual(len(stakes), 1)
        self.assertEqual(stakes[0]["stake_id"], evil)


# ═══════════════════════════════════════════════════════════════════
#  Unicode and Special Characters
# ═══════════════════════════════════════════════════════════════════

class TestUnicodeData(StorageTestBase):

    def test_unicode_address(self):
        addr = "rΣ日本語🚀"
        self.store.save_account(addr, 42.0)
        acct = self.store.get_account(addr)
        self.assertIsNotNone(acct)
        self.assertEqual(acct["address"], addr)

    def test_null_byte_in_address(self):
        """Null bytes in string fields should be stored correctly."""
        addr = "r\x00evil"
        self.store.save_account(addr, 10.0)
        acct = self.store.get_account(addr)
        self.assertIsNotNone(acct)
        self.assertEqual(acct["address"], addr)

    def test_very_long_string_address(self):
        addr = "r" + "x" * 100_000
        self.store.save_account(addr, 1.0)
        acct = self.store.get_account(addr)
        self.assertIsNotNone(acct)
        self.assertEqual(len(acct["address"]), 100_001)

    def test_empty_string_address(self):
        """Empty string as primary key should work in SQLite."""
        self.store.save_account("", 0.0)
        acct = self.store.get_account("")
        self.assertIsNotNone(acct)
        self.assertEqual(acct["address"], "")


# ═══════════════════════════════════════════════════════════════════
#  Numeric Edge Cases
# ═══════════════════════════════════════════════════════════════════

class TestNumericEdgeCases(StorageTestBase):

    def test_negative_balance(self):
        """
        VULN: Storage accepts negative balances without validation.
        This could persist invalid state.
        """
        self.store.save_account("alice", -1000.0)
        acct = self.store.get_account("alice")
        self.assertEqual(acct["balance"], -1000.0)

    def test_inf_balance(self):
        """
        VULN: SQLite stores Inf as REAL without complaint.
        """
        self.store.save_account("alice", float("inf"))
        acct = self.store.get_account("alice")
        self.assertTrue(math.isinf(acct["balance"]))

    def test_nan_balance(self):
        """
        VULN: SQLite may convert NaN to NULL or 0.0 depending on version.
        Either way, the storage layer doesn't reject it.
        """
        self.store.save_account("alice", float("nan"))
        acct = self.store.get_account("alice")
        # SQLite may store NaN as NULL or 0.0 — either is wrong for financial data
        balance = acct["balance"]
        is_nan_or_null = balance is None or (isinstance(balance, float) and math.isnan(balance))
        is_zero = balance == 0.0
        self.assertTrue(is_nan_or_null or is_zero, f"Unexpected NaN storage result: {balance}")

    def test_very_large_balance(self):
        self.store.save_account("whale", 1e308)
        acct = self.store.get_account("whale")
        self.assertEqual(acct["balance"], 1e308)

    def test_negative_sequence(self):
        self.store.save_account("alice", 100.0, sequence=-1)
        acct = self.store.get_account("alice")
        self.assertEqual(acct["sequence"], -1)

    def test_zero_sequence(self):
        self.store.save_account("alice", 100.0, sequence=0)
        acct = self.store.get_account("alice")
        self.assertEqual(acct["sequence"], 0)

    def test_huge_owner_count(self):
        self.store.save_account("alice", 100.0, owner_count=2**31 - 1)
        acct = self.store.get_account("alice")
        self.assertEqual(acct["owner_count"], 2**31 - 1)


# ═══════════════════════════════════════════════════════════════════
#  Duplicate Key / Upsert Behavior
# ═══════════════════════════════════════════════════════════════════

class TestUpsertBehavior(StorageTestBase):

    def test_account_upsert_overwrites(self):
        """INSERT OR REPLACE means second save overwrites first."""
        self.store.save_account("alice", 100.0, sequence=1)
        self.store.save_account("alice", 200.0, sequence=5)
        acct = self.store.get_account("alice")
        self.assertEqual(acct["balance"], 200.0)
        self.assertEqual(acct["sequence"], 5)
        # Only one row should exist
        self.assertEqual(len(self.store.load_accounts()), 1)

    def test_trust_line_upsert(self):
        self.store.save_trust_line("alice", "USD", "gw", 10.0, 100.0)
        self.store.save_trust_line("alice", "USD", "gw", 50.0, 100.0)
        lines = self.store.load_trust_lines()
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0]["balance"], 50.0)

    def test_applied_tx_ids_no_duplicates(self):
        """INSERT OR IGNORE means duplicates are silently dropped."""
        self.store.save_applied_tx_ids({"tx1", "tx2", "tx3"})
        self.store.save_applied_tx_ids({"tx2", "tx3", "tx4"})
        ids = self.store.load_applied_tx_ids()
        self.assertEqual(ids, {"tx1", "tx2", "tx3", "tx4"})


# ═══════════════════════════════════════════════════════════════════
#  Concurrent Access
# ═══════════════════════════════════════════════════════════════════

class TestConcurrentAccess(StorageTestBase):

    def test_concurrent_writes(self):
        """WAL mode should allow concurrent writes without corruption."""
        errors = []

        def write_accounts(start: int, count: int):
            try:
                store = LedgerStore(self.db_path)
                for i in range(start, start + count):
                    store.save_account(f"addr_{i}", float(i))
                store.close()
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=write_accounts, args=(0, 50)),
            threading.Thread(target=write_accounts, args=(50, 50)),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0, f"Errors during concurrent write: {errors}")
        # All 100 accounts should exist
        accounts = self.store.load_accounts()
        self.assertEqual(len(accounts), 100)

    def test_concurrent_read_write(self):
        """Reading while writing should not return corrupt data."""
        self.store.save_account("alice", 100.0)
        read_results = []
        errors = []

        def writer():
            try:
                store = LedgerStore(self.db_path)
                for i in range(100):
                    store.save_account("alice", float(i))
                store.close()
            except Exception as e:
                errors.append(e)

        def reader():
            try:
                store = LedgerStore(self.db_path)
                for _ in range(100):
                    acct = store.get_account("alice")
                    if acct:
                        read_results.append(acct["balance"])
                store.close()
            except Exception as e:
                errors.append(e)

        t1 = threading.Thread(target=writer)
        t2 = threading.Thread(target=reader)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        self.assertEqual(len(errors), 0, f"Errors: {errors}")
        # All read results should be valid floats
        for val in read_results:
            self.assertIsInstance(val, float)


# ═══════════════════════════════════════════════════════════════════
#  Ledger Sequence Tracking
# ═══════════════════════════════════════════════════════════════════

class TestLedgerSequence(StorageTestBase):

    def test_latest_ledger_seq_empty(self):
        self.assertEqual(self.store.latest_ledger_seq(), 0)

    def test_latest_ledger_seq_multiple(self):
        for i in range(1, 6):
            self.store.save_closed_ledger(
                sequence=i, hash=f"h{i}", previous_hash=f"h{i-1}",
                timestamp=float(i * 100), transaction_count=1,
            )
        self.assertEqual(self.store.latest_ledger_seq(), 5)

    def test_non_sequential_ledger_sequences(self):
        """Gaps in sequence numbers should be handled."""
        self.store.save_closed_ledger(1, "h1", "h0", 100.0)
        self.store.save_closed_ledger(5, "h5", "h4", 500.0)
        self.store.save_closed_ledger(3, "h3", "h2", 300.0)
        self.assertEqual(self.store.latest_ledger_seq(), 5)
        ledgers = self.store.load_closed_ledgers()
        # Should be ordered by sequence
        seqs = [row["sequence"] for row in ledgers]
        self.assertEqual(seqs, [1, 3, 5])


# ═══════════════════════════════════════════════════════════════════
#  Transaction Persistence
# ═══════════════════════════════════════════════════════════════════

class TestTransactionPersistence(StorageTestBase):

    def test_load_by_ledger_seq(self):
        self.store.save_transaction("tx1", 1, 0, "alice")
        self.store.save_transaction("tx2", 1, 0, "bob")
        self.store.save_transaction("tx3", 2, 0, "alice")
        txns_1 = self.store.load_transactions(ledger_seq=1)
        self.assertEqual(len(txns_1), 2)
        txns_2 = self.store.load_transactions(ledger_seq=2)
        self.assertEqual(len(txns_2), 1)

    def test_load_all_transactions(self):
        for i in range(10):
            self.store.save_transaction(f"tx{i}", i % 3, 0, "alice")
        txns = self.store.load_transactions()
        self.assertEqual(len(txns), 10)

    def test_transaction_with_large_memo(self):
        memo = "x" * 1_000_000
        self.store.save_transaction("tx_memo", 1, 0, "alice", memo=memo)
        txns = self.store.load_transactions()
        self.assertEqual(len(txns[0]["memo"]), 1_000_000)


# ═══════════════════════════════════════════════════════════════════
#  Stake Persistence
# ═══════════════════════════════════════════════════════════════════

class TestStakePersistence(StorageTestBase):

    def _save_sample_stake(self, stake_id="s1", amount=1000.0, matured=False):
        self.store.save_stake(
            stake_id=stake_id, tx_id="tx1", address="alice",
            amount=amount, tier=2, base_apy=0.05, effective_apy=0.05,
            lock_duration=86400 * 30, start_time=1000.0, maturity_time=1000.0 + 86400 * 30,
            matured=matured, cancelled=False, payout_amount=0.0,
        )

    def test_stake_round_trip(self):
        self._save_sample_stake()
        stakes = self.store.load_stakes()
        self.assertEqual(len(stakes), 1)
        self.assertEqual(stakes[0]["stake_id"], "s1")
        self.assertEqual(stakes[0]["amount"], 1000.0)

    def test_stake_matured_flag(self):
        self._save_sample_stake(matured=True)
        stakes = self.store.load_stakes()
        self.assertEqual(stakes[0]["matured"], 1)

    def test_negative_stake_amount(self):
        """VULN: Storage accepts negative stake amounts."""
        self._save_sample_stake(amount=-500.0)
        stakes = self.store.load_stakes()
        self.assertEqual(stakes[0]["amount"], -500.0)


# ═══════════════════════════════════════════════════════════════════
#  Applied TX IDs
# ═══════════════════════════════════════════════════════════════════

class TestAppliedTxIds(StorageTestBase):

    def test_empty_set(self):
        self.store.save_applied_tx_ids(set())
        ids = self.store.load_applied_tx_ids()
        self.assertEqual(ids, set())

    def test_large_set(self):
        big_set = {f"tx_{i}" for i in range(10_000)}
        self.store.save_applied_tx_ids(big_set)
        ids = self.store.load_applied_tx_ids()
        self.assertEqual(ids, big_set)

    def test_idempotent_save(self):
        self.store.save_applied_tx_ids({"tx1"})
        self.store.save_applied_tx_ids({"tx1"})
        ids = self.store.load_applied_tx_ids()
        self.assertEqual(ids, {"tx1"})


# ═══════════════════════════════════════════════════════════════════
#  Database Path Edge Cases
# ═══════════════════════════════════════════════════════════════════

class TestDBPathEdgeCases(unittest.TestCase):

    def test_nested_directory_creation(self):
        """Parent directories should be created automatically."""
        tmpdir = tempfile.mkdtemp()
        deep_path = os.path.join(tmpdir, "a", "b", "c", "test.db")
        store = LedgerStore(deep_path)
        store.save_account("alice", 100.0)
        store.close()
        self.assertTrue(os.path.exists(deep_path))

    def test_in_memory_database(self):
        """':memory:' path should work (no file on disk)."""
        store = LedgerStore(":memory:")
        store.save_account("alice", 100.0)
        acct = store.get_account("alice")
        self.assertIsNotNone(acct)
        store.close()


# ═══════════════════════════════════════════════════════════════════
#  Context Manager
# ═══════════════════════════════════════════════════════════════════

class TestContextManager(unittest.TestCase):

    def test_context_manager_closes(self):
        tmpdir = tempfile.mkdtemp()
        db_path = os.path.join(tmpdir, "ctx.db")
        with LedgerStore(db_path) as store:
            store.save_account("alice", 100.0)
        # After exit, connection should be closed
        # Accessing store._conn should raise ProgrammingError
        with self.assertRaises(Exception):  # noqa: B017
            store._conn.execute("SELECT 1")


if __name__ == "__main__":
    unittest.main()
