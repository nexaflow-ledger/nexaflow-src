"""
Tests for SQLite persistence layer (storage.py).

Covers:
  - Schema creation
  - Account CRUD and roundtrip
  - Trust line persistence
  - Closed ledger persistence
  - Transaction persistence
  - Stake persistence
  - Applied TX ID persistence (replay protection)
  - snapshot_ledger / restore_ledger roundtrip
  - Edge cases: empty DB, duplicate inserts, special characters
  - Context manager lifecycle
"""

from __future__ import annotations

import os

import pytest

from nexaflow_core.storage import LedgerStore


@pytest.fixture
def store(tmp_path):
    """Fresh LedgerStore in a temp directory."""
    db_path = str(tmp_path / "test.db")
    s = LedgerStore(db_path)
    yield s
    s.close()


# ═══════════════════════════════════════════════════════════════════
#  Schema
# ═══════════════════════════════════════════════════════════════════

class TestSchema:
    def test_tables_created(self, store):
        tables = store._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        names = {r["name"] for r in tables}
        assert "accounts" in names
        assert "trust_lines" in names
        assert "closed_ledgers" in names
        assert "transactions" in names
        assert "stakes" in names
        assert "applied_tx_ids" in names

    def test_wal_mode_enabled(self, store):
        mode = store._conn.execute("PRAGMA journal_mode").fetchone()[0]
        assert mode == "wal"

    def test_directory_created_if_missing(self, tmp_path):
        deep_path = str(tmp_path / "a" / "b" / "c" / "test.db")
        s = LedgerStore(deep_path)
        assert os.path.isfile(deep_path)
        s.close()


# ═══════════════════════════════════════════════════════════════════
#  Accounts
# ═══════════════════════════════════════════════════════════════════

class TestAccountPersistence:
    def test_save_and_load(self, store):
        store.save_account("rAlice", 1000.0, 5, False, 2)
        accounts = store.load_accounts()
        assert len(accounts) == 1
        assert accounts[0]["address"] == "rAlice"
        assert accounts[0]["balance"] == 1000.0
        assert accounts[0]["sequence"] == 5
        assert accounts[0]["is_gateway"] == 0
        assert accounts[0]["owner_count"] == 2

    def test_get_account(self, store):
        store.save_account("rBob", 500.0)
        acc = store.get_account("rBob")
        assert acc is not None
        assert acc["balance"] == 500.0

    def test_get_nonexistent_account(self, store):
        assert store.get_account("rNobody") is None

    def test_upsert_account(self, store):
        store.save_account("rAlice", 100.0)
        store.save_account("rAlice", 200.0, 3, True, 1)
        acc = store.get_account("rAlice")
        assert acc["balance"] == 200.0
        assert acc["sequence"] == 3
        assert acc["is_gateway"] == 1

    def test_gateway_flag_roundtrip(self, store):
        store.save_account("rGW", 0.0, 1, True, 0)
        acc = store.get_account("rGW")
        assert acc["is_gateway"] == 1

    def test_multiple_accounts(self, store):
        for i in range(50):
            store.save_account(f"r{i}", float(i * 100))
        accounts = store.load_accounts()
        assert len(accounts) == 50

    def test_special_characters_in_address(self, store):
        """Ensure no SQL injection via address field."""
        store.save_account("r'; DROP TABLE accounts; --", 100.0)
        acc = store.get_account("r'; DROP TABLE accounts; --")
        assert acc is not None
        assert acc["balance"] == 100.0
        # Table still exists
        tables = store._conn.execute(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='accounts'"
        ).fetchone()[0]
        assert tables == 1

    def test_zero_balance(self, store):
        store.save_account("rEmpty", 0.0)
        assert store.get_account("rEmpty")["balance"] == 0.0

    def test_negative_balance_stored(self, store):
        """Storage layer doesn't enforce invariants — just stores data."""
        store.save_account("rNeg", -999.0)
        assert store.get_account("rNeg")["balance"] == -999.0


# ═══════════════════════════════════════════════════════════════════
#  Trust Lines
# ═══════════════════════════════════════════════════════════════════

class TestTrustLinePersistence:
    def test_save_and_load(self, store):
        store.save_trust_line("rAlice", "USD", "rGW", 50.0, 1000.0)
        lines = store.load_trust_lines()
        assert len(lines) == 1
        assert lines[0]["holder"] == "rAlice"
        assert lines[0]["currency"] == "USD"
        assert lines[0]["balance"] == 50.0
        assert lines[0]["limit"] == 1000.0

    def test_upsert_trust_line(self, store):
        store.save_trust_line("rAlice", "USD", "rGW", 0.0, 500.0)
        store.save_trust_line("rAlice", "USD", "rGW", 100.0, 1000.0)
        lines = store.load_trust_lines()
        assert len(lines) == 1
        assert lines[0]["balance"] == 100.0
        assert lines[0]["limit"] == 1000.0

    def test_multiple_trust_lines(self, store):
        store.save_trust_line("rAlice", "USD", "rGW", 0.0, 500.0)
        store.save_trust_line("rAlice", "EUR", "rGW", 0.0, 300.0)
        store.save_trust_line("rBob", "USD", "rGW", 0.0, 100.0)
        lines = store.load_trust_lines()
        assert len(lines) == 3

    def test_empty_trust_lines(self, store):
        assert store.load_trust_lines() == []


# ═══════════════════════════════════════════════════════════════════
#  Closed Ledgers
# ═══════════════════════════════════════════════════════════════════

class TestClosedLedgerPersistence:
    def test_save_and_load(self, store):
        store.save_closed_ledger(1, "abc123", "000000", 1000.0, 5, 1e10, 10)
        ledgers = store.load_closed_ledgers()
        assert len(ledgers) == 1
        assert ledgers[0]["sequence"] == 1
        assert ledgers[0]["hash"] == "abc123"
        assert ledgers[0]["transaction_count"] == 5

    def test_latest_ledger_seq_empty(self, store):
        assert store.latest_ledger_seq() == 0

    def test_latest_ledger_seq(self, store):
        store.save_closed_ledger(1, "a", "0", 100.0)
        store.save_closed_ledger(5, "b", "a", 200.0)
        store.save_closed_ledger(3, "c", "d", 150.0)
        assert store.latest_ledger_seq() == 5

    def test_load_ordered_by_sequence(self, store):
        store.save_closed_ledger(3, "c", "b", 300.0)
        store.save_closed_ledger(1, "a", "0", 100.0)
        store.save_closed_ledger(2, "b", "a", 200.0)
        ledgers = store.load_closed_ledgers()
        seqs = [row["sequence"] for row in ledgers]
        assert seqs == [1, 2, 3]


# ═══════════════════════════════════════════════════════════════════
#  Transactions
# ═══════════════════════════════════════════════════════════════════

class TestTransactionPersistence:
    def test_save_and_load(self, store):
        store.save_transaction("tx1", 1, 0, "rAlice", "rBob", '{"value":100}')
        txns = store.load_transactions()
        assert len(txns) == 1
        assert txns[0]["tx_id"] == "tx1"
        assert txns[0]["account"] == "rAlice"

    def test_load_by_ledger_seq(self, store):
        store.save_transaction("tx1", 1, 0, "rAlice")
        store.save_transaction("tx2", 1, 0, "rBob")
        store.save_transaction("tx3", 2, 0, "rCharlie")
        ledger1 = store.load_transactions(ledger_seq=1)
        assert len(ledger1) == 2
        ledger2 = store.load_transactions(ledger_seq=2)
        assert len(ledger2) == 1

    def test_upsert_transaction(self, store):
        store.save_transaction("tx1", 1, 0, "rAlice")
        store.save_transaction("tx1", 2, 0, "rAlice")  # update
        txns = store.load_transactions()
        assert len(txns) == 1
        assert txns[0]["ledger_seq"] == 2

    def test_load_empty(self, store):
        assert store.load_transactions() == []


# ═══════════════════════════════════════════════════════════════════
#  Stakes
# ═══════════════════════════════════════════════════════════════════

class TestStakePersistence:
    def test_save_and_load(self, store):
        store.save_stake(
            "sk1", "tx1", "rAlice", 1000.0, 2, 0.08, 0.10,
            90 * 86400, 1000.0, 1000.0 + 90 * 86400, False, False, 0.0,
        )
        stakes = store.load_stakes()
        assert len(stakes) == 1
        assert stakes[0]["stake_id"] == "sk1"
        assert stakes[0]["amount"] == 1000.0
        assert stakes[0]["tier"] == 2
        assert stakes[0]["matured"] == 0
        assert stakes[0]["cancelled"] == 0

    def test_matured_flag(self, store):
        store.save_stake(
            "sk2", "tx2", "rBob", 500.0, 1, 0.05, 0.06,
            30 * 86400, 1000.0, 1000.0 + 30 * 86400, True, False, 520.0,
        )
        s = store.load_stakes()[0]
        assert s["matured"] == 1
        assert s["payout_amount"] == 520.0

    def test_cancelled_flag(self, store):
        store.save_stake(
            "sk3", "tx3", "rAlice", 300.0, 0, 0.02, 0.03,
            0, 1000.0, 0.0, False, True, 280.0,
        )
        s = store.load_stakes()[0]
        assert s["cancelled"] == 1

    def test_upsert_stake(self, store):
        store.save_stake("sk1", "tx1", "rAlice", 100.0, 0, 0.02, 0.02, 0, 1.0, 0.0)
        store.save_stake("sk1", "tx1", "rAlice", 100.0, 0, 0.02, 0.02, 0, 1.0, 0.0, True, False, 110.0)
        stakes = store.load_stakes()
        assert len(stakes) == 1
        assert stakes[0]["matured"] == 1


# ═══════════════════════════════════════════════════════════════════
#  Applied TX IDs (Replay Protection)
# ═══════════════════════════════════════════════════════════════════

class TestAppliedTxIds:
    def test_save_and_load(self, store):
        ids = {"tx_abc", "tx_def", "tx_ghi"}
        store.save_applied_tx_ids(ids)
        loaded = store.load_applied_tx_ids()
        assert loaded == ids

    def test_incremental_save(self, store):
        store.save_applied_tx_ids({"tx1", "tx2"})
        store.save_applied_tx_ids({"tx2", "tx3"})  # tx2 already exists
        loaded = store.load_applied_tx_ids()
        assert loaded == {"tx1", "tx2", "tx3"}

    def test_empty_set(self, store):
        store.save_applied_tx_ids(set())
        assert store.load_applied_tx_ids() == set()

    def test_large_batch(self, store):
        ids = {f"tx_{i}" for i in range(1000)}
        store.save_applied_tx_ids(ids)
        loaded = store.load_applied_tx_ids()
        assert len(loaded) == 1000
        assert loaded == ids


# ═══════════════════════════════════════════════════════════════════
#  Snapshot & Restore Roundtrip
# ═══════════════════════════════════════════════════════════════════

class TestSnapshotRestore:
    def test_roundtrip_accounts(self, store):
        from nexaflow_core.ledger import Ledger
        ledger = Ledger(total_supply=10000.0, genesis_account="rGen")
        ledger.create_account("rAlice", 500.0)
        ledger.create_account("rBob", 300.0)

        store.snapshot_ledger(ledger)

        ledger2 = Ledger(total_supply=10000.0, genesis_account="rGen")
        store.restore_ledger(ledger2)

        assert ledger2.get_balance("rAlice") == 500.0
        assert ledger2.get_balance("rBob") == 300.0

    def test_roundtrip_trust_lines(self, store):
        from nexaflow_core.ledger import Ledger
        ledger = Ledger(total_supply=10000.0, genesis_account="rGen")
        ledger.create_account("rAlice", 500.0)
        ledger.set_trust_line("rAlice", "USD", "rGen", 1000.0)

        store.snapshot_ledger(ledger)

        ledger2 = Ledger(total_supply=10000.0, genesis_account="rGen")
        store.restore_ledger(ledger2)

        tl = ledger2.get_trust_line("rAlice", "USD", "rGen")
        assert tl is not None
        assert tl.limit == 1000.0

    def test_roundtrip_closed_ledgers(self, store):
        from nexaflow_core.ledger import Ledger
        ledger = Ledger(total_supply=10000.0, genesis_account="rGen")
        ledger.close_ledger()
        ledger.close_ledger()

        store.snapshot_ledger(ledger)

        ledger2 = Ledger(total_supply=10000.0, genesis_account="rGen")
        store.restore_ledger(ledger2)

        assert len(ledger2.closed_ledgers) == 2
        assert ledger2.current_sequence == 3  # next after seq 2

    def test_roundtrip_applied_tx_ids(self, store):
        from nexaflow_core.ledger import Ledger
        ledger = Ledger(total_supply=10000.0, genesis_account="rGen")
        ledger.applied_tx_ids = {"tx_a", "tx_b", "tx_c"}

        store.snapshot_ledger(ledger)

        ledger2 = Ledger(total_supply=10000.0, genesis_account="rGen")
        store.restore_ledger(ledger2)

        assert ledger2.applied_tx_ids == {"tx_a", "tx_b", "tx_c"}

    def test_roundtrip_staking_pool(self, store):
        from nexaflow_core.ledger import Ledger
        ledger = Ledger(total_supply=10000.0, genesis_account="rGen")
        ledger.create_account("rAlice", 5000.0)

        # Manually record a stake
        ledger.staking_pool.record_stake(
            tx_id="stk1", address="rAlice", amount=100.0,
            tier=0, circulating_supply=10000.0, now=1000.0,
        )

        store.snapshot_ledger(ledger)

        ledger2 = Ledger(total_supply=10000.0, genesis_account="rGen")
        store.restore_ledger(ledger2)

        assert "stk1" in ledger2.staking_pool.stakes
        rec = ledger2.staking_pool.stakes["stk1"]
        assert rec.address == "rAlice"
        assert rec.amount == 100.0

    def test_restore_empty_db(self, store):
        """Restoring from empty DB should not crash."""
        from nexaflow_core.ledger import Ledger
        ledger = Ledger(total_supply=10000.0, genesis_account="rGen")
        store.restore_ledger(ledger)
        # Just genesis account
        assert "rGen" in ledger.accounts


# ═══════════════════════════════════════════════════════════════════
#  Context Manager
# ═══════════════════════════════════════════════════════════════════

class TestContextManager:
    def test_context_manager(self, tmp_path):
        db_path = str(tmp_path / "ctx.db")
        with LedgerStore(db_path) as s:
            s.save_account("rTest", 42.0)
        # Should be closed — but we can verify the file was created
        assert os.path.isfile(db_path)
