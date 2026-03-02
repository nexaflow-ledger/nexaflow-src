"""Tests for the invariant checker module."""

import pytest

from nexaflow_core.invariants import InvariantChecker, LedgerSnapshot


class MockAccount:
    """Minimal account mock for invariant testing."""
    def __init__(self, address, balance, owner_count=0, sequence=1):
        self.address = address
        self.balance = balance
        self.owner_count = owner_count
        self.sequence = sequence
        self.trust_lines = {}


class MockLedger:
    """Minimal ledger mock for invariant testing."""
    def __init__(self, total_supply=10_000.0, total_burned=0.0,
                 total_minted=0.0, initial_supply=10_000.0):
        self.total_supply = total_supply
        self.total_burned = total_burned
        self.total_minted = total_minted
        self.initial_supply = initial_supply
        self.accounts = {}

    def add_account(self, address, balance, **kwargs):
        self.accounts[address] = MockAccount(address, balance, **kwargs)


@pytest.fixture
def checker():
    return InvariantChecker()


class TestLedgerSnapshot:
    def test_capture(self, checker):
        ledger = MockLedger(10_000.0)
        ledger.add_account("rAlice", 500.0)
        ledger.add_account("rBob", 100.0)
        result = checker.capture(ledger)
        assert result is None  # capture stores internally

    def test_snapshot_preserves_values(self, checker):
        ledger = MockLedger(10_000.0)
        ledger.add_account("rAlice", 500.0, owner_count=2, sequence=5)
        checker.capture(ledger)
        snap = checker._snapshot
        assert snap.account_balances["rAlice"] == 500.0
        assert snap.account_owner_counts["rAlice"] == 2
        assert snap.account_sequences["rAlice"] == 5


class TestInvariantVerification:
    def test_verify_no_changes_passes(self, checker):
        ledger = MockLedger(10_000.0)
        ledger.add_account("rAlice", 500.0)
        checker.capture(ledger)
        passed, msg = checker.verify(ledger)
        assert passed is True
        assert msg == ""

    def test_verify_supply_conservation(self, checker):
        ledger = MockLedger(10_000.0)
        ledger.add_account("rAlice", 500.0)
        ledger.add_account("rBob", 100.0)
        checker.capture(ledger)
        # Tamper with supply without corresponding burn/mint
        ledger.total_supply = 10_001.0
        passed, msg = checker.verify(ledger)
        assert passed is False
        assert "supply" in msg.lower() or "Supply" in msg

    def test_verify_negative_balance(self, checker):
        ledger = MockLedger(10_000.0)
        ledger.add_account("rAlice", 500.0)
        checker.capture(ledger)
        ledger.accounts["rAlice"].balance = -1.0
        passed, msg = checker.verify(ledger)
        assert passed is False
        assert "negative" in msg.lower() or "Negative" in msg

    def test_verify_owner_count_non_negative(self, checker):
        ledger = MockLedger(10_000.0)
        ledger.add_account("rAlice", 500.0, owner_count=1)
        checker.capture(ledger)
        ledger.accounts["rAlice"].owner_count = -1
        passed, msg = checker.verify(ledger)
        assert passed is False
        assert "owner" in msg.lower()

    def test_verify_sequence_only_increases(self, checker):
        ledger = MockLedger(10_000.0)
        ledger.add_account("rAlice", 500.0, sequence=5)
        checker.capture(ledger)
        ledger.accounts["rAlice"].sequence = 4
        passed, msg = checker.verify(ledger)
        assert passed is False
        assert "sequence" in msg.lower() or "Sequence" in msg

    def test_verify_sequence_increase_passes(self, checker):
        ledger = MockLedger(10_000.0)
        ledger.add_account("rAlice", 500.0, sequence=5)
        checker.capture(ledger)
        ledger.accounts["rAlice"].sequence = 6
        passed, msg = checker.verify(ledger)
        # Should pass (sequence increased normally)
        seq_fail = "sequence" in msg.lower() if not passed else False
        assert not seq_fail

    def test_verify_new_account_allowed(self, checker):
        ledger = MockLedger(10_000.0)
        ledger.add_account("rAlice", 500.0)
        checker.capture(ledger)
        ledger.add_account("rNew", 0.0)
        passed, msg = checker.verify(ledger)
        # New account with 0 balance should be fine
        neg_fail = "negative" in msg.lower() if not passed else False
        assert not neg_fail


class TestMultipleViolations:
    def test_returns_multiple_violations(self, checker):
        ledger = MockLedger(10_000.0)
        ledger.add_account("rAlice", 500.0, sequence=5)
        checker.capture(ledger)
        # Multiple violations
        ledger.total_supply = 9_999.0
        ledger.accounts["rAlice"].balance = -1.0
        ledger.accounts["rAlice"].sequence = 3
        passed, msg = checker.verify(ledger)
        assert passed is False
        # Should have multiple error messages joined by ";"
        assert ";" in msg or len(msg) > 20
