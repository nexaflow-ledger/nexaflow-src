"""Tests for the fee escalation module."""

import pytest

from nexaflow_core.fee_escalation import (
    FeeEscalation,
    DEFAULT_BASE_FEE,
    DEFAULT_TARGET_TXN_COUNT,
    DEFAULT_MAX_TXN_COUNT,
    DEFAULT_MAX_QUEUE_SIZE,
)


@pytest.fixture
def fee():
    return FeeEscalation()


class TestFeeBase:
    def test_default_base_fee(self, fee):
        # minimum_fee returns base_fee when queue is empty
        assert fee.minimum_fee() == DEFAULT_BASE_FEE

    def test_open_ledger_cost_when_empty(self, fee):
        cost = fee.open_ledger_cost()
        assert cost == DEFAULT_BASE_FEE

    def test_constants(self):
        assert DEFAULT_BASE_FEE == 0.00001
        assert DEFAULT_TARGET_TXN_COUNT == 25
        assert DEFAULT_MAX_TXN_COUNT == 50
        assert DEFAULT_MAX_QUEUE_SIZE == 2000


class TestFeeEscalation:
    def test_cost_increases_with_load(self, fee):
        base = fee.open_ledger_cost()
        # Fill with transactions that get applied (high fees)
        for i in range(30):
            fee.submit(f"tx_{i}", "rAlice", i, DEFAULT_BASE_FEE * 2)
        escalated = fee.open_ledger_cost()
        assert escalated >= base

    def test_submit_returns_applied_for_valid_fee(self, fee):
        status, msg = fee.submit("tx_1", "rAlice", 1, DEFAULT_BASE_FEE * 2)
        assert status == "applied"

    def test_submit_below_minimum_rejected(self, fee):
        status, msg = fee.submit("tx_1", "rAlice", 1, DEFAULT_BASE_FEE / 10)
        assert status == "rejected"

    def test_can_include_in_ledger(self, fee):
        assert fee.can_include_in_ledger(DEFAULT_BASE_FEE) is True

    def test_drain_for_ledger(self, fee):
        # Fill ledger to capacity so things get queued
        for i in range(DEFAULT_MAX_TXN_COUNT):
            fee.submit(f"tx_fill_{i}", "rFiller", i, DEFAULT_BASE_FEE)
        # Now submit more — these will be queued
        for i in range(10):
            fee.submit(f"tx_q_{i}", "rAlice", i, DEFAULT_BASE_FEE * (10 - i))
        drained = fee.drain_for_ledger(5)
        assert len(drained) <= 5
        if len(drained) > 1:
            # Should be ordered by fee highest first
            fees = [d.fee for d in drained]
            assert fees == sorted(fees, reverse=True)

    def test_on_ledger_close_resets(self, fee):
        for i in range(10):
            fee.submit(f"tx_{i}", "rAlice", i, DEFAULT_BASE_FEE)
        fee.on_ledger_close()
        stats = fee.get_stats()
        assert stats["current_ledger_txn_count"] == 0

    def test_queue_full_rejects(self):
        fe = FeeEscalation(max_queue_size=5)
        # Fill ledger first so things get queued
        for i in range(DEFAULT_MAX_TXN_COUNT):
            fe.submit(f"tx_fill_{i}", "rFiller", i, DEFAULT_BASE_FEE)
        # Now try to queue 6 items
        for i in range(5):
            fe.submit(f"tx_q_{i}", "rAlice", i, DEFAULT_BASE_FEE)
        status, msg = fe.submit("tx_overflow", "rAlice", 99, DEFAULT_BASE_FEE)
        # Should be rejected because queue is full and fee isn't higher
        assert status == "rejected"


class TestFeeStats:
    def test_get_stats(self, fee):
        fee.submit("tx_1", "rAlice", 1, DEFAULT_BASE_FEE * 2)
        stats = fee.get_stats()
        assert "queue_size" in stats
        assert "open_ledger_cost" in stats
        assert "minimum_fee" in stats

    def test_custom_params(self):
        fe = FeeEscalation(
            base_fee=0.001,
            target_txn_count=10,
            max_txn_count=20,
            max_queue_size=100,
        )
        assert fe.base_fee == 0.001
